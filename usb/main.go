package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	_ "encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed scanner_private.pem
var signingKeyPEM []byte

//go:embed server_public.pem
var encryptKeyPEM []byte

// Global loggers for info and errors.
var (
	infoLogger  *log.Logger
	errorLogger *log.Logger
)

// ignoredDirs contains system directories to skip for efficiency and relevance.
var ignoredDirs = map[string]struct{}{
	// Windows specific directories
	"C:\\Windows":             {},
	"C:\\Program Files":       {},
	"C:\\Program Files (x86)": {},
	//"C:\\$Recycle.Bin":              {},
	//"C:\\System Volume Information": {},
	// Linux specific directories
	"/proc":    {},
	"/sys":     {},
	"/dev":     {},
	"/run":     {},
	"/tmp":     {},
	"/var/tmp": {},
}

// FileMetadata holds information about a single scanned file.
type FileMetadata struct {
	Path    string    `json:"path"`
	ModTime time.Time `json:"mod_time"`
	Size    int64     `json:"size"`
}

// ScanOutput is the top-level structure for the JSON output file.
type ScanOutput struct {
	ScannerName   string         `json:"scanner_name"`
	LaptopID      string         `json:"laptop_id"`
	HardDriveID   string         `json:"hard_drive_id"`
	InstalledApps []string       `json:"installed_apps"`
	Files         []FileMetadata `json:"files"`
}

// setupLogging initializes separate log files for informational messages and errors.
func setupLogging() error {
	// Create logs directory if it doesn't exist
	if err := os.MkdirAll("./logs", 0755); err != nil {
		return fmt.Errorf("failed to create logs directory: %w", err)
	}

	logFilePath := filepath.Join("./logs", "scan_info.log")
	errFilePath := filepath.Join("./logs", "scan_error.log")

	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open info log file: %w", err)
	}
	errFile, err := os.OpenFile(errFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open error log file: %w", err)
	}

	// Info logger writes to both console and file
	infoLogger = log.New(io.MultiWriter(os.Stdout, logFile), "INFO: ", log.Ldate|log.Ltime)
	// Error logger writes to both stderr and file, with file/line number
	errorLogger = log.New(io.MultiWriter(os.Stderr, errFile), "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
	return nil
}

// isIgnored checks if a file path matches any of the predefined ignored directories.
func isIgnored(path string) bool {
	lowerPath := strings.ToLower(filepath.ToSlash(path))
	for ignored := range ignoredDirs {
		if strings.HasPrefix(lowerPath, strings.ToLower(filepath.ToSlash(ignored))) {
			return true
		}
	}
	return false
}

// fileProcessor is a worker that processes files from a channel.
func fileProcessor(id int, wg *sync.WaitGroup, jobs <-chan string, results chan<- FileMetadata, filesProcessed *uint64, fileLimit int, limitReached chan<- struct{}) {
	defer wg.Done()
	for path := range jobs {
		if fileLimit > 0 {
			currentProcessed := atomic.LoadUint64(filesProcessed)
			if currentProcessed >= uint64(fileLimit) {
				close(limitReached)
				return
			}
		}

		stat, err := os.Stat(path)
		if err != nil {
			if !os.IsNotExist(err) && !os.IsPermission(err) {
				errorLogger.Printf("Worker %d: Failed to stat file %s: %v", id, path, err)
			}
			continue
		}

		results <- FileMetadata{
			Path:    path,
			ModTime: stat.ModTime(),
			Size:    stat.Size(),
		}

		newCount := atomic.AddUint64(filesProcessed, 1)
		if fileLimit > 0 && newCount >= uint64(fileLimit) {
			close(limitReached)
			return
		}
	}
}

// encryptAndSign secures the data payload.
func encryptAndSign(data []byte, rsaPublic *rsa.PublicKey, rsaPrivate *rsa.PrivateKey) ([]byte, error) {
	// 1. Generate a new per-file AES-256 symmetric key.
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}

	// 2. Encrypt the data with AES-GCM.
	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	encryptedData := gcm.Seal(nonce, nonce, data, nil)

	// 3. Encrypt the AES key with the server's public RSA key.
	encryptedAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPublic, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt AES key with RSA: %w", err)
	}

	// 4. Sign the hash of the encrypted data blob with our private key.
	hash := sha256.Sum256(encryptedData)
	signature, err := rsa.SignPSS(rand.Reader, rsaPrivate, crypto.SHA256, hash[:], nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	// 5. Assemble the final payload with a simple binary protocol for easy parsing:
	// [2-byte length of key][encrypted key][2-byte length of sig][signature][encrypted data]
	var buffer bytes.Buffer
	buffer.Write([]byte{byte(len(encryptedAESKey) >> 8), byte(len(encryptedAESKey))})
	buffer.Write(encryptedAESKey)
	buffer.Write([]byte{byte(len(signature) >> 8), byte(len(signature))})
	buffer.Write(signature)
	buffer.Write(encryptedData)

	return buffer.Bytes(), nil
}

// loadKeys parses the embedded PEM-encoded keys.
func loadKeys() (*rsa.PublicKey, *rsa.PrivateKey, error) {
	blockPub, _ := pem.Decode(encryptKeyPEM)
	if blockPub == nil {
		return nil, nil, errors.New("failed to decode server public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(blockPub.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse server public key: %w", err)
	}
	rsaPublic, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("server key is not an RSA public key")
	}

	blockPriv, _ := pem.Decode(signingKeyPEM)
	if blockPriv == nil {
		return nil, nil, errors.New("failed to decode scanner private key PEM")
	}
	priv, err := x509.ParsePKCS8PrivateKey(blockPriv.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse scanner private key: %w", err)
	}
	rsaPrivate, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("scanner key is not an RSA private key")
	}

	return rsaPublic, rsaPrivate, nil
}

func getWindowsDrives() ([]string, error) {
	if runtime.GOOS != "windows" {
		return nil, errors.New("not on windows")
	}
	var drives []string
	for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		path := string(drive) + ":\\"
		_, err := os.ReadDir(path)
		if err == nil {
			drives = append(drives, path)
		}
	}
	return drives, nil
}

// main is the application entry point.
func main() {
	// --- 1. User Input and Configuration ---
	scannerName := flag.String("scanner", "default_scanner", "Name of the person/entity performing the scan.")
	laptopID := flag.String("laptop", "default_laptop", "Identifier for the laptop being scanned.")
	outputPath := flag.String("out", ".", "Output path for scanned data.")
	bulkSize := flag.Int("bulk", 500, "Number of file records to save in each output file.")
	parallelism := flag.Int("p", runtime.NumCPU(), "Number of parallel workers to use for scanning.")
	fileLimit := flag.Int("limit", 0, "Maximum number of files to scan (0 for unlimited)")
	flag.Parse()

	if err := os.MkdirAll(*outputPath, 0755); err != nil {
		log.Fatalf("Could not create output directory: %v", err)
	}

	if err := setupLogging(); err != nil {
		log.Fatalf("Failed to setup logging: %v", err)
	}

	infoLogger.Println("--- Starting File Scanner ---")
	infoLogger.Printf("Config: Scanner=%s, Laptop=%s, Output=%s, BulkSize=%d, Parallelism=%d, FileLimit=%d",
		*scannerName, *laptopID, *outputPath, *bulkSize, *parallelism, *fileLimit)

	// --- 2. Initialize Crypto and System Info ---
	serverPubKey, scannerPrivKey, err := loadKeys()
	if err != nil {
		errorLogger.Fatalf("Could not load cryptographic keys: %v", err)
	}
	infoLogger.Println("Cryptographic keys loaded successfully.")

	hardDriveID := GetHardDriveID()
	installedApps := GetInstalledApps()
	infoLogger.Printf("Collected system info. HardDriveID: %s, Apps Found: %d", hardDriveID, len(installedApps))

	// --- 3. Setup Concurrent Processing ---
	jobs := make(chan string, *parallelism*2)
	results := make(chan FileMetadata, *parallelism*2)
	var wg sync.WaitGroup
	var filesProcessed, filesWritten, bulksCreated uint64

	// Create a channel to signal when file limit is reached
	limitReached := make(chan struct{})

	for w := 1; w <= *parallelism; w++ {
		wg.Add(1)
		go fileProcessor(w, &wg, jobs, results, &filesProcessed, *fileLimit, limitReached)
	}

	// --- 4. Start File System Traversal ---
	go func() {
		defer close(jobs) // Ensure jobs channel is closed when walk is done

		roots := []string{"/Users"} // Default for macOS
		if runtime.GOOS == "linux" {
			roots = []string{"/home"}
		} else if runtime.GOOS == "windows" {
			roots, _ = getWindowsDrives()
		}

		for _, root := range roots {
			select {
			case <-limitReached:
				return // Stop if file limit is reached
			default:
				infoLogger.Printf("Starting filesystem walk on: %s", root)
				filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
					select {
					case <-limitReached:
						return filepath.SkipAll
					default:
						if err != nil {
							if !os.IsPermission(err) && !os.IsNotExist(err) {
								errorLogger.Printf("Access error on path %s: %v", path, err)
							}
							return filepath.SkipDir
						}

						if atomic.LoadUint64(&filesProcessed) >= uint64(*fileLimit) && *fileLimit > 0 {
							close(limitReached)
							return filepath.SkipAll
						}

						if isIgnored(path) {
							if info.IsDir() {
								return filepath.SkipDir
							}
							return nil
						}

						if !info.IsDir() && info.Size() > 0 {
							select {
							case jobs <- path:
							case <-limitReached:
								return filepath.SkipAll
							}
						}
						return nil
					}
				})
			}
		}
	}()

	// --- 5. Progress Reporting ---
	progressTicker := time.NewTicker(5 * time.Second) // Changed to 5 seconds for better feedback with small limits
	defer progressTicker.Stop()
	quitProgress := make(chan struct{})
	go func() {
		for {
			select {
			case <-progressTicker.C:
				processed := atomic.LoadUint64(&filesProcessed)
				infoLogger.Printf("PROGRESS: %d/%d files processed | %d bulks created | %d total files written.",
					processed,
					*fileLimit,
					atomic.LoadUint64(&bulksCreated),
					atomic.LoadUint64(&filesWritten),
				)
				if *fileLimit > 0 && processed >= uint64(*fileLimit) {
					return
				}
			case <-quitProgress:
				return
			}
		}
	}()

	// --- 6. Collect Results and Write Bulks ---
	var fileBatch []FileMetadata
resultLoop:
	for {
		select {
		case result, ok := <-results:
			if !ok {
				break resultLoop // Channel is closed and drained
			}
			fileBatch = append(fileBatch, result)
			if len(fileBatch) >= *bulkSize {
				writeBulk(fileBatch, *outputPath, *scannerName, *laptopID, hardDriveID, installedApps, &bulksCreated, &filesWritten, serverPubKey, scannerPrivKey)
				fileBatch = nil // Reset batch
			}
		}
	}

	wg.Wait() // Wait for all processor goroutines to finish

	// Write any remaining files in the last batch
	if len(fileBatch) > 0 {
		infoLogger.Printf("Writing final batch with %d files.", len(fileBatch))
		writeBulk(fileBatch, *outputPath, *scannerName, *laptopID, hardDriveID, installedApps, &bulksCreated, &filesWritten, serverPubKey, scannerPrivKey)
	}

	close(quitProgress) // Stop the progress reporter
	infoLogger.Println("--- Scan Complete ---")
	infoLogger.Printf("Total files processed: %d", atomic.LoadUint64(&filesProcessed))
	infoLogger.Printf("Total files written: %d", atomic.LoadUint64(&filesWritten))
	infoLogger.Printf("Total bulks created: %d", atomic.LoadUint64(&bulksCreated))
}

// writeBulk handles the process of converting a batch of files to JSON, encrypting, and writing to disk.
func writeBulk(batch []FileMetadata, outPath, scannerName, laptopID, hdID string, apps []string, bulks, written *uint64, pubKey *rsa.PublicKey, privKey *rsa.PrivateKey) {
	output := ScanOutput{
		ScannerName:   scannerName,
		LaptopID:      laptopID,
		HardDriveID:   hdID,
		InstalledApps: apps,
		Files:         batch,
	}

	jsonData, err := json.Marshal(output)
	if err != nil {
		errorLogger.Printf("Failed to marshal JSON for bulk: %v", err)
		return
	}

	encryptedData, err := encryptAndSign(jsonData, pubKey, privKey)
	if err != nil {
		errorLogger.Printf("Failed to encrypt and sign bulk: %v", err)
		return
	}

	bulkNum := atomic.AddUint64(bulks, 1)
	filename := filepath.Join(outPath, fmt.Sprintf("scan_data_%d.json", bulkNum))

	err = os.WriteFile(filename, encryptedData, 0644)
	if err != nil {
		errorLogger.Printf("Failed to write bulk file %s: %v", filename, err)
		return
	}

	atomic.AddUint64(written, uint64(len(batch)))
}
