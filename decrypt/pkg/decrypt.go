package decrypt

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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed server_private.pem
var serverPrivKeyPEM []byte

//go:embed scanner_public.pem
var scannerPubKeyPEM []byte

// decryptAndVerify is the core function that processes a single encrypted file.
func decryptAndVerify(data []byte, serverPrivKey *rsa.PrivateKey, scannerPubKey *rsa.PublicKey) ([]byte, error) {
	// 1. --- Parse the Payload ---
	// The payload is structured as:
	// [2-byte key length][encrypted AES key][2-byte sig length][signature][encrypted data]
	if len(data) < 4 {
		return nil, errors.New("payload is too short to be valid")
	}

	keyLen := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) < keyLen {
		return nil, errors.New("invalid key length in payload")
	}
	encryptedAESKey := data[:keyLen]
	data = data[keyLen:]

	if len(data) < 2 {
		return nil, errors.New("payload is too short for signature length")
	}
	sigLen := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) < sigLen {
		return nil, errors.New("invalid signature length in payload")
	}
	signature := data[:sigLen]
	encryptedData := data[sigLen:]

	// 2. --- Decrypt the AES Key ---
	// Use OAEP padding as used in the encryption
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, serverPrivKey, encryptedAESKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AES key: %w", err)
	}

	// 3. --- Verify the Signature ---
	hash := sha256.Sum256(encryptedData)
	err = rsa.VerifyPSS(scannerPubKey, crypto.SHA256, hash[:], signature, nil)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// 4. --- Decrypt the Data ---
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher from decrypted key: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, errors.New("encrypted data is smaller than nonce size")
	}
	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]

	decryptedData, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data with AES-GCM: %w", err)
	}

	return decryptedData, nil
}

// loadKeys parses the embedded PEM-encoded keys required for decryption and verification.
func loadKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	// Load server's private key for decryption
	blockPriv, _ := pem.Decode(serverPrivKeyPEM)
	if blockPriv == nil {
		return nil, nil, errors.New("failed to decode server private key PEM")
	}
	priv, err := x509.ParsePKCS8PrivateKey(blockPriv.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse server private key: %w", err)
	}
	serverPrivKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, errors.New("server key is not an RSA private key")
	}

	// Load scanner's public key for verification
	blockPub, _ := pem.Decode(scannerPubKeyPEM)
	if blockPub == nil {
		return nil, nil, errors.New("failed to decode scanner public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(blockPub.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse scanner public key: %w", err)
	}
	scannerPubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, nil, errors.New("scanner key is not an RSA public key")
	}

	return serverPrivKey, scannerPubKey, nil
}

// worker function to process files from a channel
func worker(id int, wg *sync.WaitGroup, jobs <-chan string, targetDir string, serverPrivKey *rsa.PrivateKey, scannerPubKey *rsa.PublicKey) {
	defer wg.Done()
	for jobPath := range jobs {
		log.Printf("Worker %d: Processing %s", id, filepath.Base(jobPath))

		// Read the encrypted file content
		encryptedBytes, err := os.ReadFile(jobPath)
		if err != nil {
			log.Printf("ERROR: Worker %d failed to read %s: %v", id, jobPath, err)
			continue
		}

		// Decrypt and verify the content
		decryptedJSON, err := decryptAndVerify(encryptedBytes, serverPrivKey, scannerPubKey)
		if err != nil {
			log.Printf("ERROR: Worker %d failed to decrypt/verify %s: %v", id, jobPath, err)
			continue
		}

		// Pretty-print the JSON for readability
		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, decryptedJSON, "", "  "); err != nil {
			log.Printf("ERROR: Worker %d failed to format JSON from %s: %v", id, jobPath, err)
			// Fallback to writing the raw JSON
			prettyJSON.Write(decryptedJSON)
		}

		// Write the decrypted JSON to the target directory
		newFileName := strings.Replace(filepath.Base(jobPath), ".bin", ".json", 1)
		targetPath := filepath.Join(targetDir, newFileName)
		err = os.WriteFile(targetPath, prettyJSON.Bytes(), 0644)
		if err != nil {
			log.Printf("ERROR: Worker %d failed to write JSON file %s: %v", id, targetPath, err)
		}
	}
}

// ProcessFiles handles the decryption of all .bin files in the source directory
// and saves the decrypted JSON files to the target directory
func ProcessFiles(sourceDir string, targetDir string, parallelism int) {
	// Create target directory if it doesn't exist
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		log.Fatalf("Failed to create target directory: %v", err)
	}

	log.Println("--- Starting Decryption Process ---")
	log.Printf("Source: %s | Target: %s | Parallelism: %d", sourceDir, targetDir, parallelism)

	// Load Cryptographic Keys
	serverPrivKey, scannerPubKey, err := loadKeys()
	if err != nil {
		log.Fatalf("Fatal error loading keys: %v", err)
	}
	log.Println("Successfully loaded cryptographic keys.")

	// Setup Concurrent Workers
	jobs := make(chan string, 100)
	var wg sync.WaitGroup

	for w := 1; w <= parallelism; w++ {
		wg.Add(1)
		go worker(w, &wg, jobs, targetDir, serverPrivKey, scannerPubKey)
	}

	// Find and Dispatch Jobs
	err = filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".bin") {
			jobs <- path
		}
		return nil
	})

	if err != nil {
		log.Fatalf("Error walking source directory: %v", err)
	}

	// Close jobs channel and wait for workers to finish
	close(jobs)
	wg.Wait()
	log.Println("Decryption process completed successfully.")
}
