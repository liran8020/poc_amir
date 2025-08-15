package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"runtime"
	"testing"
)

// Unit Test for the isIgnored function.
func TestIsIgnored(t *testing.T) {
	// Setup ignoredDirs for a predictable test environment
	if runtime.GOOS == "windows" {
		ignoredDirs = map[string]struct{}{"C:\\Windows": {}}
		if !isIgnored("C:\\Windows\\System32\\kernel32.dll") {
			t.Error("Expected C:\\Windows path to be ignored")
		}
		if isIgnored("D:\\data\\file.txt") {
			t.Error("Expected D:\\data path not to be ignored")
		}
	} else {
		ignoredDirs = map[string]struct{}{"/proc": {}, "/sys": {}}
		if !isIgnored("/proc/cpuinfo") {
			t.Error("Expected /proc path to be ignored")
		}
		if isIgnored("/home/user/document.txt") {
			t.Error("Expected /home/user path not to be ignored")
		}
	}
}

// Unit Test for the calculateFileHash function.
func TestCalculateFileHash(t *testing.T) {
	content := []byte("hello world")
	tmpfile, err := os.CreateTemp("", "test_hash.*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	tmpfile.Write(content)
	tmpfile.Close()

	hash, err := calculateFileHash(tmpfile.Name())
	if err != nil {
		t.Fatalf("calculateFileHash failed: %v", err)
	}

	expectedHash := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if hash != expectedHash {
		t.Errorf("Hash mismatch: got %s, want %s", hash, expectedHash)
	}
}

// Integration Test for the crypto round-trip.
// This test is crucial because it simulates the server's role to ensure
// that data encrypted by the tool can actually be decrypted and verified later.
func TestEncryptAndSign_RoundTrip(t *testing.T) {
	// 1. Generate temporary RSA key pairs for the test.
	serverPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	serverPubKey := &serverPrivKey.PublicKey
	scannerPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	scannerPubKey := &scannerPrivKey.PublicKey

	// 2. Encrypt and sign a sample payload.
	originalData := []byte(`{"message":"this is a secret test"}`)
	encryptedPayload, err := encryptAndSign(originalData, serverPubKey, scannerPrivKey)
	if err != nil {
		t.Fatalf("encryptAndSign failed: %v", err)
	}

	// 3. --- Simulate Server-Side Decryption and Verification ---
	// Parse the payload according to our binary protocol.
	keyLen := int(encryptedPayload[0])<<8 | int(encryptedPayload[1])
	encryptedPayload = encryptedPayload[2:]
	encryptedAESKey := encryptedPayload[:keyLen]
	encryptedPayload = encryptedPayload[keyLen:]
	sigLen := int(encryptedPayload[0])<<8 | int(encryptedPayload[1])
	encryptedPayload = encryptedPayload[2:]
	signature := encryptedPayload[:sigLen]
	encryptedData := encryptedPayload[sigLen:]

	// Decrypt the symmetric AES key using the server's private key.
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, serverPrivKey, encryptedAESKey, nil)
	if err != nil {
		t.Fatalf("Failed to decrypt AES key: %v", err)
	}

	// Verify the signature using the scanner's public key.
	hash := sha256.Sum256(encryptedData)
	err = rsa.VerifyPSS(scannerPubKey, crypto.SHA256, hash[:], signature, nil)
	if err != nil {
		t.Fatalf("Signature verification failed: %v", err)
	}

	// Decrypt the main data payload using the recovered AES key.
	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	nonce, ciphertext := encryptedData[:gcm.NonceSize()], encryptedData[gcm.NonceSize():]
	decryptedData, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("Failed to decrypt data with AES-GCM: %v", err)
	}

	// 4. Final check.
	if string(decryptedData) != string(originalData) {
		t.Errorf("Decrypted data does not match original. Got: %s, Want: %s", string(decryptedData), string(originalData))
	}
	t.Log("Crypto round-trip successful!")
}
