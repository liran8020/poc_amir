package main

import (
	"flag"
	"fmt"
	"os"

	"decrypt/pkg"

	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

func loadPublicKey(path string) (interface{}, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

func main() {
	loadPublicKey("decrypt/pkg/scanner_public.pem")
	// 1. --- Setup Command-Line Arguments ---
	sourceDir := flag.String("source", "", "Source directory containing encrypted .bin files.")
	targetDir := flag.String("target", "", "Target directory to save decrypted .json files.")
	parallelism := flag.Int("p", 4, "Number of parallel workers to run.")
	flag.Parse()

	if *sourceDir == "" || *targetDir == "" {
		fmt.Println("Both --source and --target flags are required.")
		flag.Usage()
		os.Exit(1)
	}

	// Call into the decrypt package's main function
	decrypt.ProcessFiles(*sourceDir, *targetDir, *parallelism)
}
