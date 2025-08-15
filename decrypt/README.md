# Decrypt

This tool decrypt the encrypted and sign files, collected from the usb.

# To initialize the module (first time only)
go mod tidy

# To build the executable
go build -o decrypt


# To  run
./decrypt --source /path/to/source --target /path/to/target --p 4

## Example:
./decrypt --source  ../usb/out -target ./out --p 4


# Buid for windows
GOOS=windows GOARCH=amd64 go build -o decrypt.exe