# File Scanner Project

This tool scans a computer's file system, collects metadata, and saves it in encrypted and signed batches.

## 1. Prerequisites: Generate Crypto Keys

This tool requires two RSA key files to be present in the project directory before building.

- **`scanner_private.pem`**: A private key used by this tool to **sign** the data.
- **`server_public.pem`**: The public key from a server, used to **encrypt** the data's symmetric key.

Generate these keys using **OpenSSL**:

```bash
# 1. Generate the Scanner's private key for signing
openssl genpkey -algorithm RSA -out scanner_private.pem -pkeyopt rsa_keygen_bits:2048

# 2. Generate the Server's private key (the server keeps this secret)
openssl genpkey -algorithm RSA -out server_private.pem -pkeyopt rsa_keygen_bits:2048

# 3. Extract the Server's public key from its private key.
# This is the file you need for the project.
openssl rsa -in server_private.pem -pubout -out server_public.pem
```

Place `scanner_private.pem` and `server_public.pem` in the same directory as the `.go` files.

## 2. Build the Application

With the `.go` and `.pem` files in the same directory, open a terminal and run:

```bash
# To initialize the module (first time only)
go mod tidy

# To build the executable
go build -o filescanner
```
This creates `filescanner` (or `filescanner.exe` on Windows).

## 3. Run the Application

Copy the executable to a USB drive or any location and run it from the command line with flags.

**Example on Linux:**
```bash
./filescanner -scanner="John Doe" -laptop="DELL-XPS15" -out="/media/user/MY_USB/scan_results" -p=8

sudo ./filescanner -scanner="John Doe" -laptop="DELL-XPS15" -out="/Users/liran/Documents/dev/go/poc_amir/2/out" -p=8 -limit=3
```

**Example on Windows:**
```powershell
.\filescanner.exe -scanner="Jane Doe" -laptop="HP-SPECTRE" -out="E:\scan_results" -p=4 -bulk=1000
```

### Flags:
- `-scanner`: Your name or ID.
- `-laptop`: An identifier for the computer being scanned.
- `-out`: The output path for logs and data (e.g., your USB key).
- `-p`: (Optional) Number of parallel threads to use. Defaults to the number of CPU cores.
- `-bulk`: (Optional) Number of file records per output file. Defaults to 500.

## 4. Run Tests

To verify the code's correctness, run the tests from the project directory:

```bash
# Run tests and show detailed output
go test -v
```

==compile to windows
GOOS=windows GOARCH=amd64 go build -o filescanner.exe
==compile to mac intel
GOOS=darwin GOARCH=amd64 go build -o filescanner main.go

==compile to mac new (arm64)
GOOS=darwin GOARCH=arm64 go build -o filescanner main.go
