#!/usr/bin/env bash

# Settings
TOOL_NAME="./sec"
TEST_FILE="test_secret.dat"
PASS="super-secure-password"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Helper: Calculate SHA256 in a cross-platform way ---
calculate_hash() {
  if command -v sha256 >/dev/null 2>&1; then
    # FreeBSD / macOS
    # sha256 output: "SHA256 (file) = hash" -> we want the last field
    # but FreeBSD 'sha256 -q' gives just the hash.
    sha256 -q "$1"
  elif command -v sha256sum >/dev/null 2>&1; then
    # Linux
    sha256sum "$1" | awk '{ print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    # macOS
    shasum -a 256 "$1" | awk '{ pring $1 }'
  else
    echo "Error: No SHA256 utility found."
    exit 1
  fi
}

echo "--- Starting Integrity Test ---"

# 1. Build the tool first to ensure we test the latest code
echo "Building tool..."
go build -o "$TOOL_NAME" main.go
if [ $? -ne 0 ]; then
  echo -e "${RED}Build failed!${NC}"
  exit 1
fi

# 2. Create a random 10MB file
echo "Creating 10MB random file..."
dd if=/dev/urandom of=$TEST_FILE bs=1M count=10 status=none

# 3. Calculate original hash
ORIGINAL_HASH=$(calculate_hash $TEST_FILE)
echo "Original Hash: $ORIGINAL_HASH"

# 4. Encrypt
echo "Encrypting..."
$TOOL_NAME -mode=encrypt -file=$TEST_FILE -pass=$PASS
if [ $? -ne 0 ]; then
  echo -e "${RED}Encryption crashed!${NC}"
  exit 1
fi

# Verify the file is effectively "scrambled" (The hash should change)
# Note: Since we overwrite, the file on disk is now encrypted.
ENC_HASH=$(calculate_hash $TEST_FILE)
if [ "$ORIGINAL_HASH" == "$ENC_HASH" ]; then
  echo -e "${RED}Security Failure: File content did not change after encryption!${NC}"
  exit 1
fi

# 5. Decrypt
echo "Decrypting..."
$TOOL_NAME -mode=decrypt -file=$TEST_FILE -pass=$PASS
if [ $? -ne 0 ]; then
  echo -e "${RED}Decryption crashed!${NC}"
  exit 1
fi

# 6. Verify Integrity
FINAL_HASH=$(calculate_hash $TEST_FILE)
echo "Final Hash:    $FINAL_HASH"

if [ "$ORIGINAL_HASH" == "$FINAL_HASH" ]; then
  echo -e "${GREEN}SUCCESS: Decrypted file matches original exactly.${NC}"
  rm $TEST_FILE
  rm $TOOL_NAME
  exit 0
else
  echo -e "${RED}FAILURE: Hashes do not match. Data corruption occurred.${NC}"
  exit 1
fi
