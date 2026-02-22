// sec
// A tool to easily encrypt/decrypt files.

// Copyright (C) 2026 Pietrangelo Masala

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ChunkSize = 64 * 1024
	KeySize   = 32
	SaltSize  = 32
	NonceSize = 24
)

func main() {
	mode := flag.String("mode", "", "encrypt or decrypt")
	filePath := flag.String("file", "", "path to file (use - for stdin/stdout)")
	pass := flag.String("pass", "", "passphrase")
	flag.Parse()

	// 1. Support Password from Environment Variable (Best for Git)
	password := *pass
	if password == "" {
		password = os.Getenv("SEC_TOOL_PASS")
	}

	if *mode == "" || password == "" {
		log.Fatal("Usage: sec -mode=[encrypt|decrypt] -pass=SECRET (or set SEC_TOOL_PASS env)")
	}

	// 2. Setup Input/Output Streams
	var reader io.Reader
	var writer io.Writer

	if *filePath == "-" || *filePath == "" {
		// Pipe Mode
		reader = os.Stdin
		writer = os.Stdout
	} else {
		// File Mode
		f, err := os.Open(*filePath)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		reader = f

		// Create temp file for atomic write
		outF, err := os.Create(*filePath + ".tmp")
		if err != nil {
			log.Fatal(err)
		}
		defer outF.Close()
		writer = outF

		// Defer rename logic for file mode
		defer func() {
			outF.Close()
			f.Close()
			os.Rename(*filePath+".tmp", *filePath)
		}()
	}

	// 3. Run Logic
	var err error
	if *mode == "encrypt" {
		err = encryptStream(reader, writer, password)
	} else {
		err = decryptStream(reader, writer, password)
	}

	if err != nil {
		log.Fatal(err)
	}
}

// Unified Stream Logic (Works for both Files and Pipes)
func encryptStream(in io.Reader, out io.Writer, password string) error {
	salt := make([]byte, SaltSize)
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	if _, err := out.Write(salt); err != nil {
		return err
	}
	if _, err := out.Write(nonce); err != nil {
		return err
	}

	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	buf := make([]byte, ChunkSize)
	chunkNonce := make([]byte, NonceSize)
	copy(chunkNonce, nonce)

	for {
		n, readErr := in.Read(buf)
		if n > 0 {
			ciphertext := aead.Seal(nil, chunkNonce, buf[:n], nil)
			if _, err := out.Write(ciphertext); err != nil {
				return err
			}
			incrementNonce(chunkNonce)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	return nil
}
func decryptStream(in io.Reader, out io.Writer, password string) error {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(in, salt); err != nil {
		return err
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(in, nonce); err != nil {
		return err
	}

	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	// Calculate encrypted chunk size
	encChunkSize := ChunkSize + aead.Overhead()
	buf := make([]byte, encChunkSize)
	chunkNonce := make([]byte, NonceSize)
	copy(chunkNonce, nonce)

	for {
		n, readErr := in.Read(buf)
		if n > 0 {
			plaintext, err := aead.Open(nil, chunkNonce, buf[:n], nil)
			if err != nil {
				return fmt.Errorf("bad password or corrupt data")
			}
			if _, err := out.Write(plaintext); err != nil {
				return err
			}
			incrementNonce(chunkNonce)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	return nil
}

func incrementNonce(nonce []byte) {
	counter := nonce[16:]
	val := binary.LittleEndian.Uint64(counter)
	val++
	binary.LittleEndian.PutUint64(counter, val)
}
