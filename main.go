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
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sec:", err)
		os.Exit(1)
	}
}

func run() error {
	mode := flag.String("mode", "", "encrypt, decrypt or genkey")
	filePath := flag.String("file", "", "path to file (use - for stdin/stdout)")
	pass := flag.String("pass", "", "passphrase (deprecated: visible to other processes, use SEC_TOOL_PASS)")
	keyFile := flag.String("keyfile", "", "file holding a base64 key made with -mode=genkey (or set SEC_TOOL_KEY)")
	deterministic := flag.Bool("deterministic", false, "same plaintext and key give the same ciphertext (for git filters; needs a key)")
	flag.Parse()

	if *mode == "genkey" {
		k := make([]byte, KeySize)
		if _, err := rand.Read(k); err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(k))
		return nil
	}
	if *mode != "encrypt" && *mode != "decrypt" {
		return errors.New("usage: sec -mode=[encrypt|decrypt|genkey] [-file=PATH] [-keyfile=PATH | SEC_TOOL_KEY | SEC_TOOL_PASS] [-deterministic]")
	}

	secret, err := loadSecret(*keyFile, *pass)
	if err != nil {
		return err
	}

	process := func(in io.Reader, out io.Writer) error {
		if *mode == "encrypt" {
			return Encrypt(in, out, secret, *deterministic)
		}
		return Decrypt(in, out, secret)
	}

	if *filePath == "-" || *filePath == "" {
		return process(os.Stdin, os.Stdout)
	}
	return processFile(*filePath, process)
}

// loadSecret picks, in order: -keyfile, SEC_TOOL_KEY, -pass, SEC_TOOL_PASS.
// The key and the passphrase are both kept when present, so that legacy v1
// files can still be decrypted with the passphrase.
func loadSecret(keyFile, pass string) (Secret, error) {
	var s Secret
	encoded := os.Getenv("SEC_TOOL_KEY")
	if keyFile != "" {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return s, err
		}
		encoded = string(b)
	}
	if encoded != "" {
		k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
		if err != nil || len(k) != KeySize {
			return s, fmt.Errorf("key must be %d bytes, base64 encoded (make one with -mode=genkey)", KeySize)
		}
		s.Key = k
	}
	if pass != "" {
		fmt.Fprintln(os.Stderr, "sec: warning: -pass is visible to other processes and in shell history, prefer SEC_TOOL_PASS or a key")
		s.Passphrase = pass
	} else {
		s.Passphrase = os.Getenv("SEC_TOOL_PASS")
	}
	if s.Key == nil && s.Passphrase == "" {
		return s, errors.New("no key or passphrase: use -keyfile, SEC_TOOL_KEY or SEC_TOOL_PASS")
	}
	return s, nil
}

// processFile replaces path with its processed contents. The output goes to a
// private temporary file in the same directory, which only replaces the
// original once processing has fully succeeded, so a wrong key or a truncated
// file never leaves partial plaintext or a half-written file behind.
func processFile(path string, process func(io.Reader, io.Writer) error) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".sec-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()

	if err := process(in, tmp); err != nil {
		return err
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	in.Close()
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}
