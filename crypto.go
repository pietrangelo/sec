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

// File format v2
//
//	magic       "SEC\x02"                     4 bytes
//	kdf         0x01 raw key | 0x02 argon2id  1 byte
//	[argon2id]  time (u32 BE), memory KiB (u32 BE), threads (u8), salt (16 bytes)
//	prefix      nonce prefix                  16 bytes
//	chunks      XChaCha20-Poly1305 sealed chunks of up to 64 KiB of plaintext
//
// The master key is either the raw 32-byte key or Argon2id(passphrase, salt).
// The payload key is HKDF-SHA256(master, salt=prefix, info="sec v2 payload"),
// so every file gets its own key. Chunk i uses nonce prefix || u64 BE(i) and
// AAD header || flag, where flag is 0x01 for the final chunk and 0x00 otherwise.
// This is the STREAM construction: chunks cannot be reordered, dropped or
// truncated, and data appended after the final chunk is rejected. Every stream
// has a final chunk, even an empty one.
//
// In deterministic mode the prefix is HMAC-SHA256(sivKey, header || plaintext)
// truncated to 16 bytes (a synthetic IV, as git-crypt does), so the same
// plaintext under the same key always gives the same ciphertext. This keeps
// git clean filters stable and only reveals whether two files are identical.

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ChunkSize  = 64 * 1024
	KeySize    = 32
	PrefixSize = 16

	kdfRawKey   byte = 0x01
	kdfArgon2id byte = 0x02

	argonSaltSize = 16

	// Defaults follow the second recommended option of RFC 9106 (t=3, 64 MiB).
	argonTime    uint32 = 3
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 4

	// Upper bounds accepted when decrypting, so a crafted header cannot make
	// the tool allocate unbounded memory or spin forever.
	maxArgonTime   uint32 = 16
	maxArgonMemory uint32 = 2 * 1024 * 1024
)

var magicV2 = []byte("SEC\x02")

var (
	ErrAuth      = errors.New("bad key/password or corrupt data")
	ErrTruncated = errors.New("ciphertext is truncated")
)

// Secret is what the user supplies: a raw key or a passphrase, never both.
type Secret struct {
	Key        []byte
	Passphrase string
}

func (s Secret) masterKey(hdr *header) ([]byte, error) {
	switch hdr.kdf {
	case kdfRawKey:
		if len(s.Key) != KeySize {
			return nil, errors.New("this file was encrypted with a key: use -keyfile or SEC_TOOL_KEY")
		}
		return s.Key, nil
	case kdfArgon2id:
		if s.Passphrase == "" {
			return nil, errors.New("this file was encrypted with a passphrase: use SEC_TOOL_PASS")
		}
		return argon2.IDKey([]byte(s.Passphrase), hdr.salt, hdr.time, hdr.memory, hdr.threads, KeySize), nil
	}
	return nil, fmt.Errorf("unknown kdf 0x%02x", hdr.kdf)
}

type header struct {
	kdf     byte
	time    uint32
	memory  uint32
	threads uint8
	salt    []byte
	prefix  []byte
}

// params returns the serialised header without the nonce prefix.
func (h *header) params() []byte {
	b := append([]byte{}, magicV2...)
	b = append(b, h.kdf)
	if h.kdf == kdfArgon2id {
		b = binary.BigEndian.AppendUint32(b, h.time)
		b = binary.BigEndian.AppendUint32(b, h.memory)
		b = append(b, h.threads)
		b = append(b, h.salt...)
	}
	return b
}

func (h *header) bytes() []byte {
	return append(h.params(), h.prefix...)
}

func readHeader(r io.Reader) (*header, error) {
	h := &header{}
	kdf := make([]byte, 1)
	if _, err := io.ReadFull(r, kdf); err != nil {
		return nil, ErrTruncated
	}
	h.kdf = kdf[0]
	switch h.kdf {
	case kdfRawKey:
	case kdfArgon2id:
		p := make([]byte, 9+argonSaltSize)
		if _, err := io.ReadFull(r, p); err != nil {
			return nil, ErrTruncated
		}
		h.time = binary.BigEndian.Uint32(p[0:4])
		h.memory = binary.BigEndian.Uint32(p[4:8])
		h.threads = p[8]
		h.salt = p[9:]
		if h.time == 0 || h.time > maxArgonTime || h.memory < 8*uint32(h.threads) ||
			h.memory > maxArgonMemory || h.threads == 0 {
			return nil, errors.New("argon2id parameters out of accepted range")
		}
	default:
		return nil, fmt.Errorf("unknown kdf 0x%02x", h.kdf)
	}
	h.prefix = make([]byte, PrefixSize)
	if _, err := io.ReadFull(r, h.prefix); err != nil {
		return nil, ErrTruncated
	}
	return h, nil
}

func newHeader(s Secret) (*header, error) {
	if len(s.Key) == KeySize {
		return &header{kdf: kdfRawKey}, nil
	}
	if s.Key != nil {
		return nil, fmt.Errorf("key must be %d bytes", KeySize)
	}
	if s.Passphrase == "" {
		return nil, errors.New("no key or passphrase given")
	}
	salt := make([]byte, argonSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return &header{kdf: kdfArgon2id, time: argonTime, memory: argonMemory, threads: argonThreads, salt: salt}, nil
}

func payloadAEAD(master, prefix []byte) (*aeadStream, error) {
	k, err := hkdf.Key(sha256.New, master, prefix, "sec v2 payload", KeySize)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	return &aeadStream{aead: aead, prefix: prefix}, nil
}

type aeadStream struct {
	aead    cipher.AEAD
	prefix  []byte
	counter uint64
	hdr     []byte
}

func (s *aeadStream) nonceAndAAD(last bool) ([]byte, []byte) {
	nonce := binary.BigEndian.AppendUint64(append([]byte{}, s.prefix...), s.counter)
	flag := byte(0)
	if last {
		flag = 1
	}
	return nonce, append(append([]byte{}, s.hdr...), flag)
}

func (s *aeadStream) seal(p []byte, last bool) []byte {
	nonce, ad := s.nonceAndAAD(last)
	s.counter++
	return s.aead.Seal(nil, nonce, p, ad)
}

func (s *aeadStream) open(c []byte, last bool) ([]byte, error) {
	nonce, ad := s.nonceAndAAD(last)
	s.counter++
	p, err := s.aead.Open(nil, nonce, c, ad)
	if err != nil {
		return nil, ErrAuth
	}
	return p, nil
}

// Encrypt writes the v2 encryption of in to out. With deterministic set, the
// whole input is buffered in memory and a raw key is required.
func Encrypt(in io.Reader, out io.Writer, s Secret, deterministic bool) error {
	hdr, err := newHeader(s)
	if err != nil {
		return err
	}
	master, err := s.masterKey(hdr)
	if err != nil {
		return err
	}

	if deterministic {
		if hdr.kdf != kdfRawKey {
			return errors.New("deterministic mode needs a key (-keyfile or SEC_TOOL_KEY), not a passphrase")
		}
		data, err := io.ReadAll(in)
		if err != nil {
			return err
		}
		sivKey, err := hkdf.Key(sha256.New, master, nil, "sec v2 siv", KeySize)
		if err != nil {
			return err
		}
		mac := hmac.New(sha256.New, sivKey)
		mac.Write(hdr.params())
		mac.Write(data)
		hdr.prefix = mac.Sum(nil)[:PrefixSize]
		in = bytes.NewReader(data)
	} else {
		hdr.prefix = make([]byte, PrefixSize)
		if _, err := rand.Read(hdr.prefix); err != nil {
			return err
		}
	}

	stream, err := payloadAEAD(master, hdr.prefix)
	if err != nil {
		return err
	}
	stream.hdr = hdr.bytes()
	if _, err := out.Write(stream.hdr); err != nil {
		return err
	}

	br := bufio.NewReaderSize(in, ChunkSize)
	buf := make([]byte, ChunkSize)
	for {
		n, err := io.ReadFull(br, buf)
		last := false
		switch {
		case err == io.EOF || err == io.ErrUnexpectedEOF:
			last = true
		case err != nil:
			return err
		default:
			if _, perr := br.Peek(1); perr == io.EOF {
				last = true
			} else if perr != nil {
				return perr
			}
		}
		if _, err := out.Write(stream.seal(buf[:n], last)); err != nil {
			return err
		}
		if last {
			return nil
		}
	}
}

// Decrypt reads a v2 stream (or a legacy v1 stream when the magic is absent)
// and writes the plaintext to out. Each chunk is authenticated before it is
// written, but a truncated stream is only detected at the end, so callers must
// discard the output when an error is returned.
func Decrypt(in io.Reader, out io.Writer, s Secret) error {
	br := bufio.NewReaderSize(in, ChunkSize+chacha20poly1305.Overhead)
	magic, _ := br.Peek(len(magicV2))
	if len(magic) == 0 {
		return ErrTruncated
	}
	if !bytes.Equal(magic, magicV2) {
		return decryptV1(br, out, s)
	}
	br.Discard(len(magicV2))

	hdr, err := readHeader(br)
	if err != nil {
		return err
	}
	master, err := s.masterKey(hdr)
	if err != nil {
		return err
	}
	stream, err := payloadAEAD(master, hdr.prefix)
	if err != nil {
		return err
	}
	stream.hdr = hdr.bytes()

	buf := make([]byte, ChunkSize+chacha20poly1305.Overhead)
	for {
		n, err := io.ReadFull(br, buf)
		last := false
		switch {
		case err == io.EOF:
			return ErrTruncated
		case err == io.ErrUnexpectedEOF:
			last = true
		case err != nil:
			return err
		default:
			if _, perr := br.Peek(1); perr == io.EOF {
				last = true
			} else if perr != nil {
				return perr
			}
		}
		p, err := stream.open(buf[:n], last)
		if err != nil {
			if !last {
				// A full-size chunk that only opens as final means the
				// rest of the stream was cut off.
				return ErrAuth
			}
			return err
		}
		if _, err := out.Write(p); err != nil {
			return err
		}
		if last {
			return nil
		}
	}
}

// Legacy v1 format: salt (32) || nonce (24) || chunks, Argon2id(t=1, 64 MiB),
// counter in the last 8 bytes of the nonce, no final-chunk marker. Kept only
// so that existing files can still be decrypted; it does not detect truncation.
const (
	v1SaltSize  = 32
	v1NonceSize = 24
)

func decryptV1(in io.Reader, out io.Writer, s Secret) error {
	if s.Passphrase == "" {
		return errors.New("legacy v1 files need the passphrase (SEC_TOOL_PASS)")
	}
	salt := make([]byte, v1SaltSize)
	if _, err := io.ReadFull(in, salt); err != nil {
		return ErrTruncated
	}
	nonce := make([]byte, v1NonceSize)
	if _, err := io.ReadFull(in, nonce); err != nil {
		return ErrTruncated
	}
	key := argon2.IDKey([]byte(s.Passphrase), salt, 1, 64*1024, 4, KeySize)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	buf := make([]byte, ChunkSize+aead.Overhead())
	for {
		n, readErr := io.ReadFull(in, buf)
		if n > 0 {
			p, err := aead.Open(nil, nonce, buf[:n], nil)
			if err != nil {
				return ErrAuth
			}
			if _, err := out.Write(p); err != nil {
				return err
			}
			ctr := binary.LittleEndian.Uint64(nonce[16:])
			binary.LittleEndian.PutUint64(nonce[16:], ctr+1)
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}
