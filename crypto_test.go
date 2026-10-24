package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"testing/iotest"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	testKey  = bytes.Repeat([]byte{7}, KeySize)
	keySec   = Secret{Key: testKey}
	passSec  = Secret{Passphrase: "correct horse battery staple"}
	testSize = []int{0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 3*ChunkSize + 123}
)

func randBytes(t *testing.T, n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func encrypt(t *testing.T, plain []byte, s Secret, det bool) []byte {
	t.Helper()
	var out bytes.Buffer
	// OneByteReader mimics a pipe that returns short reads.
	if err := Encrypt(iotest.OneByteReader(bytes.NewReader(plain)), &out, s, det); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func decrypt(c []byte, s Secret) ([]byte, error) {
	var out bytes.Buffer
	err := Decrypt(iotest.HalfReader(bytes.NewReader(c)), &out, s)
	return out.Bytes(), err
}

func TestRoundTrip(t *testing.T) {
	for _, n := range testSize {
		plain := randBytes(t, n)
		for _, tc := range []struct {
			name string
			s    Secret
			det  bool
		}{{"key", keySec, false}, {"key-deterministic", keySec, true}, {"passphrase", passSec, false}} {
			if tc.s.Passphrase != "" && n > ChunkSize+1 {
				continue // keep Argon2id runs to a few
			}
			got, err := decrypt(encrypt(t, plain, tc.s, tc.det), tc.s)
			if err != nil {
				t.Fatalf("%s size %d: %v", tc.name, n, err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("%s size %d: plaintext mismatch", tc.name, n)
			}
		}
	}
}

func TestDeterministic(t *testing.T) {
	plain := []byte("# CLAUDE.md\nsecret instructions\n")
	a, b := encrypt(t, plain, keySec, true), encrypt(t, plain, keySec, true)
	if !bytes.Equal(a, b) {
		t.Fatal("deterministic mode gave different ciphertexts")
	}
	if c := encrypt(t, append(plain, '!'), keySec, true); bytes.Equal(a[:len(a)-20], c[:len(a)-20]) {
		t.Fatal("different plaintexts share a ciphertext prefix")
	}
	if bytes.Equal(encrypt(t, plain, keySec, false), encrypt(t, plain, keySec, false)) {
		t.Fatal("randomised mode gave identical ciphertexts")
	}
	if err := Encrypt(bytes.NewReader(plain), io.Discard, passSec, true); err == nil {
		t.Fatal("deterministic mode accepted a passphrase")
	}
}

func TestTruncationAndTampering(t *testing.T) {
	plain := randBytes(t, 3*ChunkSize+10)
	c := encrypt(t, plain, keySec, false)
	hdrLen := len(magicV2) + 1 + PrefixSize
	chunk := ChunkSize + chacha20poly1305.Overhead

	cases := map[string][]byte{
		"header only":        c[:hdrLen],
		"drop last chunk":    c[:hdrLen+3*chunk],
		"cut mid chunk":      c[:hdrLen+chunk+100],
		"trailing data":      append(append([]byte{}, c...), 0),
		"flipped bit":        flip(c, hdrLen+5),
		"flipped prefix":     flip(c, hdrLen-1),
		"swapped chunks":     swap(c, hdrLen, chunk),
		"cut at chunk end 1": c[:hdrLen+chunk],
	}
	for name, bad := range cases {
		if _, err := decrypt(bad, keySec); err == nil {
			t.Errorf("%s: decryption succeeded", name)
		}
	}

	if _, err := decrypt(c, Secret{Key: bytes.Repeat([]byte{8}, KeySize)}); !errors.Is(err, ErrAuth) {
		t.Errorf("wrong key: got %v", err)
	}
	if _, err := decrypt(c, passSec); err == nil {
		t.Error("key-encrypted file opened with a passphrase")
	}
}

func TestRejectsHostileArgonParams(t *testing.T) {
	c := encrypt(t, []byte("x"), passSec, false)
	binary.BigEndian.PutUint32(c[5+4:], maxArgonMemory+1)
	if _, err := decrypt(c, passSec); err == nil {
		t.Fatal("accepted out-of-range memory parameter")
	}
}

func TestLegacyV1(t *testing.T) {
	plain := randBytes(t, 2*ChunkSize+5)
	c := encryptV1(t, plain, passSec.Passphrase)
	got, err := decrypt(c, passSec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("legacy plaintext mismatch")
	}
}

// encryptV1 reproduces the original v1 encoder for compatibility tests.
func encryptV1(t *testing.T, plain []byte, pass string) []byte {
	salt, nonce := randBytes(t, v1SaltSize), randBytes(t, v1NonceSize)
	aead, err := chacha20poly1305.NewX(argon2.IDKey([]byte(pass), salt, 1, 64*1024, 4, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	out := append(append([]byte{}, salt...), nonce...)
	for i := 0; i < len(plain); i += ChunkSize {
		end := min(i+ChunkSize, len(plain))
		out = aead.Seal(out, nonce, plain[i:end], nil)
		ctr := binary.LittleEndian.Uint64(nonce[16:])
		binary.LittleEndian.PutUint64(nonce[16:], ctr+1)
	}
	return out
}

func flip(c []byte, i int) []byte {
	b := append([]byte{}, c...)
	b[i] ^= 1
	return b
}

func swap(c []byte, off, size int) []byte {
	b := append([]byte{}, c...)
	copy(b[off:], c[off+size:off+2*size])
	copy(b[off+size:], c[off:off+size])
	return b
}
