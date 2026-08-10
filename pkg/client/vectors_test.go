package client

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"
)

// vectorsPath is shared with the Rust implementation, which pulls the same file
// in via include_str!. Regenerate with:
//
//	go test ./pkg/client -run TestCryptoVectors -update
const vectorsPath = "../../crypto_vectors.json"

var updateVectors = flag.Bool("update", false, "regenerate crypto_vectors.json")

type cryptoVectors struct {
	Note              string          `json:"note"`
	Argon2            argon2Params    `json:"argon2"`
	Text              []textVector    `json:"text"`
	File              []fileVector    `json:"file"`
	DisplayPassphrase []displayVector `json:"displayPassphrase"`
}

type argon2Params struct {
	MemoryKiB   uint32 `json:"memoryKiB"`
	TimeCost    uint32 `json:"timeCost"`
	Parallelism uint8  `json:"parallelism"`
	KeyLen      int    `json:"keyLen"`
}

type textVector struct {
	Name         string `json:"name"`
	Passphrase   string `json:"passphrase"`
	Salt         string `json:"salt"`
	Nonce        string `json:"nonce"`
	Header       string `json:"header"`
	Plaintext    string `json:"plaintext"`
	Ciphertext   string `json:"ciphertext"`
	PasswordHash string `json:"passwordHash"`
}

type fileVector struct {
	Name              string `json:"name"`
	Passphrase        string `json:"passphrase"`
	Salt              string `json:"salt"`
	Nonce             string `json:"nonce"`
	Header            string `json:"header"`
	FileData          string `json:"fileData"`
	EncryptedFile     string `json:"encryptedFile"`
	MetaNonce         string `json:"metaNonce"`
	FileName          string `json:"fileName"`
	FileType          string `json:"fileType"`
	MetadataJSON      string `json:"metadataJson"`
	EncryptedMetadata string `json:"encryptedMetadata"`
	PasswordHash      string `json:"passwordHash"`
}

type displayVector struct {
	Display    string `json:"display"`
	Salt       string `json:"salt"`
	Passphrase string `json:"passphrase"`
}

// Fixed inputs. Changing any of these changes the expected outputs, so treat
// the generated file as the contract between the Go, Rust, and JS paths.
var (
	textInputs = []textVector{
		{
			Name:       "ascii",
			Passphrase: "correct-horse-battery-staple-1234",
			Salt:       b64(repeatByte(0x11, SaltSize)),
			Nonce:      b64(counterBytes(NonceSize, 0)),
			Header:     b64(counterBytes(HeaderSize, 100)),
			Plaintext:  "the eagle has landed",
		},
		{
			Name:       "empty plaintext",
			Passphrase: "a",
			Salt:       b64(repeatByte(0x00, SaltSize)),
			Nonce:      b64(repeatByte(0xFF, NonceSize)),
			Header:     b64(repeatByte(0x7F, HeaderSize)),
			Plaintext:  "",
		},
		{
			Name:       "unicode plaintext",
			Passphrase: "pässwörd-with-ünïcode-😀-padding",
			Salt:       b64(counterBytes(SaltSize, 200)),
			Nonce:      b64(counterBytes(NonceSize, 50)),
			Header:     b64(counterBytes(HeaderSize, 7)),
			Plaintext:  "héllo, wörld 😀 — ünïcode",
		},
	}

	fileInputs = []fileVector{
		{
			Name:       "binary file with metadata",
			Passphrase: "file-vector-passphrase-0123456789",
			Salt:       b64(repeatByte(0x22, SaltSize)),
			Nonce:      b64(counterBytes(NonceSize, 10)),
			Header:     b64(counterBytes(HeaderSize, 20)),
			FileData:   b64(counterBytes(512, 0)),
			MetaNonce:  b64(counterBytes(NonceSize, 30)),
			FileName:   "notes.bin",
			FileType:   "application/octet-stream",
		},
	}

	displayInputs = []displayVector{
		{Salt: b64(repeatByte(0x33, SaltSize)), Passphrase: "0123456789abcdefghijklmnopqrstuv"},
		{Salt: b64(counterBytes(SaltSize, 240)), Passphrase: "!#$%&*+-=?@_~aBcDeFgHiJkLmNoPqRs"},
	}
)

func TestCryptoVectors(t *testing.T) {
	if *updateVectors {
		writeVectors(t)
	}

	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	var vectors cryptoVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	if vectors.Argon2 != (argon2Params{MemoryKiB: argon2Memory, TimeCost: argon2Time, Parallelism: argon2Threads, KeyLen: KeySize}) {
		t.Fatalf("vector Argon2 parameters do not match this implementation: %+v", vectors.Argon2)
	}

	for _, v := range vectors.Text {
		t.Run("text/"+v.Name, func(t *testing.T) {
			salt := decode(t, v.Salt)
			nonce := decode(t, v.Nonce)
			header := decode(t, v.Header)

			encKey, authKey := deriveKeys(v.Passphrase, salt)

			if got := hex.EncodeToString(authKey); got != v.PasswordHash {
				t.Errorf("passwordHash = %s, want %s", got, v.PasswordHash)
			}

			ct, err := xchachaSeal(encKey, nonce, header, []byte(v.Plaintext))
			if err != nil {
				t.Fatalf("seal: %v", err)
			}
			if got := b64(ct); got != v.Ciphertext {
				t.Errorf("ciphertext = %s, want %s", got, v.Ciphertext)
			}

			// The public decrypt path must read the pinned ciphertext.
			display := v.Salt + v.Passphrase
			text, err := DecryptText(&DecryptResponse{
				EncryptedData: v.Ciphertext,
				Nonce:         v.Nonce,
				Header:        v.Header,
			}, display)
			if err != nil {
				t.Fatalf("DecryptText: %v", err)
			}
			if text != v.Plaintext {
				t.Errorf("plaintext = %q, want %q", text, v.Plaintext)
			}
		})
	}

	for _, v := range vectors.File {
		t.Run("file/"+v.Name, func(t *testing.T) {
			salt := decode(t, v.Salt)
			encKey, authKey := deriveKeys(v.Passphrase, salt)

			if got := hex.EncodeToString(authKey); got != v.PasswordHash {
				t.Errorf("passwordHash = %s, want %s", got, v.PasswordHash)
			}

			encFile, err := xchachaSeal(encKey, decode(t, v.Nonce), decode(t, v.Header), decode(t, v.FileData))
			if err != nil {
				t.Fatalf("seal file: %v", err)
			}
			if got := b64(encFile); got != v.EncryptedFile {
				t.Errorf("encryptedFile = %s, want %s", got, v.EncryptedFile)
			}

			metaJSON, err := metadataJSON(v.FileName, v.FileType)
			if err != nil {
				t.Fatalf("marshal metadata: %v", err)
			}
			if string(metaJSON) != v.MetadataJSON {
				t.Errorf("metadata JSON = %s, want %s", metaJSON, v.MetadataJSON)
			}

			blob, err := metadataBlob(encKey, decode(t, v.MetaNonce), decode(t, v.Header), metaJSON)
			if err != nil {
				t.Fatalf("seal metadata: %v", err)
			}
			if got := b64(blob); got != v.EncryptedMetadata {
				t.Errorf("encryptedMetadata = %s, want %s", got, v.EncryptedMetadata)
			}

			file, err := DecryptFile(&DecryptResponse{
				EncryptedMetadata: v.EncryptedMetadata,
				Nonce:             v.Nonce,
				Header:            v.Header,
				IsFile:            true,
				EncryptedFile:     decode(t, v.EncryptedFile),
			}, v.Salt+v.Passphrase)
			if err != nil {
				t.Fatalf("DecryptFile: %v", err)
			}
			if file.Name != v.FileName || file.ContentType != v.FileType {
				t.Errorf("metadata = %q/%q, want %q/%q", file.Name, file.ContentType, v.FileName, v.FileType)
			}
			if !bytes.Equal(file.Data, decode(t, v.FileData)) {
				t.Error("decrypted file bytes do not match the vector")
			}
		})
	}

	for _, v := range vectors.DisplayPassphrase {
		salt, passphrase, err := splitDisplayPassphrase(v.Display)
		if err != nil {
			t.Fatalf("splitDisplayPassphrase(%q): %v", v.Display, err)
		}
		if b64(salt) != v.Salt {
			t.Errorf("split salt = %s, want %s", b64(salt), v.Salt)
		}
		if passphrase != v.Passphrase {
			t.Errorf("split passphrase = %q, want %q", passphrase, v.Passphrase)
		}
	}
}

func writeVectors(t *testing.T) {
	t.Helper()

	vectors := cryptoVectors{
		Note: "Known-answer vectors shared by the Go SDK and the Rust WASM module. " +
			"Regenerate with: go test ./pkg/client -run TestCryptoVectors -update",
		Argon2: argon2Params{MemoryKiB: argon2Memory, TimeCost: argon2Time, Parallelism: argon2Threads, KeyLen: KeySize},
	}

	for _, v := range textInputs {
		salt := decode(t, v.Salt)
		encKey, authKey := deriveKeys(v.Passphrase, salt)
		ct, err := xchachaSeal(encKey, decode(t, v.Nonce), decode(t, v.Header), []byte(v.Plaintext))
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		v.Ciphertext = b64(ct)
		v.PasswordHash = hex.EncodeToString(authKey)
		vectors.Text = append(vectors.Text, v)
	}

	for _, v := range fileInputs {
		salt := decode(t, v.Salt)
		encKey, authKey := deriveKeys(v.Passphrase, salt)

		encFile, err := xchachaSeal(encKey, decode(t, v.Nonce), decode(t, v.Header), decode(t, v.FileData))
		if err != nil {
			t.Fatalf("seal file: %v", err)
		}
		metaJSON, err := metadataJSON(v.FileName, v.FileType)
		if err != nil {
			t.Fatalf("marshal metadata: %v", err)
		}
		blob, err := metadataBlob(encKey, decode(t, v.MetaNonce), decode(t, v.Header), metaJSON)
		if err != nil {
			t.Fatalf("seal metadata: %v", err)
		}

		v.EncryptedFile = b64(encFile)
		v.MetadataJSON = string(metaJSON)
		v.EncryptedMetadata = b64(blob)
		v.PasswordHash = hex.EncodeToString(authKey)
		vectors.File = append(vectors.File, v)
	}

	for _, v := range displayInputs {
		v.Display = v.Salt + v.Passphrase
		vectors.DisplayPassphrase = append(vectors.DisplayPassphrase, v)
	}

	out, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}
	if err := os.WriteFile(vectorsPath, append(out, '\n'), 0644); err != nil {
		t.Fatalf("write vectors: %v", err)
	}
	t.Logf("regenerated %s", vectorsPath)
}

func metadataBlob(encKey, metaNonce, header, metaJSON []byte) ([]byte, error) {
	ct, err := xchachaSeal(encKey, metaNonce, header, metaJSON)
	if err != nil {
		return nil, err
	}
	return append(append([]byte{}, metaNonce...), ct...), nil
}

func b64(b []byte) string { return base64.URLEncoding.EncodeToString(b) }

func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return b
}

func repeatByte(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

func counterBytes(n, start int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte((start + i) % 256)
	}
	return out
}
