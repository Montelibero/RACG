package executor

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUploadFilePublishesOnlyVerifiedContent(t *testing.T) {
	for _, tc := range []struct {
		name, mode           string
		wrongHash, wrongSize bool
	}{
		{name: "preserve permissions"}, {name: "override permissions", mode: "0600"},
		{name: "checksum mismatch", wrongHash: true}, {name: "size mismatch", wrongSize: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "target")
			if err := os.WriteFile(path, []byte("original"), 0o640); err != nil {
				t.Fatal(err)
			}
			data := []byte{0, 1, 255, '\n'}
			sum := sha256.Sum256(data)
			spec := UploadSpec{Path: path, Mode: tc.mode, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
			if tc.wrongHash {
				spec.SHA256 = strings.Repeat("0", 64)
			}
			if tc.wrongSize {
				spec.Size++
			}
			res := UploadFile(spec, bytes.NewReader(data))
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wrongHash || tc.wrongSize {
				if res.Status != "FAILED" || res.Stderr != "staged upload checksum mismatch" || string(got) != "original" {
					t.Fatalf("result=%+v file=%q", res, got)
				}
			} else {
				if res.Status != "SUCCEEDED" || !bytes.Equal(got, data) {
					t.Fatalf("result=%+v file=%q", res, got)
				}
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				want := os.FileMode(0o640)
				if tc.mode != "" {
					want = 0o600
				}
				if info.Mode().Perm() != want {
					t.Fatalf("mode=%o", info.Mode().Perm())
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatalf("temporary files leaked: %v %v", entries, err)
			}
		})
	}
}

func TestDownloadFileCreatesIndependentSnapshot(t *testing.T) {
	dir := t.TempDir()
	source, target := filepath.Join(dir, "source"), filepath.Join(dir, "artifacts", "snapshot")
	data := []byte{0, 255, '\n', 'a'}
	if err := os.WriteFile(source, data, 0o640); err != nil {
		t.Fatal(err)
	}
	meta, res := DownloadFile(source, target, int64(len(data)))
	if res.Status != "SUCCEEDED" {
		t.Fatalf("result=%+v", res)
	}
	sum := sha256.Sum256(data)
	if meta.Size != int64(len(data)) || meta.SHA256 != hex.EncodeToString(sum[:]) || meta.Mode != "0640" || meta.Name != "source" {
		t.Fatalf("meta=%+v", meta)
	}
	if err := os.WriteFile(source, []byte("changed"), 0o640); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("snapshot=%q err=%v", got, err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode=%o", info.Mode().Perm())
	}
}

func TestDownloadFileRejectsOversizeAndDirectory(t *testing.T) {
	for _, directory := range []bool{false, true} {
		dir := t.TempDir()
		source, target := filepath.Join(dir, "source"), filepath.Join(dir, "snapshot")
		if directory {
			if err := os.Mkdir(source, 0o700); err != nil {
				t.Fatal(err)
			}
		} else if err := os.WriteFile(source, []byte("too long"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, res := DownloadFile(source, target, 2)
		if res.Status != "FAILED" {
			t.Fatalf("result=%+v", res)
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatalf("unexpected snapshot: %v", err)
		}
	}
}
