package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCLIUpdateCheckReportsLatestRelease(t *testing.T) {
	withUpdateTestServer(t, "v9.8.7", []byte("new-binary"), func(ts *httptest.Server, _ string) {
		var out bytes.Buffer
		var errOut bytes.Buffer
		root := NewRoot(&out, &errOut)

		code := root.Run([]string{"update", "--check", "--repo", "owner/repo"})
		if code != 0 {
			t.Fatalf("code=%d stderr=%s stdout=%s", code, errOut.String(), out.String())
		}

		for _, want := range []string{
			"current_version: ",
			"latest_version: 9.8.7",
			"update_available: true",
			"repo: owner/repo",
		} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("stdout missing %q:\n%s", want, out.String())
			}
		}
	})
}

func TestCLIUpdateDownloadsVerifiesAndInstallsTarget(t *testing.T) {
	target := filepath.Join(t.TempDir(), "racg")
	if err := os.WriteFile(target, []byte("old-binary"), 0o755); err != nil {
		t.Fatalf("write target: %v", err)
	}

	withUpdateTestServer(t, "v9.8.7", []byte("new-binary"), func(ts *httptest.Server, _ string) {
		var out bytes.Buffer
		var errOut bytes.Buffer
		root := NewRoot(&out, &errOut)

		code := root.Run([]string{"update", "--repo", "owner/repo", "--target", target})
		if code != 0 {
			t.Fatalf("code=%d stderr=%s stdout=%s", code, errOut.String(), out.String())
		}

		got, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("read target: %v", err)
		}
		if string(got) != "new-binary" {
			t.Fatalf("target=%q", got)
		}
		for _, want := range []string{
			"updated=true",
			"version: 9.8.7",
			"target: " + target,
			"restart racg serve",
		} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("stdout missing %q:\n%s", want, out.String())
			}
		}
	})
}

func withUpdateTestServer(t *testing.T, tag string, binary []byte, fn func(*httptest.Server, string)) {
	t.Helper()

	archive := makeRACGArchive(t, binary)
	sum := sha256.Sum256(archive)
	versionNoV := strings.TrimPrefix(tag, "v")
	asset := fmt.Sprintf("racg_%s_%s_%s.tar.gz", versionNoV, runtime.GOOS, runtime.GOARCH)

	var ts *httptest.Server
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/releases/latest":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"tag_name":%q}`, tag)
		case "/owner/repo/releases/download/" + tag + "/" + asset:
			_, _ = w.Write(archive)
		case "/owner/repo/releases/download/" + tag + "/checksums.txt":
			fmt.Fprintf(w, "%s  %s\n", hex.EncodeToString(sum[:]), asset)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	oldAPIBase := updateGitHubAPIBaseURL
	oldDownloadBase := updateGitHubDownloadBaseURL
	updateGitHubAPIBaseURL = ts.URL
	updateGitHubDownloadBaseURL = ts.URL
	defer func() {
		updateGitHubAPIBaseURL = oldAPIBase
		updateGitHubDownloadBaseURL = oldDownloadBase
	}()

	fn(ts, asset)
}

func makeRACGArchive(t *testing.T, binary []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "racg", Mode: 0o755, Size: int64(len(binary))}); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if _, err := tw.Write(binary); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}
