package cli

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/itolstov/racg/internal/version"
)

var (
	updateGitHubAPIBaseURL      = "https://api.github.com"
	updateGitHubDownloadBaseURL = "https://github.com"
	updateExecCommandContext    = exec.CommandContext
)

type UpdateCmd struct {
	stdout io.Writer
	stderr io.Writer
}

func NewUpdateCmd(stdout, stderr io.Writer) *UpdateCmd {
	return &UpdateCmd{stdout: stdout, stderr: stderr}
}

func (c *UpdateCmd) Run(args []string) int {
	fs := flag.NewFlagSet("racg update", flag.ContinueOnError)
	fs.SetOutput(c.stderr)

	checkOnly := fs.Bool("check", false, "check latest release without installing")
	repo := fs.String("repo", envOrDefault("RACG_REPO", "Montelibero/RACG"), "GitHub repository owner/name")
	explicitVersion := fs.String("version", "", "release version or tag to install")
	target := fs.String("target", "", "target binary path; defaults to current executable")
	useSudo := fs.Bool("sudo", false, "install with sudo")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(c.stderr, "usage: racg update [--check] [--version vX.Y.Z] [--target PATH] [--sudo]")
		return 2
	}

	opts := updateOptions{
		Repo:            strings.TrimSpace(*repo),
		ExplicitVersion: strings.TrimSpace(*explicitVersion),
		Target:          strings.TrimSpace(*target),
		UseSudo:         *useSudo,
		CheckOnly:       *checkOnly,
	}
	if opts.Repo == "" {
		fmt.Fprintln(c.stderr, "repo is required")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	info, err := resolveUpdate(ctx, opts)
	if err != nil {
		fmt.Fprintf(c.stderr, "update failed: %v\n", err)
		return 1
	}
	if opts.CheckOnly {
		fmt.Fprintf(c.stdout, "current_version: %s\nlatest_version: %s\nupdate_available: %t\nrepo: %s\n", version.Version, strings.TrimPrefix(info.Tag, "v"), version.Compare(strings.TrimPrefix(info.Tag, "v"), version.Version) > 0, opts.Repo)
		return 0
	}
	if version.Compare(strings.TrimPrefix(info.Tag, "v"), version.Version) == 0 && opts.ExplicitVersion == "" {
		fmt.Fprintf(c.stdout, "updated=false\ncurrent_version: %s\nlatest_version: %s\n", version.Version, strings.TrimPrefix(info.Tag, "v"))
		return 0
	}

	if err := installUpdate(ctx, info, opts); err != nil {
		fmt.Fprintf(c.stderr, "update failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.stdout, "updated=true\nversion: %s\ntarget: %s\n", strings.TrimPrefix(info.Tag, "v"), info.Target)
	fmt.Fprintln(c.stdout, "restart racg serve to use the new version")
	return 0
}

type updateOptions struct {
	Repo            string
	ExplicitVersion string
	Target          string
	UseSudo         bool
	CheckOnly       bool
}

type updateInfo struct {
	Tag       string
	AssetName string
	Target    string
}

func resolveUpdate(ctx context.Context, opts updateOptions) (updateInfo, error) {
	if runtime.GOOS != "linux" {
		return updateInfo{}, fmt.Errorf("unsupported OS %s; update currently supports linux only", runtime.GOOS)
	}
	arch := runtime.GOARCH
	switch arch {
	case "amd64", "arm64":
	default:
		return updateInfo{}, fmt.Errorf("unsupported architecture %s", arch)
	}

	tag := opts.ExplicitVersion
	if tag == "" {
		resolved, err := fetchLatestReleaseTag(ctx, opts.Repo)
		if err != nil {
			return updateInfo{}, err
		}
		tag = resolved
	}
	if tag == "" {
		return updateInfo{}, errors.New("release tag is empty")
	}
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}

	target := opts.Target
	if target == "" {
		exe, err := os.Executable()
		if err != nil {
			return updateInfo{}, fmt.Errorf("resolve current executable: %w", err)
		}
		target = exe
	}
	versionNoV := strings.TrimPrefix(tag, "v")
	return updateInfo{
		Tag:       tag,
		AssetName: fmt.Sprintf("racg_%s_%s_%s.tar.gz", versionNoV, runtime.GOOS, arch),
		Target:    target,
	}, nil
}

func installUpdate(ctx context.Context, info updateInfo, opts updateOptions) error {
	tmpDir, err := os.MkdirTemp("", "racg-update-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	archivePath := filepath.Join(tmpDir, info.AssetName)
	sumPath := filepath.Join(tmpDir, "checksums.txt")
	if err := downloadFile(ctx, updateReleaseURL(opts.Repo, info.Tag, info.AssetName), archivePath); err != nil {
		return err
	}
	if err := downloadFile(ctx, updateReleaseURL(opts.Repo, info.Tag, "checksums.txt"), sumPath); err != nil {
		return err
	}
	if err := verifyChecksum(archivePath, sumPath, info.AssetName); err != nil {
		return err
	}

	binaryPath := filepath.Join(tmpDir, "racg")
	if err := extractRACGBinary(archivePath, binaryPath); err != nil {
		return err
	}
	if opts.UseSudo {
		return installWithSudo(ctx, binaryPath, info.Target)
	}
	if err := installWithoutSudo(binaryPath, info.Target); err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("%w; retry with --sudo or run install manually", err)
		}
		return err
	}
	return nil
}

func fetchLatestReleaseTag(ctx context.Context, repo string) (string, error) {
	url := strings.TrimRight(updateGitHubAPIBaseURL, "/") + "/repos/" + strings.Trim(repo, "/") + "/releases/latest"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("latest release http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if out.TagName == "" {
		return "", errors.New("latest release response missing tag_name")
	}
	return out.TagName, nil
}

func updateReleaseURL(repo, tag, asset string) string {
	return strings.TrimRight(updateGitHubDownloadBaseURL, "/") + "/" + strings.Trim(repo, "/") + "/releases/download/" + tag + "/" + asset
}

func downloadFile(ctx context.Context, url string, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("download %s failed: http %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func verifyChecksum(archivePath, checksumsPath, assetName string) error {
	want, err := checksumForAsset(checksumsPath, assetName)
	if err != nil {
		return err
	}
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("checksum mismatch for %s", assetName)
	}
	return nil
}

func checksumForAsset(checksumsPath, assetName string) (string, error) {
	b, err := os.ReadFile(checksumsPath)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if filepath.Base(fields[len(fields)-1]) == assetName {
			if len(fields[0]) != sha256.Size*2 {
				return "", fmt.Errorf("invalid checksum for %s", assetName)
			}
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("checksums.txt missing %s", assetName)
}

func extractRACGBinary(archivePath, outPath string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if filepath.Base(h.Name) != "racg" || h.Typeflag != tar.TypeReg {
			continue
		}
		out, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, tr)
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}
	return errors.New("archive does not contain racg binary")
}

func installWithoutSudo(binaryPath, target string) error {
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".racg-update-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	src, err := os.Open(binaryPath)
	if err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := io.Copy(tmp, src); err != nil {
		_ = src.Close()
		_ = tmp.Close()
		return err
	}
	if err := src.Close(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, target)
}

func installWithSudo(ctx context.Context, binaryPath, target string) error {
	cmd := updateExecCommandContext(ctx, "sudo", "install", "-m", "0755", binaryPath, target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sudo install failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
