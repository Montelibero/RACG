package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type FileCmd struct {
	stdout io.Writer
	stderr io.Writer
}

func NewFileCmd(stdout, stderr io.Writer) *FileCmd {
	return &FileCmd{stdout: stdout, stderr: stderr}
}

func (c *FileCmd) Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, fileUsage())
		return 2
	}
	switch args[0] {
	case "read":
		return c.runRead(args[1:])
	case "patch":
		return c.runPatch(args[1:])
	case "upload":
		return c.runUpload(args[1:])
	case "download":
		return c.runDownload(args[1:])
	default:
		fmt.Fprintln(c.stderr, fileUsage())
		return 2
	}
}

func (c *FileCmd) runUpload(args []string) int {
	fs := flag.NewFlagSet("racg file upload", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	mode := fs.String("mode", "", "octal permissions; existing target mode is preserved when omitted")
	host := fs.String("host", strings.TrimSpace(os.Getenv("RACG_HOST")), "RACG server URL")
	token := fs.String("token", strings.TrimSpace(os.Getenv("RACG_TOKEN")), "session bearer token")
	name := fs.String("name", strings.TrimSpace(os.Getenv("RACG_CLIENT_NAME")), "client profile name")
	noWait := fs.Bool("no-wait", false, "create request and print request id without waiting")
	pollInterval := fs.Duration("poll-interval", 500*time.Millisecond, "poll interval while waiting")
	waitTimeout := fs.Duration("wait-timeout", 0, "maximum time to wait for terminal status")
	if err := fs.Parse(interspersedFileArgs(args)); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 2 {
		fmt.Fprintln(c.stderr, "usage: racg file upload <local-path> <remote-path> [--mode 0644]")
		return 2
	}
	if *mode != "" {
		if _, err := parseCLIFileMode(*mode); err != nil {
			fmt.Fprintln(c.stderr, err)
			return 2
		}
	}
	f, err := os.Open(rest[0])
	if err != nil {
		fmt.Fprintf(c.stderr, "open upload source failed: %v\n", err)
		return 1
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		fmt.Fprintln(c.stderr, "upload source must be a regular file")
		return 1
	}

	resolvedHost, resolvedToken, err := resolveClientAuthNamed(*host, *token, *name)
	if err != nil {
		fmt.Fprintln(c.stderr, err)
		return 2
	}
	client, err := newRACGClient(resolvedHost, resolvedToken)
	if err != nil {
		fmt.Fprintln(c.stderr, err)
		return 2
	}
	staged, err := client.stageUpload(f)
	if err != nil {
		fmt.Fprintf(c.stderr, "file upload staging failed: %v\n", err)
		return 1
	}
	payload := map[string]any{
		"path": rest[1], "upload_id": staged.UploadID,
		"size": staged.Size, "sha256": staged.SHA256,
	}
	if *mode != "" {
		payload["mode"] = *mode
	}
	created, err := client.createRequest(map[string]any{"op": map[string]any{"type": "fs.upload", "payload": payload}})
	if err != nil {
		fmt.Fprintf(c.stderr, "file upload request failed: %v\n", err)
		return 1
	}
	if *noWait {
		fmt.Fprintf(c.stdout, "request_id: %s\nstatus: %s\n", created.RequestID, created.Status)
		return 0
	}
	rec, err := client.waitRequest(created.RequestID, *pollInterval, *waitTimeout)
	if err != nil {
		fmt.Fprintf(c.stderr, "file upload wait failed: %v\n", err)
		return 1
	}
	printRequestResult(c.stdout, rec)
	if rec.Status == "SUCCEEDED" && rec.Result != nil {
		return normalizeExitCode(rec.Result.ExitCode)
	}
	return 1
}

func (c *FileCmd) runDownload(args []string) int {
	fs := flag.NewFlagSet("racg file download", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	force := fs.Bool("force", false, "replace an existing local file")
	host := fs.String("host", strings.TrimSpace(os.Getenv("RACG_HOST")), "RACG server URL")
	token := fs.String("token", strings.TrimSpace(os.Getenv("RACG_TOKEN")), "session bearer token")
	name := fs.String("name", strings.TrimSpace(os.Getenv("RACG_CLIENT_NAME")), "client profile name")
	pollInterval := fs.Duration("poll-interval", 500*time.Millisecond, "poll interval while waiting")
	waitTimeout := fs.Duration("wait-timeout", 0, "maximum time to wait for terminal status")
	if err := fs.Parse(interspersedFileArgs(args)); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 2 {
		fmt.Fprintln(c.stderr, "usage: racg file download <remote-path> <local-path> [--force]")
		return 2
	}
	if _, err := os.Stat(rest[1]); err == nil && !*force {
		fmt.Fprintf(c.stderr, "local destination already exists: %s; pass --force to replace it\n", rest[1])
		return 1
	} else if err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(c.stderr, "inspect local destination failed: %v\n", err)
		return 1
	}

	resolvedHost, resolvedToken, err := resolveClientAuthNamed(*host, *token, *name)
	if err != nil {
		fmt.Fprintln(c.stderr, err)
		return 2
	}
	client, err := newRACGClient(resolvedHost, resolvedToken)
	if err != nil {
		fmt.Fprintln(c.stderr, err)
		return 2
	}
	created, err := client.createRequest(map[string]any{
		"op": map[string]any{"type": "fs.download", "payload": map[string]any{"path": rest[0]}},
	})
	if err != nil {
		fmt.Fprintf(c.stderr, "file download request failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.stdout, "request_id: %s\n", created.RequestID)
	fmt.Fprintf(c.stdout, "status: %s\n", created.Status)
	rec, err := client.waitRequest(created.RequestID, *pollInterval, *waitTimeout)
	if err != nil {
		fmt.Fprintf(c.stderr, "file download wait failed: %v\n", err)
		return 1
	}
	if rec.Status != "SUCCEEDED" || rec.Result == nil || rec.Result.ExitCode != 0 {
		printRequestResult(c.stdout, rec)
		return 1
	}
	meta, err := client.downloadRequestFile(created.RequestID, rest[1], *force)
	if err != nil {
		fmt.Fprintf(c.stderr, "file download failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.stdout, "status: SUCCEEDED\nlocal_path: %s\nsize: %d\nsha256: %s\n", rest[1], meta.Size, meta.SHA256)
	return 0
}

type stagedUploadResponse struct {
	UploadID string `json:"upload_id"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}

type downloadedFile struct {
	Size   int64
	SHA256 string
}

func (c *racgClient) stageUpload(r io.Reader) (stagedUploadResponse, error) {
	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/v1/uploads", r)
	if err != nil {
		return stagedUploadResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/octet-stream")
	client := *c.http
	client.Timeout = 0
	resp, err := client.Do(req)
	if err != nil {
		return stagedUploadResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return stagedUploadResponse{}, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out stagedUploadResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return stagedUploadResponse{}, err
	}
	if out.UploadID == "" || out.SHA256 == "" {
		return stagedUploadResponse{}, fmt.Errorf("server response missing upload metadata")
	}
	return out, nil
}

func (c *racgClient) downloadRequestFile(requestID, destination string, replace bool) (downloadedFile, error) {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+"/v1/requests/"+requestID+"/file", nil)
	if err != nil {
		return downloadedFile{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	client := *c.http
	client.Timeout = 0
	resp, err := client.Do(req)
	if err != nil {
		return downloadedFile{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return downloadedFile{}, fmt.Errorf("http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	wantHash := strings.TrimSpace(resp.Header.Get("X-RACG-SHA256"))
	if len(wantHash) != sha256.Size*2 {
		return downloadedFile{}, errors.New("server response missing valid X-RACG-SHA256")
	}
	mode := os.FileMode(0o644)
	if value := strings.TrimSpace(resp.Header.Get("X-RACG-Mode")); value != "" {
		mode, err = parseCLIFileMode(value)
		if err != nil {
			return downloadedFile{}, err
		}
	}
	dir := filepath.Dir(destination)
	tmp, err := os.CreateTemp(dir, ".racg-download-*")
	if err != nil {
		return downloadedFile{}, err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return downloadedFile{}, err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(tmp, h), resp.Body)
	if copyErr == nil {
		copyErr = tmp.Sync()
	}
	if closeErr := tmp.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		return downloadedFile{}, copyErr
	}
	gotHash := hex.EncodeToString(h.Sum(nil))
	if gotHash != wantHash {
		return downloadedFile{}, fmt.Errorf("download checksum mismatch: got %s want %s", gotHash, wantHash)
	}
	if replace {
		if err := os.Rename(tmpPath, destination); err != nil {
			return downloadedFile{}, err
		}
	} else {
		if err := os.Link(tmpPath, destination); err != nil {
			return downloadedFile{}, fmt.Errorf("create local destination without replacing it: %w", err)
		}
		if err := os.Remove(tmpPath); err != nil {
			return downloadedFile{}, err
		}
	}
	return downloadedFile{Size: n, SHA256: gotHash}, nil
}

func parseCLIFileMode(value string) (os.FileMode, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(value), 8, 9)
	if err != nil || n > 0o777 {
		return 0, fmt.Errorf("invalid file mode %q; use octal permissions such as 0644", value)
	}
	return os.FileMode(n), nil
}

func (c *FileCmd) runRead(args []string) int {
	fs := flag.NewFlagSet("racg file read", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	maxBytes := fs.Int("max-bytes", 0, "maximum bytes to read")
	plain := fs.Bool("plain", false, "print file content without line numbers")
	unredacted := fs.Bool("unredacted", false, "print file content without automatic secret redaction")
	host := fs.String("host", strings.TrimSpace(os.Getenv("RACG_HOST")), "RACG server URL")
	token := fs.String("token", strings.TrimSpace(os.Getenv("RACG_TOKEN")), "session bearer token")
	name := fs.String("name", strings.TrimSpace(os.Getenv("RACG_CLIENT_NAME")), "client profile name")
	noWait := fs.Bool("no-wait", false, "create request and print request id without waiting")
	pollInterval := fs.Duration("poll-interval", 500*time.Millisecond, "poll interval while waiting")
	waitTimeout := fs.Duration("wait-timeout", 0, "maximum time to wait for terminal status")
	if err := fs.Parse(interspersedFileArgs(args)); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(c.stderr, "usage: racg file read <path> [--max-bytes N] [--plain] [--unredacted]")
		return 2
	}

	payload := map[string]any{"path": rest[0]}
	if *maxBytes > 0 {
		payload["max_bytes"] = *maxBytes
	}
	return c.submitFileRequest(*host, *token, *name, *noWait, *pollInterval, *waitTimeout, "fs.read", payload, *unredacted, !*plain)
}

func (c *FileCmd) runPatch(args []string) int {
	fs := flag.NewFlagSet("racg file patch", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	diff := fs.String("diff", "", "unified diff text")
	diffFile := fs.String("diff-file", "", "path to a unified diff file")
	host := fs.String("host", strings.TrimSpace(os.Getenv("RACG_HOST")), "RACG server URL")
	token := fs.String("token", strings.TrimSpace(os.Getenv("RACG_TOKEN")), "session bearer token")
	name := fs.String("name", strings.TrimSpace(os.Getenv("RACG_CLIENT_NAME")), "client profile name")
	noWait := fs.Bool("no-wait", false, "create request and print request id without waiting")
	pollInterval := fs.Duration("poll-interval", 500*time.Millisecond, "poll interval while waiting")
	waitTimeout := fs.Duration("wait-timeout", 0, "maximum time to wait for terminal status")
	if err := fs.Parse(interspersedFileArgs(args)); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(c.stderr, "usage: racg file patch <path> (--diff TEXT | --diff-file PATH)")
		return 2
	}
	diffText := *diff
	if strings.TrimSpace(*diffFile) != "" {
		b, err := os.ReadFile(strings.TrimSpace(*diffFile))
		if err != nil {
			fmt.Fprintf(c.stderr, "read diff file failed: %v\n", err)
			return 1
		}
		diffText = string(b)
	}
	if diffText == "" {
		fmt.Fprintln(c.stderr, "diff is required; pass --diff or --diff-file")
		return 2
	}

	payload := map[string]any{"path": rest[0], "diff": diffText}
	return c.submitFileRequest(*host, *token, *name, *noWait, *pollInterval, *waitTimeout, "fs.patch_unified", payload, false, false)
}

func (c *FileCmd) submitFileRequest(host, token, name string, noWait bool, pollInterval, waitTimeout time.Duration, opType string, payload map[string]any, unredacted, numberStdout bool) int {
	resolvedHost, resolvedToken, err := resolveClientAuthNamed(host, token, name)
	if err != nil {
		fmt.Fprintf(c.stderr, "%v\n", err)
		return 2
	}
	client, err := newRACGClient(resolvedHost, resolvedToken)
	if err != nil {
		fmt.Fprintf(c.stderr, "%v\n", err)
		return 2
	}
	client.unredacted = unredacted
	created, err := client.createRequest(map[string]any{
		"op": map[string]any{
			"type":    opType,
			"payload": payload,
		},
	})
	if err != nil {
		fmt.Fprintf(c.stderr, "file request failed: %v\n", err)
		return 1
	}
	if noWait {
		fmt.Fprintf(c.stdout, "request_id: %s\nstatus: %s\n", created.RequestID, created.Status)
		return 0
	}
	rec, err := client.waitRequest(created.RequestID, pollInterval, waitTimeout)
	if err != nil {
		fmt.Fprintf(c.stderr, "file request wait failed: %v\n", err)
		return 1
	}
	rec = filterRequestOutput(rec, unredacted)
	if numberStdout && rec.Result != nil {
		result := *rec.Result
		result.Stdout = numberOutputLines(result.Stdout)
		rec.Result = &result
	}
	printRequestResult(c.stdout, rec)
	if rec.Status == "SUCCEEDED" && rec.Result != nil {
		return normalizeExitCode(rec.Result.ExitCode)
	}
	return 1
}

func interspersedFileArgs(args []string) []string {
	valueFlags := map[string]bool{
		"--max-bytes":     true,
		"--diff":          true,
		"--diff-file":     true,
		"--host":          true,
		"--token":         true,
		"--name":          true,
		"--poll-interval": true,
		"--wait-timeout":  true,
		"--mode":          true,
	}
	boolFlags := map[string]bool{
		"--no-wait":    true,
		"--force":      true,
		"--plain":      true,
		"--unredacted": true,
	}
	var flags []string
	var positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "--") {
			if eq := strings.IndexByte(arg, '='); eq > 0 {
				name := arg[:eq]
				if valueFlags[name] || boolFlags[name] {
					flags = append(flags, arg)
					continue
				}
			}
			if valueFlags[arg] && i+1 < len(args) {
				flags = append(flags, arg, args[i+1])
				i++
				continue
			}
			if boolFlags[arg] {
				flags = append(flags, arg)
				continue
			}
		}
		positional = append(positional, arg)
	}
	return append(flags, positional...)
}

func fileUsage() string {
	return `usage: racg file <read|patch|upload|download> [args]

Read plain text or arbitrary files through RACG approval:
  racg file read <path>
  racg file read <path> --max-bytes 65536
  racg file read <path> --plain --unredacted

Patch plain text files through RACG approval with a unified diff:
  racg file patch <path> --diff-file /tmp/change.patch
  racg file patch <path> --diff '@@ -1 +1 @@...'

Transfer binary or large files without putting their content in JSON:
  racg file upload <local-path> <remote-path> [--mode 0644]
  racg file download <remote-path> <local-path> [--force]

Underlying operations:
  read     -> fs.read
  patch    -> fs.patch_unified
  upload   -> fs.upload
  download -> fs.download

Common flags:
  --host URL
  --token TOKEN
  --no-wait
  --poll-interval 500ms
  --wait-timeout 30s
`
}
