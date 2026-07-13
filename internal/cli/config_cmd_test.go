package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCLIConfigSetCreatesConfSetRequestAndWaits(t *testing.T) {
	var posted struct {
		Op struct {
			Type    string `json:"type"`
			Payload struct {
				Path      string `json:"path"`
				Format    string `json:"format"`
				Key       string `json:"key"`
				Value     string `json:"value"`
				ValueType string `json:"value_type"`
				Backup    bool   `json:"backup"`
				Create    bool   `json:"create"`
			} `json:"payload"`
		} `json:"op"`
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Fatalf("Authorization=%q", got)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/requests":
			if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
				t.Fatalf("decode post: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"request_id":"req1","status":"PENDING_APPROVAL"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/requests/req1":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"request_id":"req1","status":"SUCCEEDED","result":{"exit_code":0,"stdout":"path: config.yaml\nkey: image.tag\n","stderr":""}}`))
		default:
			t.Fatalf("%s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRoot(&out, &errOut)
	code := root.Run([]string{"config", "set", "config.yaml", "image.tag", "v1.2.3", "--format", "yaml", "--type", "string", "--create", "--host", ts.URL, "--token", "tok"})
	if code != 0 {
		t.Fatalf("code=%d stderr=%s stdout=%s", code, errOut.String(), out.String())
	}

	if posted.Op.Type != "conf.set" {
		t.Fatalf("op.type=%q", posted.Op.Type)
	}
	p := posted.Op.Payload
	if p.Path != "config.yaml" || p.Format != "yaml" || p.Key != "image.tag" || p.Value != "v1.2.3" || p.ValueType != "string" || !p.Backup || !p.Create {
		t.Fatalf("payload=%+v", p)
	}
	for _, want := range []string{"request_id: req1", "status: SUCCEEDED", "stdout:", "path: config.yaml"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("stdout missing %q:\n%s", want, out.String())
		}
	}
}

func TestCLIConfigUsageDocumentsCreate(t *testing.T) {
	got := configUsage()
	for _, want := range []string{"--create", "mode 0600", "--type json"} {
		if !strings.Contains(got, want) {
			t.Fatalf("config usage missing %q:\n%s", want, got)
		}
	}
}
