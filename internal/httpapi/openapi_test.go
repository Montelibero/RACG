package httpapi

import (
	"encoding/json"
	"testing"
)

func TestOpenAPIDocumentCoversCoreEndpoints(t *testing.T) {
	b, err := openapiFS.ReadFile("openapi.json")
	if err != nil {
		t.Fatalf("read openapi.json: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	paths, _ := doc["paths"].(map[string]any)
	if paths == nil {
		t.Fatalf("missing paths")
	}

	decision := paths["/v1/requests/{request_id}/decision"].(map[string]any)["post"].(map[string]any)
	responses := decision["responses"].(map[string]any)
	if decision["deprecated"] != true || responses["403"] == nil || responses["200"] != nil {
		t.Fatalf("legacy decision endpoint must be documented as disabled: %v", decision)
	}

	wantPaths := []string{
		"/healthz",
		"/openapi.json",
		"/v1/info",
		"/v1/session/open",
		"/v1/session/me",
		"/v1/uploads",
		"/v1/requests",
		"/v1/requests/{request_id}",
		"/v1/requests/{request_id}/decision",
		"/v1/requests/{request_id}/kill",
		"/v1/requests/{request_id}/logs/live",
		"/v1/requests/{request_id}/logs/stdout",
		"/v1/requests/{request_id}/logs/stderr",
		"/v1/requests/{request_id}/file",
		"/v1/events",
		"/v1/approver/challenge",
		"/v1/approver/pairing",
		"/v1/approver/requests",
		"/v1/approver/requests/{request_id}",
		"/v1/approver/requests/{request_id}/scope",
		"/v1/approver/decision",
		"/v1/approver/sessions",
		"/v1/approver/sessions/extend",
		"/v1/approver/sessions/revoke",
		"/v1/approver/devices",
		"/v1/approver/devices/revoke",
		"/v1/approver/pairing-code",
		"/v1/approver/events",
		"/v1/admin/approver/enrollment",
		"/v1/admin/pairing-code",
	}
	for _, p := range wantPaths {
		if _, ok := paths[p]; !ok {
			t.Fatalf("missing path %q", p)
		}
	}

	components, _ := doc["components"].(map[string]any)
	if components == nil {
		t.Fatalf("missing components")
	}
	secSchemes, _ := components["securitySchemes"].(map[string]any)
	if secSchemes == nil {
		t.Fatalf("missing components.securitySchemes")
	}
	if _, ok := secSchemes["bearerAuth"]; !ok {
		t.Fatalf("missing components.securitySchemes.bearerAuth")
	}

	schemas, _ := components["schemas"].(map[string]any)
	if schemas == nil {
		t.Fatalf("missing components.schemas")
	}
	for _, name := range []string{"CreateRequestRequest", "Op", "CmdRunPayload", "FsUploadPayload", "FsDownloadPayload", "StagedUploadResponse"} {
		if _, ok := schemas[name]; !ok {
			t.Fatalf("missing schema %q", name)
		}
	}
	cmdRun, _ := schemas["CmdRunPayload"].(map[string]any)
	properties, _ := cmdRun["properties"].(map[string]any)
	for _, name := range []string{"stdin_upload_id", "stdin_size", "stdin_sha256"} {
		if _, ok := properties[name]; !ok {
			t.Fatalf("CmdRunPayload missing property %q", name)
		}
	}
}
