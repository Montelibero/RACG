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

	wantPaths := []string{
		"/healthz",
		"/openapi.json",
		"/v1/info",
		"/v1/session/open",
		"/v1/session/me",
		"/v1/requests",
		"/v1/requests/{request_id}",
		"/v1/requests/{request_id}/decision",
		"/v1/requests/{request_id}/kill",
		"/v1/requests/{request_id}/logs/live",
		"/v1/requests/{request_id}/logs/stdout",
		"/v1/requests/{request_id}/logs/stderr",
		"/v1/events",
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
	for _, name := range []string{"CreateRequestRequest", "Op", "CmdRunPayload"} {
		if _, ok := schemas[name]; !ok {
			t.Fatalf("missing schema %q", name)
		}
	}
}
