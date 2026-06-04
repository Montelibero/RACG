package httpapi

import "testing"

func TestListJobsForTUI(t *testing.T) {
	api := &API{reqs: map[string]requestRecord{
		"r1": {ID: "r1", Status: "RUNNING", CreatedAt: "2026-02-11T01:00:00Z"},
		"r2": {ID: "r2", Status: "APPROVED", CreatedAt: "2026-02-11T01:01:00Z"},
		"r3": {ID: "r3", Status: "SUCCEEDED", CreatedAt: "2026-02-11T01:02:00Z"},
		"r4": {ID: "r4", Status: "FAILED", CreatedAt: "2026-02-11T01:03:00Z"},
		"r5": {ID: "r5", Status: "DENIED", CreatedAt: "2026-02-11T01:04:00Z"},
		"r6": {ID: "r6", Status: "CANCELED", CreatedAt: "2026-02-11T01:05:00Z"},
	}}

	runningOnly := api.ListJobsForTUI(false)
	if len(runningOnly) != 2 {
		t.Fatalf("runningOnly len=%d, want 2", len(runningOnly))
	}
	if runningOnly[0].ID != "r2" || runningOnly[1].ID != "r1" {
		t.Fatalf("runningOnly ids=%v,%v", runningOnly[0].ID, runningOnly[1].ID)
	}

	all := api.ListJobsForTUI(true)
	if len(all) != 5 {
		t.Fatalf("all len=%d, want 5", len(all))
	}
	if all[0].ID != "r6" || all[1].ID != "r4" || all[2].ID != "r3" || all[3].ID != "r2" || all[4].ID != "r1" {
		t.Fatalf("unexpected order/ids: %#v", all)
	}
}
