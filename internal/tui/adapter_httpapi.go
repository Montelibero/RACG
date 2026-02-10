package tui

import "github.com/itolstov/racg/internal/httpapi"

type httpAPIApprover struct {
	api *httpapi.API
}

func NewHTTPAPIApprover(api *httpapi.API) Approver {
	return &httpAPIApprover{api: api}
}

func (a *httpAPIApprover) ListPending() ([]Request, error) {
	pending := a.api.ListPendingForTUI()
	out := make([]Request, 0, len(pending))
	for _, r := range pending {
		out = append(out, Request{ID: r.ID, Summary: r.Summary})
	}
	return out, nil
}

func (a *httpAPIApprover) Decide(id string, decision Decision) error {
	return a.api.DecideForTUI(id, string(decision))
}
