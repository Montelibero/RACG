package service

import (
	"context"
	"sync"

	"github.com/itolstov/racg/internal/approval"
	"github.com/itolstov/racg/internal/authority"
)

// executionSupervisor exposes the authority broker protocol while keeping
// execution dispatch inside the privileged process. It is not an execution API.
type executionSupervisor struct {
	*authority.Authority
	options authority.OperationExecutionOptions
	workers sync.WaitGroup
}

func newExecutionSupervisor(authority *authority.Authority, options authority.OperationExecutionOptions) *executionSupervisor {
	return &executionSupervisor{Authority: authority, options: options}
}

// SubmitDecision first durably consumes the signed decision. Only after that
// commit does it dispatch ALLOW_ONCE work on a shutdown-tracked worker.
func (s *executionSupervisor) SubmitDecision(ctx context.Context, requestID string, decision approval.SignedDecision, challenge []byte) (approval.SignedDecisionReceipt, error) {
	receipt, err := s.Authority.SubmitDecision(ctx, requestID, decision, challenge)
	if err != nil {
		return receipt, err
	}
	if decision.Decision.Action != "ALLOW_ONCE" {
		return receipt, nil
	}
	// A graceful authority shutdown waits for bounded terminal work instead of
	// manufacturing an uncertain outcome. Crashes still become UNCERTAIN and
	// are never rerun.
	detached := context.WithoutCancel(ctx)
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		_, _ = s.Authority.ExecuteStored(detached, requestID, s.options)
	}()
	return receipt, nil
}

func (s *executionSupervisor) Close() error {
	s.workers.Wait()
	return nil
}
