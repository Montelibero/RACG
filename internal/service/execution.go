package service

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/itolstov/racg/internal/approval"
	"github.com/itolstov/racg/internal/authority"
)

// executionSupervisor exposes the authority broker protocol while keeping
// execution dispatch inside the privileged process. It is not an execution API.
type executionSupervisor struct {
	*authority.Authority
	options    authority.OperationExecutionOptions
	workers    sync.WaitGroup
	dispatched sync.Map
	lastError  atomic.Value
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
	if decision.Decision.Action == "DENY" {
		return receipt, nil
	}
	s.dispatch(ctx, requestID)
	return receipt, nil
}

// Submit checks whether authority-side durable grants auto-authorized the
// newly frozen request before returning it to the broker.
func (s *executionSupervisor) Submit(ctx context.Context, signed approval.SignedSubmission) (approval.SignedRequest, error) {
	request, err := s.Authority.Submit(ctx, signed)
	if err != nil {
		return request, err
	}
	_, status, statusErr := s.Authority.Request(ctx, request.Request.RequestID)
	if statusErr != nil {
		return request, statusErr
	}
	if status == "AUTHORIZED" {
		s.dispatch(ctx, request.Request.RequestID)
	}
	return request, nil
}

func (s *executionSupervisor) dispatch(ctx context.Context, requestID string) {
	if _, loaded := s.dispatched.LoadOrStore(requestID, struct{}{}); loaded {
		return
	}
	// A graceful authority shutdown waits for bounded terminal work instead of
	// manufacturing an uncertain outcome. Crashes still become UNCERTAIN and
	// are never rerun.
	detached := context.WithoutCancel(ctx)
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		if _, err := s.Authority.ExecuteStored(detached, requestID, s.options); err != nil {
			s.lastError.Store(err)
		}
	}()
}

func (s *executionSupervisor) executionError() error {
	if err := s.lastError.Load(); err != nil {
		return err.(error)
	}
	return nil
}

func (s *executionSupervisor) Close() error {
	s.workers.Wait()
	return nil
}
