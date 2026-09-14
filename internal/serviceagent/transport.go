package serviceagent

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/itolstov/racg/internal/approval"
	"github.com/itolstov/racg/internal/broker"
)

type Connection struct {
	Client *broker.AuthorityClient
}

func (c Connection) validate() error {
	if c.Client == nil {
		return errors.New("service protocol connection required")
	}
	return nil
}

func (c Connection) StageUpload(ctx context.Context, signed approval.SignedStagedUpload, data []byte) (approval.StagedUpload, error) {
	return c.Client.StageUpload(ctx, broker.UploadSubmission{Upload: signed, Data: append([]byte(nil), data...)})
}

type Submission struct {
	Request approval.SignedRequest
	Nonce   []byte
}

type Result struct {
	Request   approval.SignedRequest
	Status    string
	Execution *ExecutionResult
	Download  *DownloadArtifact
}

type ExecutionResult = approval.ExecutionResult

type DownloadArtifact = approval.DownloadArtifact

type Transport struct {
	Connection Connection
	Profile    Profile
	Key        *Key
	Now        func() time.Time
}

func (t Transport) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t Transport) validate() error {
	if err := t.Connection.validate(); err != nil {
		return err
	}
	if t.Key == nil || t.Key.ClientID == "" || len(t.Key.Private) != ed25519.PrivateKeySize {
		return errors.New("valid unlocked service agent key required")
	}
	if t.Profile.ServerID == "" || len(t.Profile.PublicKey) != ed25519.PublicKeySize {
		return errors.New("valid pinned server profile required")
	}
	return nil
}

// Submit sends the signed operation and verifies the returned frozen request
// against the SSH-pinned server key. Submission does not imply approval.
func (t Transport) Submit(ctx context.Context, operation []byte, validUntil time.Time) (Submission, error) {
	if err := t.validate(); err != nil {
		return Submission{}, err
	}
	if !json.Valid(operation) {
		return Submission{}, errors.New("operation must contain valid JSON")
	}
	submission, err := approval.NewSubmission(t.Profile.ServerID, t.Key.ClientID, operation, validUntil)
	if err != nil {
		return Submission{}, err
	}
	signed, err := approval.SignSubmission(submission, t.Key.Private)
	if err != nil {
		return Submission{}, err
	}
	request, err := t.Connection.Client.SubmitAgent(ctx, signed)
	if err != nil {
		return Submission{}, err
	}
	if err := approval.VerifyRequest(request, t.Profile.ServerID, t.Profile.PublicKey); err != nil {
		return Submission{}, err
	}
	if request.Request.ClientID != t.Key.ClientID {
		return Submission{}, errors.New("authority returned another agent's request")
	}
	return Submission{Request: request, Nonce: submission.Nonce}, nil
}

// StageUpload stores agent-authenticated immutable bytes. It does not authorize
// use against any target; the operation must later reference the upload ID.
func (t Transport) StageUpload(ctx context.Context, data []byte, validUntil time.Time) (approval.StagedUpload, error) {
	if err := t.validate(); err != nil {
		return approval.StagedUpload{}, err
	}
	upload, err := approval.NewStagedUpload(t.Profile.ServerID, t.Key.ClientID, data, validUntil)
	if err != nil {
		return approval.StagedUpload{}, err
	}
	private, err := t.Key.privateCopy()
	if err != nil {
		return approval.StagedUpload{}, err
	}
	signed, err := approval.SignStagedUpload(upload, private)
	if err != nil {
		return approval.StagedUpload{}, err
	}
	clearBytes(private)
	stored, err := t.Connection.StageUpload(ctx, signed, append([]byte(nil), data...))
	if err != nil {
		return approval.StagedUpload{}, err
	}
	if stored.UploadID != upload.UploadID || stored.Size != upload.Size || stored.SHA256 != upload.SHA256 {
		return approval.StagedUpload{}, errors.New("authority returned mismatched staged upload")
	}
	return stored, nil
}

func clearBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// Wait polls authenticated lookup snapshots until a terminal status. It never
// resubmits the original operation after a delivery deadline.
func (t Transport) Wait(ctx context.Context, nonce []byte, deadline time.Time) (Result, error) {
	if err := t.validate(); err != nil {
		return Result{}, err
	}
	if len(nonce) != 32 {
		return Result{}, errors.New("submission nonce required")
	}
	for {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		now := t.now()
		if !deadline.IsZero() && now.After(deadline) {
			return Result{}, errors.New("service result deadline expired")
		}
		lookupValidUntil := now.Add(time.Minute)
		if !deadline.IsZero() && deadline.Before(lookupValidUntil) {
			lookupValidUntil = deadline
		}
		lookup, err := approval.NewLookup(t.Profile.ServerID, t.Key.ClientID, nonce, lookupValidUntil)
		if err != nil {
			return Result{}, err
		}
		signedLookup, err := approval.SignLookup(lookup, t.Key.Private)
		if err != nil {
			return Result{}, err
		}
		response, err := t.Connection.Client.LookupSubmission(ctx, signedLookup)
		if err != nil {
			return Result{}, err
		}
		if err := approval.VerifyLookupResult(lookup, response, t.Profile.PublicKey, now); err != nil {
			return Result{}, err
		}
		if !response.Result.Found {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		switch response.Result.Status {
		case "SUCCEEDED", "FAILED", "KILLED", "TIMED_OUT", "DENIED", "UNCERTAIN":
			return Result{
				Request:   *response.Result.Request,
				Status:    response.Result.Status,
				Execution: response.Result.Result,
				Download:  response.Result.Download,
			}, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
}
