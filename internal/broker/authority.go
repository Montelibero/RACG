package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/itolstov/racg/internal/approval"
)

// Authority is the complete authority surface available to a broker. The
// absent methods are the security boundary: execution, enrollment, revocation
// and signing never cross this interface.
type Authority interface {
	Submit(context.Context, approval.SignedSubmission) (approval.SignedRequest, error)
	LookupSubmission(context.Context, approval.SignedLookup) (approval.SignedLookupResult, error)
	StageUpload(context.Context, approval.SignedStagedUpload, []byte) (approval.StagedUpload, error)
	SubmitDecision(context.Context, string, approval.SignedDecision, []byte) (approval.SignedDecisionReceipt, error)
	LookupDecision(context.Context, approval.SignedDecisionLookup) (approval.SignedDecisionLookupResult, error)
	ListPending(context.Context, approval.SignedRequestList) (approval.SignedRequestListResult, error)
	CancelSubmission(context.Context, approval.SignedCancellation) (approval.SignedCancellationResult, error)
	EnrollDevice(context.Context, approval.DeviceEnrollmentSubmission) (approval.SignedDeviceEnrollmentReceipt, error)
}

// ServeAuthority reads sequential JSON protocol values from in and writes one
// response for each request to out. The transport can be an in-memory pipe now
// or a permission-restricted Unix socket later.
func ServeAuthority(ctx context.Context, authority Authority, in io.Reader, out io.Writer) error {
	if authority == nil {
		return errors.New("authority required")
	}
	if in == nil || out == nil {
		return errors.New("authority connection required")
	}
	decoder := json.NewDecoder(in)
	encoder := json.NewEncoder(out)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var request Request
		err := decoder.Decode(&request)
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		if err != nil {
			_ = encoder.Encode(Response{Version: ProtocolVersion, Error: "decode request"})
			return fmt.Errorf("decode authority request: %w", err)
		}
		result, responseErr := handleAuthorityRequest(ctx, authority, request)
		response := Response{Version: ProtocolVersion, ID: request.ID}
		if responseErr != nil {
			response.Error = responseErr.Error()
		} else {
			encoded, encodeErr := json.Marshal(result)
			if encodeErr != nil {
				response.Error = "encode result"
			} else {
				response.Result = encoded
			}
		}
		if err := encoder.Encode(response); err != nil {
			return fmt.Errorf("encode authority response: %w", err)
		}
	}
}

func handleAuthorityRequest(ctx context.Context, authority Authority, request Request) (any, error) {
	if request.Version != ProtocolVersion {
		return nil, errors.New("unsupported authority protocol version")
	}
	switch request.Method {
	case MethodSubmitAgent:
		var params approval.SignedSubmission
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return authority.Submit(ctx, params)
	case MethodLookupSubmission:
		var params approval.SignedLookup
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return authority.LookupSubmission(ctx, params)
	case MethodStageUpload:
		var params UploadSubmission
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return authority.StageUpload(ctx, params.Upload, params.Data)
	case MethodSubmitDecision:
		var params DecisionSubmission
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return authority.SubmitDecision(ctx, params.RequestID, params.Decision, params.Challenge)
	case MethodLookupDecision:
		var params approval.SignedDecisionLookup
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return authority.LookupDecision(ctx, params)
	case MethodListPending:
		var params approval.SignedRequestList
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return authority.ListPending(ctx, params)
	case MethodCancelSubmission:
		var params approval.SignedCancellation
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return authority.CancelSubmission(ctx, params)
	case MethodEnrollDevice:
		var params approval.DeviceEnrollmentSubmission
		if err := decodeParams(request.Params, &params); err != nil {
			return nil, err
		}
		return authority.EnrollDevice(ctx, params)
	default:
		return nil, errors.New("unknown authority method")
	}
}

func decodeParams(data []byte, target any) error {
	if len(data) == 0 {
		return errors.New("missing request parameters")
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode request parameters: %w", err)
	}
	return nil
}
