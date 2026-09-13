package authority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/itolstov/racg/internal/approval"
	"github.com/itolstov/racg/internal/rules"
)

// GrantScope binds one canonical interactive matcher rule to one enrolled
// service agent. It deliberately includes the agent: a grant is not authority
// for every client that shares a broker, host or network location.
type GrantScope struct {
	Version  int        `json:"version"`
	ClientID string     `json:"client_id"`
	Rule     rules.Rule `json:"rule"`
}

type storedGrant struct {
	ID        string
	DeviceID  string
	ClientID  string
	Rule      rules.Rule
	ExpiresAt *time.Time
	Permanent bool
}

// TrustedGrant is an administrative registry view of a reusable authorization.
type TrustedGrant struct {
	ID        string     `json:"id"`
	DeviceID  string     `json:"device_id"`
	ClientID  string     `json:"client_id"`
	Rule      rules.Rule `json:"rule"`
	ExpiresAt string     `json:"expires_at,omitempty"`
	Permanent bool       `json:"permanent"`
	Revoked   bool       `json:"revoked"`
}

func (a *Authority) ListGrantsTrusted(ctx context.Context) ([]TrustedGrant, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	rows, err := a.db.QueryContext(ctx,
		"SELECT grant_id,device_id,client_id,rule,expires_at,revoked FROM authority_grants ORDER BY created_at,grant_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	grants := []TrustedGrant{}
	for rows.Next() {
		var grant TrustedGrant
		var ruleBytes []byte
		var expires sql.NullString
		var revoked int
		if err := rows.Scan(&grant.ID, &grant.DeviceID, &grant.ClientID, &ruleBytes, &expires, &revoked); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(ruleBytes, &grant.Rule); err != nil {
			return nil, err
		}
		if expires.Valid {
			grant.ExpiresAt = expires.String
		} else {
			grant.Permanent = true
		}
		grant.Revoked = revoked != 0
		grants = append(grants, grant)
	}
	return grants, rows.Err()
}

func (a *Authority) RevokeGrantTrusted(ctx context.Context, grantID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	result, err := a.db.ExecContext(ctx, "UPDATE authority_grants SET revoked=1 WHERE grant_id=?", grantID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func parseGrantScope(request approval.Request, decision approval.SignedDecision, now time.Time) (GrantScope, rules.Rule, *time.Time, error) {
	if decision.Decision.Grant == nil {
		return GrantScope{}, rules.Rule{}, nil, errors.New("reusable decision missing grant")
	}
	var scope GrantScope
	decoder := json.NewDecoder(bytes.NewReader(decision.Decision.Grant.Scope))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&scope); err != nil {
		return GrantScope{}, rules.Rule{}, nil, fmt.Errorf("decode grant scope: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return GrantScope{}, rules.Rule{}, nil, errors.New("trailing grant scope data")
		}
		return GrantScope{}, rules.Rule{}, nil, err
	}
	if scope.Version != approval.Version || scope.ClientID == "" {
		return GrantScope{}, rules.Rule{}, nil, errors.New("invalid grant scope identity")
	}
	if scope.ClientID != request.ClientID {
		return GrantScope{}, rules.Rule{}, nil, errors.New("grant scope agent mismatch")
	}
	rule, err := canonicalGrantRule(scope.Rule)
	if err != nil {
		return GrantScope{}, rules.Rule{}, nil, err
	}
	var expires *time.Time
	switch decision.Decision.Action {
	case "ALLOW_UNTIL":
		parsed, err := time.Parse(time.RFC3339Nano, decision.Decision.Grant.ExpiresAt)
		if err != nil {
			return GrantScope{}, rules.Rule{}, nil, fmt.Errorf("parse grant expiry: %w", err)
		}
		expires = &parsed
		if !now.Before(parsed) {
			return GrantScope{}, rules.Rule{}, nil, errors.New("grant already expired")
		}
	case "ALLOW_ALWAYS":
		if decision.Decision.Grant.ExpiresAt != "" {
			return GrantScope{}, rules.Rule{}, nil, errors.New("permanent grant must not have expiry")
		}
	default:
		return GrantScope{}, rules.Rule{}, nil, fmt.Errorf("unsupported reusable action %q", decision.Decision.Action)
	}
	return scope, rule, expires, nil
}

func canonicalGrantRule(rule rules.Rule) (rules.Rule, error) {
	if rule.ID == "" {
		rule.ID = uuid.NewString()
	}
	if rule.OpType == "" {
		return rules.Rule{}, errors.New("grant operation type required")
	}
	switch rule.OpType {
	case "cmd.run":
		if rule.Path != nil || rule.Cmd == nil || len(rule.Cmd.ArgvPrefix) == 0 {
			return rules.Rule{}, errors.New("cmd.run grant requires argv scope")
		}
		for _, arg := range rule.Cmd.ArgvPrefix {
			if arg == "" {
				return rules.Rule{}, errors.New("grant argv segments must not be empty")
			}
		}
	case "fs.read", "fs.patch_unified", "fs.upload", "fs.download", "conf.set":
		if rule.Cmd != nil || rule.Path == nil {
			return rules.Rule{}, errors.New("path grant requires one path scope")
		}
		fields := 0
		for _, value := range []string{rule.Path.Exact, rule.Path.Prefix, rule.Path.Glob} {
			if value != "" {
				fields++
			}
		}
		if fields != 1 {
			return rules.Rule{}, errors.New("path grant requires exactly one of exact, prefix or glob")
		}
	default:
		return rules.Rule{}, fmt.Errorf("unsupported grant operation type %q", rule.OpType)
	}
	return rule, nil
}

func canonicalGrantScope(scope GrantScope, rule rules.Rule) ([]byte, error) {
	scope.Rule = rule
	scope.Version = approval.Version
	return json.Marshal(scope)
}

func (a *Authority) createGrantTx(ctx context.Context, tx *sql.Tx, deviceID string, request approval.Request, decision approval.SignedDecision) (string, error) {
	now := a.now().UTC()
	scope, rule, expires, err := parseGrantScope(request, decision, now)
	if err != nil {
		return "", err
	}
	scope.ClientID = request.ClientID
	canonical, err := canonicalGrantScope(scope, rule)
	if err != nil {
		return "", err
	}
	ruleBytes, err := json.Marshal(rule)
	if err != nil {
		return "", err
	}
	grantID := grantFingerprint(deviceID, canonical, decision.Signature)
	var expiresValue any
	expiresText := ""
	if expires != nil {
		expiresText = expires.UTC().Format(time.RFC3339Nano)
		expiresValue = expiresText
	}
	_, err = tx.ExecContext(ctx,
		"INSERT INTO authority_grants(grant_id,device_id,client_id,canonical_scope,rule,expires_at,revoked,created_at) VALUES(?,?,?,?,?,?,0,?)",
		grantID, decision.Decision.DeviceID, scope.ClientID, canonical, ruleBytes, expiresValue, now.Format(time.RFC3339Nano))
	if err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO authority_grant_requests(request_id,grant_id) VALUES(?,?)", request.RequestID, grantID); err != nil {
		return "", err
	}
	return grantID, nil
}

func grantFingerprint(deviceID string, scope, decisionSignature []byte) string {
	hash := sha256.New()
	fmt.Fprintf(hash, "RACG/grant/v1\x00%s\x00", deviceID)
	hash.Write(scope)
	hash.Write([]byte{0})
	hash.Write(decisionSignature)
	return hex.EncodeToString(hash.Sum(nil))
}

func (a *Authority) activeGrantForOperation(tx *sql.Tx, clientID string, operation []byte) (storedGrant, error) {
	now := a.now().UTC().Format(time.RFC3339Nano)
	rows, err := tx.QueryContext(context.Background(),
		`SELECT g.grant_id,g.device_id,g.client_id,g.rule,g.expires_at
		   FROM authority_grants g
		   JOIN authority_devices d ON d.device_id=g.device_id
		  WHERE g.client_id=? AND g.revoked=0 AND d.revoked=0
		    AND (g.expires_at IS NULL OR g.expires_at>?)
		  ORDER BY COALESCE(g.expires_at,'9999-12-31T23:59:59.999999999Z')`, clientID, now)
	if err != nil {
		return storedGrant{}, err
	}
	defer rows.Close()
	var op rules.Op
	if err := json.Unmarshal(operation, &op); err != nil {
		return storedGrant{}, err
	}
	for rows.Next() {
		grant := storedGrant{ClientID: clientID}
		var ruleBytes []byte
		var expires sql.NullString
		if err := rows.Scan(&grant.ID, &grant.DeviceID, &grant.ClientID, &ruleBytes, &expires); err != nil {
			return storedGrant{}, err
		}
		if err := json.Unmarshal(ruleBytes, &grant.Rule); err != nil {
			return storedGrant{}, err
		}
		if expires.Valid {
			parsed, err := time.Parse(time.RFC3339Nano, expires.String)
			if err != nil {
				return storedGrant{}, err
			}
			grant.ExpiresAt = &parsed
		} else {
			grant.Permanent = true
		}
		engine := rules.NewEngine()
		engine.AddAlways(grant.Rule)
		if _, ok := engine.Match("", op); ok {
			return grant, nil
		}
	}
	if err := rows.Err(); err != nil {
		return storedGrant{}, err
	}
	return storedGrant{}, sql.ErrNoRows
}

func (a *Authority) grantForExecution(ctx context.Context, tx *sql.Tx, requestID, clientID string, now time.Time) (storedGrant, error) {
	var grant storedGrant
	var ruleBytes []byte
	var expires sql.NullString
	var revoked int
	err := tx.QueryRowContext(ctx,
		`SELECT g.grant_id,g.device_id,g.client_id,g.rule,g.expires_at,d.revoked
		   FROM authority_grant_requests r
		   JOIN authority_grants g ON g.grant_id=r.grant_id
		   JOIN authority_devices d ON d.device_id=g.device_id
		  WHERE r.request_id=? AND g.client_id=? AND g.revoked=0`,
		requestID, clientID).Scan(&grant.ID, &grant.DeviceID, &grant.ClientID, &ruleBytes, &expires, &revoked)
	if err != nil {
		return storedGrant{}, fmt.Errorf("grant authorization unavailable: %w", err)
	}
	if revoked != 0 {
		return storedGrant{}, errors.New("approver device revoked before dispatch")
	}
	if err := json.Unmarshal(ruleBytes, &grant.Rule); err != nil {
		return storedGrant{}, err
	}
	if expires.Valid {
		parsed, err := time.Parse(time.RFC3339Nano, expires.String)
		if err != nil {
			return storedGrant{}, err
		}
		grant.ExpiresAt = &parsed
		if !now.Before(parsed) {
			return storedGrant{}, errors.New("grant expired before dispatch")
		}
	} else {
		grant.Permanent = true
	}
	return grant, nil
}
