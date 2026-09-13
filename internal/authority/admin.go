package authority

import (
	"context"
	"crypto/ed25519"

	"github.com/itolstov/racg/internal/approval"
)

// TrustedCredential is an administrative registry view. Public keys are
// enrolled bytes and never bearer credentials.
type TrustedCredential struct {
	ID        string `json:"id"`
	PublicKey []byte `json:"public_key"`
	Revoked   bool   `json:"revoked"`
}

func (a *Authority) ListDevicesTrusted(ctx context.Context) ([]TrustedCredential, error) {
	return listCredentials(ctx, a, "SELECT device_id,public_key,revoked FROM authority_devices ORDER BY device_id")
}

func (a *Authority) ListAgentsTrusted(ctx context.Context) ([]TrustedCredential, error) {
	return listCredentials(ctx, a, "SELECT client_id,public_key,revoked FROM authority_agents ORDER BY client_id")
}

// IdentityTrusted returns the authority identity over the local trusted admin
// boundary. Public-key disclosure is intentional; the signing key is not.
func (a *Authority) IdentityTrusted() (int, string, []byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	public := a.key.Public().(ed25519.PublicKey)
	return approval.Version, a.serverID, append([]byte(nil), public...), nil
}

// RotateDeviceTrusted is an explicit re-enrollment of one device identity.
// Pending signatures from the old key fail; already-consumed state does not
// change and running executions are not affected.
func (a *Authority) RotateDeviceTrusted(ctx context.Context, deviceID string, key ed25519.PublicKey) error {
	return a.EnrollTrusted(ctx, deviceID, key)
}

// RotateAgentTrusted follows the same permanent credential rotation model.
func (a *Authority) RotateAgentTrusted(ctx context.Context, clientID string, key ed25519.PublicKey) error {
	return a.EnrollAgentTrusted(ctx, clientID, key)
}

func listCredentials(ctx context.Context, a *Authority, query string) ([]TrustedCredential, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	rows, err := a.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	credentials := []TrustedCredential{}
	for rows.Next() {
		var credential TrustedCredential
		if err := rows.Scan(&credential.ID, &credential.PublicKey, &credential.Revoked); err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}
	return credentials, rows.Err()
}
