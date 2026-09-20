package cli

import (
	"context"
	"os"
	"path/filepath"

	"github.com/itolstov/racg/internal/approvalbridge"
	"github.com/itolstov/racg/internal/httpapi"
)

func (c *ServeCmd) runPhoneBridge(ctx context.Context, api *httpapi.API) error {
	if err := os.MkdirAll(filepath.Dir(c.phoneBridge), 0o750); err != nil {
		return err
	}
	backend := approvalbridge.NewServer(api, approvalbridge.NewDeviceRegistry(c.phoneBridge+".devices.json"))
	return approvalbridge.Serve(ctx, c.phoneBridge, backend)
}
