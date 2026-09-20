package cli

import (
	"context"
	"os"
	"path/filepath"

	"github.com/itolstov/racg/internal/approvalbridge"
	"github.com/itolstov/racg/internal/httpapi"
)

func (c *ServeCmd) runPhoneBridge(ctx context.Context, api *httpapi.API, phoneBridge string) error {
	if err := os.MkdirAll(filepath.Dir(phoneBridge), 0o750); err != nil {
		return err
	}
	backend := approvalbridge.NewServer(api, approvalbridge.NewDeviceRegistry(phoneBridge+".devices.json"))
	return approvalbridge.Serve(ctx, phoneBridge, backend)
}
