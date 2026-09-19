package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/itolstov/racg/internal/approval"
)

func runAppCommand(args []string, stdout, stderr io.Writer) (bool, int) {
	if len(args) == 0 || (args[0] != "keygen" && args[0] != "public-key") {
		return false, 0
	}
	command := args[0]
	fs := flag.NewFlagSet("racg-approver "+command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("key", "", "passphrase-encrypted device key")
	deviceID := fs.String("device-id", "", "device identity to enroll (keygen only)")
	passphrase := fs.String("passphrase", os.Getenv("RACG_DEVICE_PASSPHRASE"), "device key passphrase")
	if err := fs.Parse(args[1:]); err != nil {
		return true, 2
	}
	if *keyPath == "" {
		fmt.Fprintln(stderr, "key path required")
		return true, 2
	}
	if *passphrase == "" {
		fmt.Fprintln(stderr, "passphrase required")
		return true, 2
	}
	var key *DeviceKey
	var err error
	if command == "keygen" {
		key, err = newDeviceKey()
		if err == nil && *deviceID != "" {
			key.ID = *deviceID
		}
		if err == nil {
			err = saveDeviceKey(*keyPath, key.ID, key.Private, *passphrase)
		}
	} else {
		key, err = loadDeviceKey(*keyPath, *passphrase)
	}
	if err != nil {
		fmt.Fprintf(stderr, "%s failed: %v\n", command, err)
		return true, 1
	}
	fmt.Fprintf(stdout, "device_id=%s\npublic_key=%s\n", key.ID, key.publicKeyText())
	return true, 0
}

const helpText = `usage: racg-approver [--key path] [--server-profile path] [--request path]
                   [--connect URI] [--poll-interval duration]

Development preview of the separate Linux desktop approver.
It can create or unlock a passphrase-encrypted local signing key, inspect a
signed request, and create an offline Allow once or Deny envelope.
When --connect is supplied, it polls a broker/service protocol endpoint and can
send locally signed decisions. It never receives an authority signing key and
cannot execute operations. Without --connect, no network connection is made.
The existing racg serve and its local TUI do not require this application.

headless commands:
  keygen --key PATH --device-id ID [--passphrase VALUE | RACG_DEVICE_PASSPHRASE]
      create a mode-0600 encrypted device key and print its public key
  public-key --key PATH [--passphrase VALUE | RACG_DEVICE_PASSPHRASE]
      decrypt a local device key and print its identity and public key

--key             optional passphrase-encrypted Ed25519 signing key; created with
                  a passphrase and kept on this device, never sent anywhere
--server-profile  trusted JSON from SSH enrollment: server_id and public_key
                  (base64 Ed25519 public key); never trust a broker-provided key
--request         JSON signed request envelope exported from the authority
--connect         broker/service endpoint URI; examples:
                  unix:///run/racg/approver.sock and tcp://127.0.0.1:9443
--poll-interval   signed pending-list polling interval (default 5s)
--help            show this help without opening a window

Verify both files, unlock the signing key, then use Allow once or Deny. A valid
request signature authenticates content, not its safety or current pending
status. A created envelope is only a local file payload until a future service
connection sends it. The key unlock timer is independent from decision validity
and future grants; locking prevents new signatures but does not revoke an
envelope that has already been sent. Go cannot guarantee that every copy of key
material is erased from memory.

The Signing key Auto-lock field accepts an empty value (off) or a positive Go
duration such as 15m. Decision validity is required and uses the same duration
form. Offline envelopes remain in the Decision tab. Service decisions are sent
only after the operator selects a verified pending request and uses a service
action; the authority receipt is verified before the UI reports acceptance.
`

type options struct {
	key          string
	profile      string
	request      string
	connect      string
	pollInterval time.Duration
}

func parseOptions(args []string, out io.Writer) (options, error) {
	var o options
	fs := flag.NewFlagSet("racg-approver", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() { fmt.Fprint(out, helpText) }
	fs.StringVar(&o.key, "key", "", "passphrase-encrypted signing key")
	fs.StringVar(&o.profile, "server-profile", "", "trusted server profile")
	fs.StringVar(&o.request, "request", "", "signed request envelope")
	fs.StringVar(&o.connect, "connect", "", "broker/service endpoint URI")
	fs.DurationVar(&o.pollInterval, "poll-interval", 5*time.Second, "pending-list polling interval")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() != 0 {
		return o, fmt.Errorf("unexpected arguments")
	}
	return o, nil
}

type previewUI struct {
	keyPath           *widget.Entry
	passphrase        *widget.Entry
	confirmPassphrase *widget.Entry
	autoLock          *widget.Entry
	profilePath       *widget.Entry
	requestPath       *widget.Entry
	decisionValidity  *widget.Entry
	transportAddress  *widget.Entry
	pollInterval      *widget.Entry
	saveProfile       *widget.Button
	connect           *widget.Button
	disconnect        *widget.Button
	requestList       *widget.List
	inspectSelected   *widget.Button
	serviceAllow      *widget.Button
	serviceDeny       *widget.Button
	preview           *widget.Entry
	decision          *widget.Entry
	status            *widget.Label
	createKey         *widget.Button
	unlockKey         *widget.Button
	lockNow           *widget.Button
	verify            *widget.Button
	allow             *widget.Button
	deny              *widget.Button
	tabs              *container.AppTabs

	app             fyne.App
	profileValue    ServerProfile
	connection      Connection
	closeConnection func()
	transportCancel context.CancelFunc
	serviceRequests []approval.SignedRequest
	seenRequests    map[string]struct{}
	selectedIndex   int
	selectedRequest approval.SignedRequest
	transportActive bool
	disconnecting   bool
	key             *DeviceKey
	request         approval.Request
	lockTimer       *time.Timer
}

func newPreviewUI(o options, application fyne.App) *previewUI {
	u := &previewUI{app: application, seenRequests: map[string]struct{}{}}
	u.keyPath = widget.NewEntry()
	u.keyPath.SetPlaceHolder("Path to passphrase-encrypted signing key")
	u.keyPath.SetText(o.key)
	u.passphrase = widget.NewPasswordEntry()
	u.passphrase.SetPlaceHolder("Signing key passphrase")
	u.confirmPassphrase = widget.NewPasswordEntry()
	u.confirmPassphrase.SetPlaceHolder("Confirm passphrase (create only)")
	u.autoLock = widget.NewEntry()
	u.autoLock.SetPlaceHolder("Key auto-lock (empty = off; example 15m)")
	u.profilePath = widget.NewEntry()
	u.profilePath.SetPlaceHolder("Path to trusted server profile")
	u.profilePath.SetText(o.profile)
	u.requestPath = widget.NewEntry()
	u.requestPath.SetPlaceHolder("Path to signed request JSON")
	u.requestPath.SetText(o.request)
	u.decisionValidity = widget.NewEntry()
	u.decisionValidity.SetPlaceHolder("Offline decision validity (example 5m)")
	u.transportAddress = widget.NewEntry()
	u.transportAddress.SetPlaceHolder("Broker/service URI (unix:///path or tcp://host:port)")
	u.transportAddress.SetText(o.connect)
	u.pollInterval = widget.NewEntry()
	u.pollInterval.SetText(o.pollInterval.String())
	u.saveProfile = widget.NewButton("Save profile", u.saveProfileClicked)
	u.connect = widget.NewButton("Connect", u.connectClicked)
	u.disconnect = widget.NewButton("Disconnect", u.disconnectClicked)
	u.preview = widget.NewMultiLineEntry()
	u.preview.TextStyle = fyne.TextStyle{Monospace: true}
	u.preview.Wrapping = fyne.TextWrapOff
	u.preview.Disable()
	u.decision = widget.NewMultiLineEntry()
	u.decision.TextStyle = fyne.TextStyle{Monospace: true}
	u.decision.Wrapping = fyne.TextWrapWord
	u.decision.SetPlaceHolder("Offline signed decision envelope")
	u.decision.Disable()
	u.status = widget.NewLabel("Offline preview — signing key management only; no network or execution.")
	if o.connect != "" {
		u.status.SetText("Offline preview ready. Press Connect to poll the configured broker/service endpoint.")
	}
	u.status.Wrapping = fyne.TextWrapWord
	u.createKey = widget.NewButton("Create encrypted key", u.createKeyClicked)
	u.unlockKey = widget.NewButton("Unlock key", u.unlockKeyClicked)
	u.lockNow = widget.NewButton("Lock now", u.lockKey)
	u.verify = widget.NewButton("Verify and inspect", u.verifyClicked)
	u.allow = widget.NewButton("Allow once", func() { u.signClicked("ALLOW_ONCE") })
	u.deny = widget.NewButton("Deny", func() { u.signClicked("DENY") })
	u.updateSigningButtons()
	return u
}

func (u *previewUI) canvas() fyne.CanvasObject {
	keyForm := widget.NewForm(
		widget.NewFormItem("Signing key", u.keyPath),
		widget.NewFormItem("Passphrase", u.passphrase),
		widget.NewFormItem("Confirm", u.confirmPassphrase),
		widget.NewFormItem("Auto-lock", u.autoLock),
	)
	keyButtons := container.NewHBox(u.createKey, u.unlockKey, u.lockNow)
	requestForm := widget.NewForm(
		widget.NewFormItem("Trusted server profile", u.profilePath),
		widget.NewFormItem("Signed request", u.requestPath),
		widget.NewFormItem("Decision validity", u.decisionValidity),
	)
	requestButtons := container.NewHBox(u.verify, u.saveProfile, u.allow, u.deny)
	u.requestList = widget.NewList(
		func() int { return len(u.serviceRequests) },
		func() fyne.CanvasObject { return widget.NewLabel("template") },
		func(i int, object fyne.CanvasObject) {
			if i >= 0 && i < len(u.serviceRequests) {
				object.(*widget.Label).SetText(requestListText(u.serviceRequests[i]))
			}
		},
	)
	u.requestList.OnSelected = func(i int) {
		if i >= 0 && i < len(u.serviceRequests) {
			u.selectedIndex = i
			u.selectedRequest = u.serviceRequests[i]
		}
		u.updateServiceButtons()
	}
	u.inspectSelected = widget.NewButton("Inspect selected", u.inspectServiceRequest)
	u.serviceAllow = widget.NewButton("Send Allow once", func() { u.sendServiceDecision("ALLOW_ONCE") })
	u.serviceDeny = widget.NewButton("Send Deny", func() { u.sendServiceDecision("DENY") })
	u.updateServiceButtons()
	serviceButtons := container.NewHBox(u.inspectSelected, u.serviceAllow, u.serviceDeny)
	transportForm := widget.NewForm(
		widget.NewFormItem("Endpoint", u.transportAddress),
		widget.NewFormItem("Poll interval", u.pollInterval),
	)
	transportButtons := container.NewHBox(u.connect, u.disconnect)
	top := container.NewVBox(
		widget.NewLabelWithStyle("RACG Approver · offline signing preview", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		requestForm, requestButtons,
		transportForm, transportButtons,
		widget.NewLabelWithStyle("Signing key", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		keyForm, keyButtons,
		u.status,
	)
	u.tabs = container.NewAppTabs(
		container.NewTabItem("Request", u.preview),
		container.NewTabItem("Decision", u.decision),
		container.NewTabItem("Service", container.NewVBox(serviceButtons, u.requestList)),
	)
	return container.NewBorder(top, nil, nil, nil, u.tabs)
}

func buildContent(o options, application fyne.App) fyne.CanvasObject {
	return newPreviewUI(o, application).canvas()
}

func (u *previewUI) verifyClicked() {
	u.request = approval.Request{}
	u.preview.SetText("")
	u.decision.SetText("")
	u.decision.Disable()
	u.updateSigningButtons()
	profile, err := loadProfile(u.profilePath.Text)
	var request []byte
	if err == nil {
		request, err = os.ReadFile(u.requestPath.Text)
	}
	var signed approval.SignedRequest
	var text string
	if err == nil {
		signed, text, err = verifiedRequest(profile, request)
	}
	if err != nil {
		u.status.SetText("Verification failed: " + visibleText(err.Error()))
		return
	}
	u.request = signed.Request
	u.profileValue = profile
	u.preview.SetText(text)
	u.updateSigningButtons()
	u.status.SetText("Signature verified. Offline snapshot only; not proof of safety or current pending status.")
}

func (u *previewUI) createKeyClicked() {
	u.lockKey()
	if _, err := u.requestedAutoLock(); err != nil {
		u.status.SetText("Key creation failed: " + err.Error())
		return
	}
	if u.passphrase.Text == "" {
		u.status.SetText("Key creation failed: passphrase can't be empty")
		return
	}
	if u.passphrase.Text != u.confirmPassphrase.Text {
		u.status.SetText("Key creation failed: passphrases do not match")
		return
	}
	key, err := newDeviceKey()
	if err == nil {
		err = saveDeviceKey(u.keyPath.Text, key.ID, key.Private, u.passphrase.Text)
	}
	if err != nil {
		key.lock()
		u.status.SetText("Key creation failed: " + visibleText(err.Error()))
		return
	}
	u.setUnlockedKey(key)
	u.status.SetText("Encrypted key created. Public key for trusted SSH enrollment: " + key.publicKeyText())
}

func (u *previewUI) unlockKeyClicked() {
	u.lockKey()
	if _, err := u.requestedAutoLock(); err != nil {
		u.status.SetText("Unlock failed: " + err.Error())
		return
	}
	key, err := loadDeviceKey(u.keyPath.Text, u.passphrase.Text)
	if err != nil {
		u.status.SetText("Unlock failed: " + visibleText(err.Error()))
		return
	}
	u.setUnlockedKey(key)
	u.status.SetText("Signing key unlocked. Device ID: " + key.ID + " · Public key: " + key.publicKeyText())
}

func (u *previewUI) setUnlockedKey(key *DeviceKey) {
	u.key = key
	u.passphrase.SetText("")
	u.confirmPassphrase.SetText("")
	u.updateSigningButtons()
	u.scheduleAutoLock()
}

func (u *previewUI) lockKey() {
	if u.lockTimer != nil {
		u.lockTimer.Stop()
		u.lockTimer = nil
	}
	if u.key != nil {
		u.key.lock()
		u.key = nil
	}
	u.updateSigningButtons()
}

func (u *previewUI) scheduleAutoLock() {
	if u.lockTimer != nil {
		u.lockTimer.Stop()
		u.lockTimer = nil
	}
	text := strings.TrimSpace(u.autoLock.Text)
	if text == "" {
		return
	}
	duration, err := u.requestedAutoLock()
	if err != nil {
		u.status.SetText("Auto-lock unchanged: " + err.Error())
		return
	}
	u.lockTimer = time.AfterFunc(duration, func() {
		fyne.Do(func() {
			u.lockKey()
			u.status.SetText("Signing key locked automatically. This does not revoke envelopes already sent.")
		})
	})
}

func (u *previewUI) requestedAutoLock() (time.Duration, error) {
	text := strings.TrimSpace(u.autoLock.Text)
	if text == "" {
		return 0, nil
	}
	return parseFlexibleDuration(text)
}

func (u *previewUI) signClicked(action string) {
	u.decision.SetText("")
	u.decision.Disable()
	validity, err := parseFlexibleDuration(strings.TrimSpace(u.decisionValidity.Text))
	if err != nil {
		u.status.SetText("Decision not created: " + err.Error())
		return
	}
	envelope, err := decisionEnvelope(u.request, u.deviceID(), action, time.Now().Add(validity), u.key)
	if err != nil {
		u.status.SetText("Decision not created: " + visibleText(err.Error()))
		return
	}
	u.decision.SetText(envelope)
	u.decision.Enable()
	u.status.SetText("Offline " + action + " envelope created. It has not been sent, approved by the authority, or executed.")
}

func (u *previewUI) deviceID() string {
	if u.key == nil {
		return ""
	}
	return u.key.ID
}

func (u *previewUI) updateSigningButtons() {
	ready := u.key != nil && u.request.RequestID != ""
	if ready {
		u.allow.Enable()
		u.deny.Enable()
	} else {
		u.allow.Disable()
		u.deny.Disable()
	}
}

func (u *previewUI) saveProfileClicked() {
	if err := SaveServerProfile(u.profilePath.Text, u.profileValue); err != nil {
		u.status.SetText("Profile save failed: " + visibleText(err.Error()))
		return
	}
	u.status.SetText("Trusted profile saved with mode 0600. Never accept a profile from a broker message.")
}

func (u *previewUI) connectClicked() {
	if u.transportActive {
		u.status.SetText("Service connection is already active.")
		return
	}
	interval, err := time.ParseDuration(strings.TrimSpace(u.pollInterval.Text))
	if err != nil || interval <= 0 {
		u.status.SetText("Connect failed: poll interval must be a positive duration")
		return
	}
	profile, err := loadProfile(u.profilePath.Text)
	if err != nil {
		u.status.SetText("Connect failed: " + visibleText(err.Error()))
		return
	}
	if u.key == nil {
		u.status.SetText("Connect failed: unlock the signing key first")
		return
	}
	network, address, err := parseTransportAddress(u.transportAddress.Text)
	if err != nil {
		u.status.SetText("Connect failed: " + visibleText(err.Error()))
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	connection, closeConnection, err := DialProtocol(ctx, network, address)
	if err != nil {
		cancel()
		u.status.SetText("Connect failed: " + visibleText(err.Error()))
		return
	}
	u.connection = connection
	u.closeConnection = closeConnection
	u.transportCancel = cancel
	u.profileValue = profile
	u.transportActive = true
	u.updateServiceButtons()
	u.status.SetText("Service connected. Pending snapshots are verified against the pinned server key.")
	go func() {
		poller := Poller{
			Connection: connection,
			Profile:    profile,
			Interval:   interval,
			OnPending:  u.handlePending,
		}
		err := poller.Run(ctx, u.key)
		closeConnection()
		fyne.Do(func() {
			u.transportStopped(err)
		})
	}()
}

func (u *previewUI) disconnectClicked() {
	if !u.transportActive {
		return
	}
	u.disconnecting = true
	u.transportCancel()
	u.closeConnection()
}

func (u *previewUI) transportStopped(err error) {
	u.transportActive = false
	u.connection = nil
	u.transportCancel = nil
	u.closeConnection = nil
	u.updateServiceButtons()
	if u.disconnecting || errors.Is(err, context.Canceled) {
		u.disconnecting = false
		u.status.SetText("Service connection closed.")
		return
	}
	u.disconnecting = false
	u.status.SetText("Service connection stopped: " + visibleText(err.Error()))
}

func (u *previewUI) handlePending(requests []approval.SignedRequest, pollErr error) {
	fyne.Do(func() {
		u.applyPending(requests, pollErr)
	})
}

func (u *previewUI) applyPending(requests []approval.SignedRequest, pollErr error) {
	if pollErr != nil {
		u.status.SetText("Pending poll failed: " + visibleText(pollErr.Error()))
		return
	}
	fresh := make([]approval.SignedRequest, 0, len(requests))
	for _, request := range requests {
		if _, seen := u.seenRequests[request.Request.RequestID]; seen {
			continue
		}
		u.seenRequests[request.Request.RequestID] = struct{}{}
		fresh = append(fresh, request)
	}
	u.serviceRequests = append([]approval.SignedRequest(nil), requests...)
	if u.requestList != nil {
		u.requestList.Refresh()
	}
	if len(fresh) != 0 {
		_ = NotifyPending(u.app, fresh)
	}
	if len(requests) == 0 {
		u.status.SetText("Service connected. Pending queue is empty.")
		return
	}
	u.status.SetText(fmt.Sprintf("Service connected. Verified %d pending request(s).", len(requests)))
}

func (u *previewUI) inspectServiceRequest() {
	if u.selectedRequest.Request.RequestID == "" {
		u.status.SetText("Select a service request first.")
		return
	}
	data, err := json.Marshal(u.selectedRequest)
	if err != nil {
		u.status.SetText("Request display failed: " + visibleText(err.Error()))
		return
	}
	text, err := verifiedPreview(u.profileValue, data)
	if err != nil {
		u.status.SetText("Request verification failed: " + visibleText(err.Error()))
		return
	}
	u.request = u.selectedRequest.Request
	u.preview.SetText(text)
	u.tabs.Select(u.tabs.Items[0])
	u.updateSigningButtons()
	u.status.SetText("Verified service request. Use Service actions to send a decision.")
}

func (u *previewUI) sendServiceDecision(action string) {
	if !u.transportActive || u.selectedRequest.Request.RequestID == "" {
		u.status.SetText("Select a verified pending request first.")
		return
	}
	validity, err := parseFlexibleDuration(strings.TrimSpace(u.decisionValidity.Text))
	if err != nil {
		u.status.SetText("Service decision not sent: " + err.Error())
		return
	}
	receipt, err := u.transportSubmit(action, validity)
	if err != nil {
		u.status.SetText("Service decision rejected: " + visibleText(err.Error()))
		return
	}
	u.removeServiceRequest(u.selectedRequest.Request.RequestID)
	u.status.SetText(fmt.Sprintf("%s sent. Authority receipt: %s.", action, receipt.Receipt.Status))
}

func (u *previewUI) transportSubmit(action string, validity time.Duration) (approval.SignedDecisionReceipt, error) {
	transport := Transport{
		Connection: u.connection,
		Profile:    u.profileValue,
	}
	return transport.SubmitDecision(context.Background(), u.key, u.selectedRequest, action, time.Now().Add(validity))
}

func (u *previewUI) updateServiceButtons() {
	ready := u.transportActive && u.selectedRequest.Request.RequestID != ""
	if ready {
		u.inspectSelected.Enable()
		u.serviceAllow.Enable()
		u.serviceDeny.Enable()
	} else {
		u.inspectSelected.Disable()
		u.serviceAllow.Disable()
		u.serviceDeny.Disable()
	}
}

func (u *previewUI) removeServiceRequest(requestID string) {
	remaining := make([]approval.SignedRequest, 0, len(u.serviceRequests))
	for _, request := range u.serviceRequests {
		if request.Request.RequestID != requestID {
			remaining = append(remaining, request)
		}
	}
	u.serviceRequests = remaining
	if u.selectedRequest.Request.RequestID == requestID {
		u.selectedIndex = -1
		u.selectedRequest = approval.SignedRequest{}
	}
	if u.requestList != nil {
		u.requestList.Refresh()
	}
	u.updateServiceButtons()
}

func parseFlexibleDuration(value string) (time.Duration, error) {
	if value == "" {
		return 0, errors.New("duration required")
	}
	if duration, err := time.ParseDuration(value); err == nil {
		if duration <= 0 {
			return 0, errors.New("duration must be positive")
		}
		return duration, nil
	}
	minutes, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, errors.New("duration must be positive (for example 5m, 90s or 30)")
	}
	if minutes > math.MaxInt64/int64(time.Minute) {
		return 0, errors.New("duration is too large")
	}
	duration := time.Duration(minutes) * time.Minute
	if duration <= 0 {
		return 0, errors.New("duration must be positive")
	}
	return duration, nil
}

func main() {
	args := os.Args[1:]
	if handled, code := runAppCommand(args, os.Stdout, os.Stderr); handled {
		os.Exit(code)
	}
	o, err := parseOptions(args, os.Stdout)
	if err == flag.ErrHelp {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	application := app.NewWithID("io.racg.approver.preview")
	window := application.NewWindow("RACG Approver")
	window.Resize(fyne.NewSize(1080, 820))
	if o.connect != "" {
		window.SetContent(buildServiceUI(o, application))
	} else {
		window.SetContent(buildContent(o, application))
	}
	window.ShowAndRun()
}
