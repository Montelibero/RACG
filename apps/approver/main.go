package main

import (
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

const helpText = `usage: racg-approver [--key path] [--server-profile path] [--request path]

Development preview of the separate Linux desktop approver.
It can create or unlock a passphrase-encrypted local signing key, inspect a
signed request, and create an offline Allow once or Deny envelope.
It has no network or service connection and cannot send decisions or execute.
The existing racg serve and its local TUI do not require this application.

--key             optional passphrase-encrypted Ed25519 signing key; created with
                  a passphrase and kept on this device, never sent anywhere
--server-profile  trusted JSON from SSH enrollment: server_id and public_key
                  (base64 Ed25519 public key); never trust a broker-provided key
--request         JSON signed request envelope exported from the authority
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
form. The Decision tab contains a copyable envelope only; nothing is sent.
`

type options struct {
	key     string
	profile string
	request string
}

func parseOptions(args []string, out io.Writer) (options, error) {
	var o options
	fs := flag.NewFlagSet("racg-approver", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() { fmt.Fprint(out, helpText) }
	fs.StringVar(&o.key, "key", "", "passphrase-encrypted signing key")
	fs.StringVar(&o.profile, "server-profile", "", "trusted server profile")
	fs.StringVar(&o.request, "request", "", "signed request envelope")
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
	preview           *widget.Entry
	decision          *widget.Entry
	status            *widget.Label
	createKey         *widget.Button
	unlockKey         *widget.Button
	lockNow           *widget.Button
	verify            *widget.Button
	allow             *widget.Button
	deny              *widget.Button

	key       *DeviceKey
	request   approval.Request
	lockTimer *time.Timer
}

func newPreviewUI(o options) *previewUI {
	u := &previewUI{}
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
	requestButtons := container.NewHBox(u.verify, u.allow, u.deny)
	top := container.NewVBox(
		widget.NewLabelWithStyle("RACG Approver · offline signing preview", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		requestForm, requestButtons,
		widget.NewLabelWithStyle("Signing key", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		keyForm, keyButtons,
		u.status,
	)
	tabs := container.NewAppTabs(
		container.NewTabItem("Request", u.preview),
		container.NewTabItem("Decision", u.decision),
	)
	return container.NewBorder(top, nil, nil, nil, tabs)
}

func buildContent(o options) fyne.CanvasObject {
	return newPreviewUI(o).canvas()
}

func (u *previewUI) verifyClicked() {
	u.request = approval.Request{}
	u.preview.SetText("")
	u.decision.SetText("")
	u.decision.Disable()
	u.updateSigningButtons()
	profileBytes, err := os.ReadFile(u.profilePath.Text)
	var profile ServerProfile
	if err == nil {
		err = json.Unmarshal(profileBytes, &profile)
	}
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
	o, err := parseOptions(os.Args[1:], os.Stdout)
	if err == flag.ErrHelp {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	application := app.NewWithID("io.racg.approver.preview")
	window := application.NewWindow("RACG Approver — offline signing preview")
	window.Resize(fyne.NewSize(1080, 820))
	window.SetContent(buildContent(o))
	window.ShowAndRun()
}
