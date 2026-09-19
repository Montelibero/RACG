package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/itolstov/racg/internal/approval"
)

type simpleUI struct {
	app        fyne.App
	options    options
	interval   time.Duration
	profile    ServerProfile
	connection Connection
	closeConn  func()
	cancel     context.CancelFunc
	active     bool
	key        *DeviceKey
	requests   []approval.SignedRequest
	selected   approval.SignedRequest

	status      *widget.Label
	endpoint    *widget.Entry
	profilePath *widget.Entry
	keyPath     *widget.Entry
	passphrase  *widget.Entry
	validity    *widget.Entry
	start       *widget.Button
	stop        *widget.Button
	lock        *widget.Button
	list        *widget.List
	details     *widget.Entry
	allow       *widget.Button
	deny        *widget.Button
	pollCancel  context.CancelFunc
}

func newSimpleUI(o options, app fyne.App) *simpleUI {
	u := &simpleUI{app: app, options: o, interval: o.pollInterval}
	u.status = widget.NewLabel("Enter connection details, then press Start.")
	u.status.Wrapping = fyne.TextWrapWord
	u.endpoint = widget.NewEntry()
	u.endpoint.SetText(o.connect)
	u.profilePath = widget.NewEntry()
	u.profilePath.SetText(o.profile)
	u.keyPath = widget.NewEntry()
	u.keyPath.SetText(o.key)
	u.passphrase = widget.NewPasswordEntry()
	u.passphrase.SetPlaceHolder("Device key passphrase")
	u.validity = widget.NewEntry()
	u.validity.SetText("5m")
	u.start = widget.NewButton("Start approvals", u.startClicked)
	u.stop = widget.NewButton("Stop", u.stopClicked)
	u.lock = widget.NewButton("Lock key", u.lockClicked)
	u.list = widget.NewList(
		func() int { return len(u.requests) },
		func() fyne.CanvasObject { return widget.NewLabel("template") },
		func(i int, object fyne.CanvasObject) {
			if i >= 0 && i < len(u.requests) {
				object.(*widget.Label).SetText(requestListText(u.requests[i]))
			}
		},
	)
	u.list.OnSelected = func(i int) {
		if i >= 0 && i < len(u.requests) {
			u.selected = u.requests[i]
			u.showSelected()
		}
		u.updateButtons()
	}
	u.details = widget.NewMultiLineEntry()
	u.details.TextStyle = fyne.TextStyle{Monospace: true}
	u.details.Wrapping = fyne.TextWrapBreak
	u.details.SetPlaceHolder("Select a pending request to review it here")
	u.details.Disable()
	u.allow = widget.NewButton("Allow once", func() { u.decide("ALLOW_ONCE") })
	u.deny = widget.NewButton("Deny", func() { u.decide("DENY") })
	u.updateButtons()
	return u
}

func (u *simpleUI) canvas() fyne.CanvasObject {
	connectionForm := widget.NewForm(
		widget.NewFormItem("Broker endpoint", u.endpoint),
		widget.NewFormItem("Server profile", u.profilePath),
		widget.NewFormItem("Device key", u.keyPath),
		widget.NewFormItem("Passphrase", u.passphrase),
	)
	connectionButtons := container.NewHBox(u.start, u.stop, u.lock)
	decisionButtons := container.NewHBox(u.allow, u.deny)
	validity := container.NewHBox(widget.NewLabel("Decision validity"), u.validity)
	pending := widget.NewCard("Pending requests", "", container.NewBorder(decisionButtons, nil, nil, nil, u.list))
	details := widget.NewCard("Selected request", "", container.NewBorder(validity, nil, nil, nil, u.details))
	split := container.NewVSplit(pending, details)
	split.Offset = 0.38
	top := container.NewVBox(
		u.status,
		connectionForm,
		connectionButtons,
	)
	return container.NewBorder(top, nil, nil, nil, split)
}

func buildServiceUI(o options, app fyne.App) fyne.CanvasObject {
	return newSimpleUI(o, app).canvas()
}

func (u *simpleUI) setStatus(text string) {
	u.status.SetText(text)
}

func (u *simpleUI) updateButtons() {
	if u.active {
		u.start.Disable()
		u.stop.Enable()
	} else {
		u.start.Enable()
		u.stop.Disable()
	}
	ready := u.active && u.key != nil && u.selected.Request.RequestID != ""
	if ready {
		u.allow.Enable()
		u.deny.Enable()
	} else {
		u.allow.Disable()
		u.deny.Disable()
	}
}

func (u *simpleUI) startClicked() {
	if u.active {
		u.setStatus("Approvals are already running.")
		return
	}
	interval := u.interval
	profile, err := loadProfile(u.profilePath.Text)
	if err != nil {
		u.setStatus("Start failed: " + visibleText(err.Error()))
		return
	}
	passphrase := u.passphrase.Text
	if passphrase == "" {
		u.setStatus("Start failed: passphrase required")
		return
	}
	key, err := loadDeviceKey(u.keyPath.Text, passphrase)
	if err != nil {
		u.setStatus("Start failed: " + visibleText(err.Error()))
		return
	}
	network, address, err := parseTransportAddress(u.endpoint.Text)
	if err != nil {
		u.setStatus("Start failed: " + visibleText(err.Error()))
		return
	}
	connection, closeConn, err := DialProtocol(context.Background(), network, address)
	if err != nil {
		u.setStatus("Start failed: " + visibleText(err.Error()))
		return
	}
	u.profile = profile
	u.key = key
	u.connection = connection
	u.closeConn = closeConn
	u.active = true
	ctx, cancel := context.WithCancel(context.Background())
	u.cancel = cancel
	u.updateButtons()
	u.setStatus("Connected. Waiting for signed pending requests.")
	go u.pollLoop(ctx, interval)
}

func (u *simpleUI) stopClicked() {
	u.disconnect()
	u.setStatus("Approvals stopped.")
}

func (u *simpleUI) lockClicked() {
	u.disconnect()
	if u.key != nil {
		u.key.lock()
		u.key = nil
	}
	u.setStatus("Device key locked.")
}

func (u *simpleUI) disconnect() {
	if u.cancel != nil {
		u.cancel()
		u.cancel = nil
	}
	if u.closeConn != nil {
		u.closeConn()
		u.closeConn = nil
	}
	u.active = false
	u.connection = nil
	u.updateButtons()
}

func (u *simpleUI) pollLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Second
	}
	transport := Transport{
		Connection: u.connection,
		Profile:    u.profile,
		Now:        time.Now,
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	requests, err := transport.PendingRequests(ctx, u.key)
	fyne.Do(func() { u.applyPending(requests, err) })
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			requests, err := transport.PendingRequests(ctx, u.key)
			fyne.Do(func() { u.applyPending(requests, err) })
		}
	}
}

func (u *simpleUI) applyPending(requests []approval.SignedRequest, err error) {
	if err != nil {
		u.setStatus("Pending poll failed: " + visibleText(err.Error()))
		return
	}
	selectedID := u.selected.Request.RequestID
	u.requests = append([]approval.SignedRequest(nil), requests...)
	u.list.Refresh()
	if selectedID != "" {
		for _, request := range u.requests {
			if request.Request.RequestID == selectedID {
				u.selected = request
				u.showSelected()
				break
			}
		}
	}
	switch len(requests) {
	case 0:
		u.setStatus("Connected. Pending queue is empty.")
	default:
		u.setStatus(fmt.Sprintf("Connected. %d verified pending request(s).", len(requests)))
	}
}

func (u *simpleUI) showSelected() {
	data, err := json.Marshal(u.selected)
	if err != nil {
		u.setStatus("Request display failed: " + visibleText(err.Error()))
		return
	}
	text, err := verifiedPreview(u.profile, data)
	if err != nil {
		u.setStatus("Request verification failed: " + visibleText(err.Error()))
		return
	}
	u.details.SetText(text)
}

func (u *simpleUI) decide(action string) {
	if !u.active || u.selected.Request.RequestID == "" {
		u.setStatus("Select a pending request first.")
		return
	}
	validity, err := parseFlexibleDuration(strings.TrimSpace(u.validity.Text))
	if err != nil {
		u.setStatus("Decision failed: " + err.Error())
		return
	}
	transport := Transport{
		Connection: u.connection,
		Profile:    u.profile,
		Now:        time.Now,
	}
	receipt, err := transport.SubmitDecision(context.Background(), u.key, u.selected, action, time.Now().Add(validity))
	if err != nil {
		u.setStatus("Decision rejected: " + visibleText(err.Error()))
		return
	}
	requestID := u.selected.Request.RequestID
	remaining := make([]approval.SignedRequest, 0, len(u.requests))
	for _, request := range u.requests {
		if request.Request.RequestID != requestID {
			remaining = append(remaining, request)
		}
	}
	u.requests = remaining
	u.selected = approval.SignedRequest{}
	u.details.SetText("")
	u.list.Refresh()
	u.updateButtons()
	u.setStatus(fmt.Sprintf("%s accepted by authority. Receipt status: %s.", action, receipt.Receipt.Status))
}
