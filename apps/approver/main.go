package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

const helpText = `usage: racg-approver [--server-profile path] [--request path]

Development preview of the separate Linux desktop approver.
Offline signature inspection only: no network connection, signing or execution.
The existing racg serve and its local TUI do not require this application.

--server-profile  trusted JSON from SSH enrollment: server_id and public_key
                  (base64 Ed25519 public key); never trust a broker-provided key
--request         JSON signed request envelope exported from the authority
--help            show this help without opening a window

Select both files, then click Verify and inspect. Invalid signatures hide the
operation. Invisible formatting characters are escaped for review. A valid
signature authenticates content, not its safety, freshness or pending status.
Preview mode cannot approve or deny. No keys or server profiles are saved.
`

type options struct{ profile, request string }

func parseOptions(args []string, out io.Writer) (options, error) {
	var o options
	fs := flag.NewFlagSet("racg-approver", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.Usage = func() { fmt.Fprint(out, helpText) }
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

func buildContent(o options) fyne.CanvasObject {
	profilePath := widget.NewEntry()
	profilePath.SetPlaceHolder("Path to trusted server profile")
	profilePath.SetText(o.profile)
	requestPath := widget.NewEntry()
	requestPath.SetPlaceHolder("Path to signed request JSON")
	requestPath.SetText(o.request)
	status := widget.NewLabel("Offline preview — no signing, network or execution.")
	status.Wrapping = fyne.TextWrapWord
	preview := widget.NewMultiLineEntry()
	preview.TextStyle = fyne.TextStyle{Monospace: true}
	preview.Wrapping = fyne.TextWrapOff
	preview.Disable()
	verify := widget.NewButton("Verify and inspect", func() {
		preview.SetText("")
		profileBytes, err := os.ReadFile(profilePath.Text)
		var profile ServerProfile
		if err == nil {
			err = json.Unmarshal(profileBytes, &profile)
		}
		var request []byte
		if err == nil {
			request, err = os.ReadFile(requestPath.Text)
		}
		var text string
		if err == nil {
			text, err = verifiedPreview(profile, request)
		}
		if err != nil {
			status.SetText("Verification failed: " + visibleText(err.Error()))
			return
		}
		preview.SetText(text)
		status.SetText("Signature verified. Offline snapshot only; not proof of safety or current pending status.")
	})
	form := widget.NewForm(widget.NewFormItem("Trusted server profile", profilePath), widget.NewFormItem("Signed request", requestPath))
	top := container.NewVBox(widget.NewLabelWithStyle("RACG Approver · development preview", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}), form, verify, status)
	return container.NewBorder(top, nil, nil, nil, preview)
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
	window := application.NewWindow("RACG Approver — offline preview")
	window.Resize(fyne.NewSize(960, 720))
	window.SetContent(buildContent(o))
	window.ShowAndRun()
}
