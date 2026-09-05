package main

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

func TestUIVerificationFailureClearsPreview(t *testing.T) {
	app := test.NewApp()
	defer app.Quit()
	content := buildContent(options{profile: "/nonexistent-racg-test-profile"})
	var preview *widget.Entry
	var verify *widget.Button
	var labels []*widget.Label
	var walk func(fyne.CanvasObject)
	walk = func(obj fyne.CanvasObject) {
		switch v := obj.(type) {
		case *fyne.Container:
			for _, child := range v.Objects {
				walk(child)
			}
		case *widget.Entry:
			if v.MultiLine {
				preview = v
			}
		case *widget.Button:
			if v.Text == "Verify and inspect" {
				verify = v
			}
		case *widget.Label:
			labels = append(labels, v)
		}
	}
	walk(content)
	if preview == nil || verify == nil {
		t.Fatal("missing preview controls")
	}
	preview.SetText("previous verified request")
	test.Tap(verify)
	if preview.Text != "" {
		t.Fatal("stale request remained visible after verification failed")
	}
	found := false
	for _, label := range labels {
		if strings.HasPrefix(label.Text, "Verification failed:") {
			found = true
		}
	}
	if !found {
		t.Fatal("verification error not shown")
	}
}
