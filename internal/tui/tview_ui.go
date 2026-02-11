package tui

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/itolstov/racg/internal/events"
	"github.com/itolstov/racg/internal/httpapi"
	"github.com/itolstov/racg/internal/store"
)

type ServeUIConfig struct {
	Version  string
	Listen   string
	API      *httpapi.API
	Store    *store.Store
	ExitFunc func()
}

func RunServeUI(ctx context.Context, cfg ServeUIConfig) error {
	if cfg.API == nil {
		return fmt.Errorf("API required")
	}
	if cfg.ExitFunc == nil {
		cfg.ExitFunc = func() {}
	}

	app := tview.NewApplication().EnableMouse(true)
	pages := tview.NewPages()

	state := newUIState(cfg.API, cfg.Store)

	pairingPage := buildPairingPage(ctx, app, pages, state, cfg)
	dashboardPage := buildDashboardPage(app, pages, state, cfg)
	helpPage := buildHelpModal(pages, state)
	rulesPage := buildRulesPage(app, pages, state, cfg)
	historyPage := buildHistoryPage(app, pages, state, cfg)

	pages.AddPage("pairing", pairingPage, true, true)
	pages.AddPage("dashboard", dashboardPage, true, false)
	pages.AddPage("rules", rulesPage, true, false)
	pages.AddPage("history", historyPage, true, false)
	pages.AddPage("help", helpPage, true, false)

	app.SetRoot(pages, true)

	app.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEsc {
			if state.overlayClose != nil {
				state.overlayClose()
				return nil
			}
		}
		switch ev.Key() {
		case tcell.KeyTAB:
			state.cycleFocus(app)
			return nil
		case tcell.KeyF1:
			state.openHelp(pages)
			return nil
		case tcell.KeyEsc:
			state.back(app, pages)
			return nil
		}
		switch ev.Rune() {
		case 'q':
			cfg.ExitFunc()
			app.Stop()
			return nil
		case '?':
			state.openHelp(pages)
			return nil
		case 'r':
			state.showRules(app, pages)
			return nil
		case 'h':
			state.showHistory(app, pages)
			return nil
		}
		return ev
	})

	// Events -> UI state.
	evCh, cancel := cfg.API.SubscribeEvents(256)
	defer cancel()
	go func() {
		for {
			select {
			case <-ctx.Done():
				app.QueueUpdateDraw(func() { app.Stop() })
				return
				case e, ok := <-evCh:
					if !ok {
						return
					}
					app.QueueUpdateDraw(func() {
						state.onEvent(e)
						state.maybeAutoSwitchToDashboard(app, pages, len(cfg.API.ListPendingForTUI()))
					})
				}
			}
		}()

	// Safety net: periodic refresh to avoid missing dropped events.
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				app.QueueUpdateDraw(func() {
					state.refresh()
					state.maybeAutoSwitchToDashboard(app, pages, len(cfg.API.ListPendingForTUI()))
				})
			}
		}
	}()

	return app.Run()
}

type uiState struct {
	api   *httpapi.API
	store *store.Store

	mu sync.Mutex

	page string

	// Dashboard widgets.
	pendingList *tview.List
	filter      *tview.InputField
	details     *tview.TextView
	jobsList    *tview.List
	statusBar   *tview.TextView
	jobsModeBtn *tview.Button

	// Job view widgets.
	jobHeader *tview.TextView
	jobLog    *tview.TextView
	follow    bool

	// Focus cycle order.
	focus []tview.Primitive

	// Selected IDs.
	selectedPending string
	selectedJob     string
	pendingIDs      []string
	jobIDs          []string
	showAllJobs     bool

	// Optional page refresh hooks (for non-dashboard pages).
	rulesRefresh   func()
	historyRefresh func()

	// Last toast.
	toastUntil time.Time
	toastText  string

	// Overlay (e.g. copy mode) close handler.
	overlayClose func()
}

func newUIState(api *httpapi.API, st *store.Store) *uiState {
	return &uiState{api: api, store: st, follow: true, page: "pairing", showAllJobs: false}
}

func (s *uiState) setCurrentPage(p string) { s.page = p }

func (s *uiState) showDashboard(app *tview.Application, pages *tview.Pages) {
	if pages != nil {
		pages.ShowPage("dashboard")
	}
	s.page = "dashboard"
	s.refresh()
	if app != nil {
		s.cycleFocusTo(app, s.pendingList)
	}
}

func (s *uiState) maybeAutoSwitchToDashboard(app *tview.Application, pages *tview.Pages, pendingCount int) bool {
	if s.page != "pairing" || pendingCount <= 0 {
		return false
	}
	s.showDashboard(app, pages)
	return true
}

func (s *uiState) showRules(app *tview.Application, pages *tview.Pages) {
	if pages != nil {
		pages.ShowPage("rules")
	}
	s.page = "rules"
	if s.rulesRefresh != nil {
		s.rulesRefresh()
	}
}

func (s *uiState) showHistory(app *tview.Application, pages *tview.Pages) {
	if pages != nil {
		pages.ShowPage("history")
	}
	s.page = "history"
	if s.historyRefresh != nil {
		s.historyRefresh()
	}
}

func (s *uiState) back(app *tview.Application, pages *tview.Pages) {
	if s.page == "dashboard" {
		if pages != nil {
			pages.ShowPage("pairing")
		}
		s.page = "pairing"
		return
	}
	// If we're leaving a job page via global Esc, remove it to avoid stacking stale job pages.
	if s.page == "job" && pages != nil {
		pages.RemovePage("job")
	}
	s.showDashboard(app, pages)
}

func (s *uiState) cycleFocus(app *tview.Application) {
	if len(s.focus) == 0 {
		return
	}
	cur := app.GetFocus()
	for i, p := range s.focus {
		if p == cur {
			next := s.focus[(i+1)%len(s.focus)]
			app.SetFocus(next)
			return
		}
	}
	app.SetFocus(s.focus[0])
}

func (s *uiState) cycleFocusTo(app *tview.Application, p tview.Primitive) {
	if p == nil {
		return
	}
	app.SetFocus(p)
}

func (s *uiState) openHelp(pages *tview.Pages) {
	pages.ShowPage("help")
	s.overlayClose = func() {
		pages.HidePage("help")
		s.overlayClose = nil
	}
}

func (s *uiState) openCopyOverlay(app *tview.Application, pages *tview.Pages, title, text string) {
	// Disable mouse reporting so terminal text selection works for copy/paste.
	app.EnableMouse(false)

	prevFocus := app.GetFocus()

	hint := tview.NewTextView().SetDynamicColors(false).SetTextAlign(tview.AlignLeft)
	hint.SetText("Copy mode: select text with mouse, Esc to close")

	box := tview.NewTextView().SetDynamicColors(false).SetScrollable(true)
	box.SetText(text)
	box.SetBorder(true).SetTitle(title)

	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(hint, 1, 0, false).
		AddItem(box, 0, 1, true)

	close := func() {
		pages.RemovePage("copy")
		app.EnableMouse(true)
		s.overlayClose = nil
		if prevFocus != nil {
			app.SetFocus(prevFocus)
		}
	}
	s.overlayClose = close

	root.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEsc {
			close()
			return nil
		}
		return ev
	})

	pages.AddPage("copy", root, true, true)
	app.SetFocus(box)
}

func (s *uiState) jobsModeLabel() string {
	if s.showAllJobs {
		return "Only running"
	}
	return "Show all"
}

func (s *uiState) setJobsModeLabel() {
	if s.jobsModeBtn == nil {
		return
	}
	s.jobsModeBtn.SetLabel(s.jobsModeLabel())
}

func (s *uiState) toggleJobsMode() {
	s.showAllJobs = !s.showAllJobs
	s.setJobsModeLabel()
	s.refreshJobs()
}

func (s *uiState) jobIndex(id string) int {
	for i, jobID := range s.jobIDs {
		if jobID == id {
			return i
		}
	}
	return -1
}

func (s *uiState) nextJobID(delta int) string {
	if len(s.jobIDs) == 0 {
		return ""
	}
	idx := s.jobIndex(s.selectedJob)
	if idx < 0 {
		idx = 0
	}
	next := (idx + delta) % len(s.jobIDs)
	if next < 0 {
		next += len(s.jobIDs)
	}
	return s.jobIDs[next]
}

func (s *uiState) nthJobID(n int) string {
	if n < 1 || n > len(s.jobIDs) {
		return ""
	}
	return s.jobIDs[n-1]
}

func (s *uiState) renderJobTabs(activeID string) string {
	if len(s.jobIDs) == 0 {
		return "Tabs: no jobs"
	}
	var b strings.Builder
	b.WriteString("Tabs: ")
	for i, id := range s.jobIDs {
		info, ok := s.api.GetRequestInfoForTUI(id)
		status := "?"
		if ok {
			status = shortStatus(info.Status)
		}
		if i > 0 {
			b.WriteString(" | ")
		}
		prefix := fmt.Sprintf("%d:%s", i+1, status)
		if id == activeID {
			b.WriteString("[" + prefix + "]")
		} else {
			b.WriteString(prefix)
		}
	}
	return b.String()
}

func (s *uiState) openJobPage(app *tview.Application, pages *tview.Pages, cfg ServeUIConfig, requestID string) {
	if requestID == "" || pages == nil {
		return
	}
	pages.RemovePage("job")
	job := buildJobPage(app, pages, s, cfg, requestID)
	pages.AddAndSwitchToPage("job", job, true)
	s.setCurrentPage("job")
}

func shortStatus(st string) string {
	switch st {
	case "RUNNING":
		return "RUN"
	case "SUCCEEDED":
		return "OK"
	case "FAILED":
		return "FAIL"
	case "TIMED_OUT":
		return "TIMEOUT"
	case "KILLED":
		return "KILLED"
	case "APPROVED":
		return "WAIT"
	default:
		return st
	}
}

func (s *uiState) onEvent(e events.Event) {
	switch e.Type {
	case "request.created":
		s.toastText = fmt.Sprintf("New request from %s", e.ClientID)
		s.toastUntil = time.Now().Add(3 * time.Second)
	case "request.output":
		if s.selectedJob == e.RequestID && s.jobLog != nil {
			chunk, _ := e.Data["chunk"].(string)
			stream, _ := e.Data["stream"].(string)
			if chunk != "" {
				pfx := "O: "
				if stream == "stderr" {
					pfx = "E: "
				}
				fmt.Fprint(s.jobLog, pfx+chunk)
				if s.follow {
					s.jobLog.ScrollToEnd()
				}
			}
		}
	}
	s.refresh()
}

func (s *uiState) refresh() {
	if s.pendingList != nil {
		s.refreshPending()
	}
	if s.jobsList != nil {
		s.refreshJobs()
	}
	if s.statusBar != nil {
		s.refreshStatus()
	}
	if s.details != nil && s.selectedPending != "" {
		s.refreshDetails(s.selectedPending)
	}
	if s.jobHeader != nil && s.selectedJob != "" {
		s.refreshJobHeader(s.selectedJob)
	}
}

func (s *uiState) refreshStatus() {
	pn := len(s.api.ListPendingForTUI())
	rn := len(s.api.ListRunningForTUI())
	mode := "ROOT MODE"
	line := fmt.Sprintf("F1/? Help | Tab focus | a once | s session | A always | d deny | r rules | h history | q quit   %s   pending=%d running=%d",
		mode, pn, rn)
	if time.Now().Before(s.toastUntil) && s.toastText != "" {
		line = s.toastText + "   |   " + line
	}
	s.statusBar.SetText(line)
}

func (s *uiState) refreshPending() {
	filter := strings.TrimSpace(s.filter.GetText())
	items := s.api.ListPendingForTUI()

	s.pendingList.Clear()
	s.pendingIDs = s.pendingIDs[:0]
	for _, it := range items {
		if filter != "" {
			hay := strings.ToLower(it.ClientID + " " + it.Summary + " " + strings.Join(it.RiskFlags, " "))
			if !strings.Contains(hay, strings.ToLower(filter)) {
				continue
			}
		}
		label := fmt.Sprintf("%s · %s · %s", trimTime(it.CreatedAt), it.ClientID, it.Summary)
		if len(it.RiskFlags) > 0 {
			label += "  [" + strings.Join(it.RiskFlags, ",") + "]"
		}
		s.pendingIDs = append(s.pendingIDs, it.ID)
		s.pendingList.AddItem(label, "", 0, nil)
	}
	if s.pendingList.GetItemCount() == 0 {
		s.selectedPending = ""
		s.details.SetText("")
		return
	}
	if s.selectedPending == "" {
		s.pendingList.SetCurrentItem(0)
	}
}

func (s *uiState) refreshDetails(requestID string) {
	info, ok := s.api.GetRequestInfoForTUI(requestID)
	if !ok {
		s.details.SetText("")
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "id: %s\nstatus: %s\nclient_id: %s\nsession_id: %s\nrequested_at: %s\n\n",
		info.ID, info.Status, info.ClientID, info.SessionID, info.CreatedAt)
	if len(info.RiskFlags) > 0 {
		fmt.Fprintf(&b, "risk: %s\n\n", strings.Join(info.RiskFlags, ", "))
	}
	if info.Details != "" {
		b.WriteString(info.Details)
		b.WriteString("\n")
	}
	s.details.SetText(b.String())
}

func (s *uiState) refreshJobs() {
	items := s.api.ListJobsForTUI(s.showAllJobs)
	s.jobsList.Clear()
	s.jobIDs = s.jobIDs[:0]
	for _, it := range items {
		label := fmt.Sprintf("%s · %-7s · %s", trimTime(it.CreatedAt), shortStatus(it.Status), it.Summary)
		s.jobIDs = append(s.jobIDs, it.ID)
		s.jobsList.AddItem(label, it.ClientID, 0, nil)
	}
	if len(s.jobIDs) == 0 {
		s.selectedJob = ""
		return
	}
	idx := s.jobIndex(s.selectedJob)
	if idx < 0 {
		idx = 0
		s.selectedJob = s.jobIDs[0]
	}
	s.jobsList.SetCurrentItem(idx)
}

func (s *uiState) refreshJobHeader(requestID string) {
	info, ok := s.api.GetRequestInfoForTUI(requestID)
	if !ok {
		s.jobHeader.SetText("")
		return
	}
	s.jobHeader.SetText(fmt.Sprintf("job: %s  status=%s  client=%s", info.ID, info.Status, info.ClientID))
}

func buildPairingPage(ctx context.Context, app *tview.Application, pages *tview.Pages, s *uiState, cfg ServeUIConfig) tview.Primitive {
	title := tview.NewTextView().SetDynamicColors(false).SetTextAlign(tview.AlignLeft)
	code := tview.NewTextView().SetDynamicColors(false).SetTextAlign(tview.AlignLeft)
	meta := tview.NewTextView().SetDynamicColors(false).SetTextAlign(tview.AlignLeft)

	goDashboard := func() {
		pages.ShowPage("dashboard")
		s.setCurrentPage("dashboard")
		s.refresh()
		app.SetFocus(s.pendingList)
	}
	btnDash := tview.NewButton("Go to Dashboard").SetSelectedFunc(goDashboard)

	regen := func() {
		cfg.API.RegeneratePairingCode()
	}
	btnRegen := tview.NewButton("Regenerate code").SetSelectedFunc(regen)

	quit := func() {
		cfg.ExitFunc()
		app.Stop()
	}
	btnQuit := tview.NewButton("Quit").SetSelectedFunc(quit)

	copy := func() {
		listenURL := cfg.Listen
		if !strings.Contains(listenURL, "://") {
			listenURL = "http://" + listenURL
		}
		pc := cfg.API.PairingCode()
		s.openCopyOverlay(app, pages, "Pairing Info", PairingCopyText(listenURL, pc))
	}
	btnCopy := tview.NewButton("Copy").SetSelectedFunc(copy)

	btns := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(btnDash, 0, 1, false).
		AddItem(btnCopy, 0, 1, false).
		AddItem(btnRegen, 0, 1, false).
		AddItem(btnQuit, 0, 1, false)

	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(title, 3, 0, false).
		AddItem(code, 4, 0, false).
		AddItem(meta, 0, 1, false).
		AddItem(btns, 1, 0, true)

	refresh := func() {
		title.SetText(fmt.Sprintf("RACG serve  v%s\nlisten=%s\n", cfg.Version, cfg.Listen))
		pc := cfg.API.PairingCode()
		code.SetText("PAIRING CODE:\n" + pc + "\n\nRACG_CODE=" + pc + "\nopen_session --code " + pc + "\n")
		meta.SetText(fmt.Sprintf("expires in %s\npending=%d  running=%d\n",
			formatMMSS(cfg.API.PairingExpiresIn()),
			len(cfg.API.ListPendingForTUI()),
			len(cfg.API.ListRunningForTUI()),
		))
	}
	refresh()

	// Pairing page-specific keys.
	root.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyEnter:
			goDashboard()
			return nil
		}
		switch ev.Rune() {
		case 'r':
			regen()
			return nil
		case 'c':
			copy()
			return nil
		}
		return ev
	})

	// Refresh timer on this page.
	go func() {
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				app.QueueUpdateDraw(refresh)
			}
		}
	}()

	s.page = "pairing"
	s.focus = []tview.Primitive{btnDash, btnCopy, btnRegen, btnQuit}
	return root
}

func buildDashboardPage(app *tview.Application, pages *tview.Pages, s *uiState, cfg ServeUIConfig) tview.Primitive {
	s.filter = tview.NewInputField().SetLabel("filter: ")
	s.pendingList = tview.NewList().ShowSecondaryText(false)
	s.details = tview.NewTextView().SetDynamicColors(false).SetScrollable(true)
	s.jobsList = tview.NewList().ShowSecondaryText(true)
	s.statusBar = tview.NewTextView().SetDynamicColors(false)
	s.jobsModeBtn = tview.NewButton("").SetSelectedFunc(func() {
		s.toggleJobsMode()
	})
	s.setJobsModeLabel()

	s.filter.SetChangedFunc(func(text string) { s.refreshPending() })
	s.filter.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			app.SetFocus(s.pendingList)
		}
	})

	left := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(s.filter, 1, 0, false).
		AddItem(s.pendingList, 0, 1, true)
	left.SetBorder(true).SetTitle("Pending approvals")

	center := tview.NewFlex().SetDirection(tview.FlexRow)
	center.SetBorder(true).SetTitle("Request details")
	center.AddItem(s.details, 0, 1, false)

	btnOnce := tview.NewButton("Allow once").SetSelectedFunc(func() { s.doDecision("ALLOW_ONCE") })
	btnSess := tview.NewButton("Allow session").SetSelectedFunc(func() { s.doDecision("ALLOW_SESSION") })
	btnAlways := tview.NewButton("Allow always").SetSelectedFunc(func() { s.doDecision("ALLOW_ALWAYS") })
	btnDeny := tview.NewButton("Deny").SetSelectedFunc(func() { s.doDecision("DENY") })
	btnRow := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(btnOnce, 0, 1, false).
		AddItem(btnSess, 0, 1, false).
		AddItem(btnAlways, 0, 1, false).
		AddItem(btnDeny, 0, 1, false)
	center.AddItem(btnRow, 1, 0, false)

	right := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(s.jobsModeBtn, 1, 0, false).
		AddItem(s.jobsList, 0, 1, true)
	right.SetBorder(true).SetTitle("Running jobs")

	body := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(left, 0, 3, true).
		AddItem(center, 0, 5, false).
		AddItem(right, 0, 3, false)

	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(body, 0, 1, true).
		AddItem(s.statusBar, 1, 0, false)

	s.pendingList.SetChangedFunc(func(index int, _, _ string, _ rune) {
		if index < 0 || index >= len(s.pendingIDs) {
			return
		}
		s.selectedPending = s.pendingIDs[index]
		s.refreshDetails(s.selectedPending)
	})

	s.pendingList.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Rune() == '/' {
			app.SetFocus(s.filter)
			return nil
		}
		switch ev.Rune() {
		case 'a':
			s.doDecision("ALLOW_ONCE")
			return nil
		case 's':
			s.doDecision("ALLOW_SESSION")
			return nil
		case 'A':
			s.doDecision("ALLOW_ALWAYS")
			return nil
		case 'd':
			s.doDecision("DENY")
			return nil
		}
		return ev
	})

	s.jobsList.SetChangedFunc(func(index int, _, _ string, _ rune) {
		if index < 0 || index >= len(s.jobIDs) {
			s.selectedJob = ""
			return
		}
		s.selectedJob = s.jobIDs[index]
	})

	s.jobsList.SetSelectedFunc(func(_ int, _ string, _ string, _ rune) {
		id := s.selectedJob
		if id == "" {
			return
		}
		s.openJobPage(app, pages, cfg, id)
	})

	s.focus = []tview.Primitive{s.pendingList, s.details, s.jobsList}
	s.setCurrentPage("dashboard")
	s.refresh()
	return root
}

func (s *uiState) doDecision(dec string) {
	if s.selectedPending == "" {
		return
	}
	_ = s.api.DecideForTUI(s.selectedPending, dec)
	s.selectedPending = ""
	s.refresh()
}

func buildJobPage(app *tview.Application, pages *tview.Pages, s *uiState, cfg ServeUIConfig, requestID string) tview.Primitive {
	s.selectedJob = requestID
	activeRequestID := requestID
	s.jobHeader = tview.NewTextView().SetDynamicColors(false)
	s.jobLog = tview.NewTextView().SetDynamicColors(false).SetScrollable(true)
	s.follow = true
	tabs := tview.NewTextView().SetDynamicColors(false).SetTextAlign(tview.AlignLeft)
	tabs.SetText(s.renderJobTabs(activeRequestID))

	btnKill := tview.NewButton("Kill").SetSelectedFunc(func() {
		m := tview.NewModal().
			SetText("Kill selected job?").
			AddButtons([]string{"Cancel", "Kill"}).
			SetDoneFunc(func(ix int, _ string) {
				pages.RemovePage("confirm_kill")
				if ix == 1 {
					_ = cfg.API.KillForTUI(activeRequestID)
				}
			})
		pages.AddPage("confirm_kill", m, true, true)
	})
	toggleFollow := func() {
		s.follow = !s.follow
	}
	btnFollow := tview.NewButton("Toggle follow").SetSelectedFunc(toggleFollow)

	back := func() {
		pages.RemovePage("job")
		pages.ShowPage("dashboard")
		s.setCurrentPage("dashboard")
		s.refresh()
		app.SetFocus(s.jobsList)
	}
	btnBack := tview.NewButton("Back").SetSelectedFunc(back)
	btns := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(btnKill, 0, 1, false).
		AddItem(btnFollow, 0, 1, false).
		AddItem(btnBack, 0, 1, false)

	header := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tabs, 1, 0, false).
		AddItem(s.jobHeader, 1, 0, false).
		AddItem(btns, 1, 0, true)
	log := s.jobLog
	log.SetBorder(true).SetTitle("Output")

	combined, _ := cfg.API.GetLiveJobOutput(activeRequestID)
	log.SetText(combined)
	log.ScrollToEnd()
	s.refreshJobHeader(activeRequestID)

	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(header, 2, 0, true).
		AddItem(log, 0, 1, true)

	root.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyEsc:
			back()
			return nil
		}
		if ev.Modifiers()&tcell.ModAlt != 0 {
			switch ev.Rune() {
			case '1', '2', '3', '4', '5', '6', '7', '8', '9':
				n := int(ev.Rune() - '0')
				if id := s.nthJobID(n); id != "" {
					s.openJobPage(app, pages, cfg, id)
				}
				return nil
			}
		}
		switch ev.Rune() {
		case 'f':
			toggleFollow()
			return nil
		case '[':
			if id := s.nextJobID(-1); id != "" {
				s.openJobPage(app, pages, cfg, id)
			}
			return nil
		case ']':
			if id := s.nextJobID(1); id != "" {
				s.openJobPage(app, pages, cfg, id)
			}
			return nil
		}
		return ev
	})

	return root
}

func buildHelpModal(pages *tview.Pages, s *uiState) tview.Primitive {
	m := tview.NewModal().
		SetText("Keys:\n  Tab focus\n  a once / s session / A always / d deny\n  r rules / h history\n  Esc back / q quit\n  F1 or ? help\n").
		AddButtons([]string{"Close"}).
		SetDoneFunc(func(_ int, _ string) {
			pages.HidePage("help")
			if s.overlayClose != nil {
				s.overlayClose = nil
			}
		})
	return m
}

func buildRulesPage(app *tview.Application, pages *tview.Pages, s *uiState, cfg ServeUIConfig) tview.Primitive {
	table := tview.NewTable().SetSelectable(true, false)
	details := tview.NewTextView().SetScrollable(true)
	var selectedRuleID string
	var selectedRuleEnabled bool

	refresh := func() {
		table.Clear()
		table.SetCell(0, 0, tview.NewTableCell("enabled"))
		table.SetCell(0, 1, tview.NewTableCell("id"))
		table.SetCell(0, 2, tview.NewTableCell("op"))
		table.SetCell(0, 3, tview.NewTableCell("scope"))
		if cfg.Store == nil {
			return
		}
		rows, err := cfg.Store.ListRules(context.Background(), 1000)
		if err != nil {
			details.SetText("error: " + err.Error())
			return
		}
		for i, r := range rows {
			en := "0"
			if r.Enabled {
				en = "1"
			}
			scope := ""
			if r.PathExact != nil {
				scope = "path=" + *r.PathExact
			}
			table.SetCell(i+1, 0, tview.NewTableCell(en))
			table.SetCell(i+1, 1, tview.NewTableCell(r.RuleID))
			table.SetCell(i+1, 2, tview.NewTableCell(r.OpType))
			table.SetCell(i+1, 3, tview.NewTableCell(scope))
		}
	}
	refresh()
	s.rulesRefresh = refresh

	table.SetSelectedFunc(func(row, _ int) {
		if row <= 0 {
			return
		}
		id := table.GetCell(row, 1).Text
		selectedRuleID = id
		selectedRuleEnabled = table.GetCell(row, 0).Text == "1"
		details.SetText(fmt.Sprintf("rule_id=%s\nenabled=%v\n", id, selectedRuleEnabled))
	})

	btnToggle := tview.NewButton("Enable/Disable").SetSelectedFunc(func() {
		if cfg.Store == nil || selectedRuleID == "" {
			return
		}
		if selectedRuleEnabled {
			_ = cfg.Store.DisableRule(context.Background(), selectedRuleID, time.Now().UTC())
		} else {
			_ = cfg.Store.EnableRule(context.Background(), selectedRuleID)
		}
		refresh()
	})

	btnDelete := tview.NewButton("Delete").SetSelectedFunc(func() {
		if cfg.Store == nil || selectedRuleID == "" {
			return
		}
		m := tview.NewModal().
			SetText("Delete rule " + selectedRuleID + "?").
			AddButtons([]string{"Cancel", "Delete"}).
			SetDoneFunc(func(ix int, _ string) {
				pages.RemovePage("confirm_delete_rule")
				if ix == 1 {
					_ = cfg.Store.DeleteRule(context.Background(), selectedRuleID)
					selectedRuleID = ""
					refresh()
				}
			})
		pages.AddPage("confirm_delete_rule", m, true, true)
	})

	back := func() {
		s.showDashboard(app, pages)
	}
	btnBack := tview.NewButton("Back").SetSelectedFunc(back)

	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tview.NewFlex().SetDirection(tview.FlexColumn).
			AddItem(table.SetBorder(true).SetTitle("Rules"), 0, 2, true).
			AddItem(details.SetBorder(true).SetTitle("Details"), 0, 3, false), 0, 1, true).
		AddItem(tview.NewFlex().SetDirection(tview.FlexColumn).
			AddItem(btnToggle, 0, 1, false).
			AddItem(btnDelete, 0, 1, false).
			AddItem(btnBack, 0, 1, true), 1, 0, true)

	root.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEsc {
			back()
			return nil
		}
		return ev
	})
	return root
}

func buildHistoryPage(app *tview.Application, pages *tview.Pages, s *uiState, cfg ServeUIConfig) tview.Primitive {
	table := tview.NewTable().SetSelectable(true, false)
	details := tview.NewTextView().SetScrollable(true)

	refresh := func() {
		table.Clear()
		table.SetCell(0, 0, tview.NewTableCell("session_id"))
		table.SetCell(0, 1, tview.NewTableCell("started_at"))
		if cfg.Store == nil {
			return
		}
		ss, err := cfg.Store.ListSessions(context.Background(), 100)
		if err != nil {
			details.SetText("error: " + err.Error())
			return
		}
		for i, sess := range ss {
			table.SetCell(i+1, 0, tview.NewTableCell(sess.ID))
			table.SetCell(i+1, 1, tview.NewTableCell(sess.StartedAt.UTC().Format(time.RFC3339)))
		}
	}
	refresh()
	s.historyRefresh = refresh

	back := func() {
		s.showDashboard(app, pages)
	}
	btnBack := tview.NewButton("Back").SetSelectedFunc(back)

	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tview.NewFlex().SetDirection(tview.FlexColumn).
			AddItem(table.SetBorder(true).SetTitle("Sessions"), 0, 2, true).
			AddItem(details.SetBorder(true).SetTitle("Details"), 0, 3, false), 0, 1, true).
		AddItem(btnBack, 1, 0, true)

	root.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEsc {
			back()
			return nil
		}
		return ev
	})
	return root
}

func trimTime(ts string) string {
	if len(ts) >= 19 {
		return ts[11:19]
	}
	return ts
}

func formatMMSS(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	sec := int(d.Seconds())
	return fmt.Sprintf("%02d:%02d", sec/60, sec%60)
}
