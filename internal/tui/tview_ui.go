package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/itolstov/racg/internal/httpapi"
	"github.com/itolstov/racg/internal/outputfilter"
	"github.com/itolstov/racg/internal/rules"
	"github.com/itolstov/racg/internal/store"
)

type ServeUIConfig struct {
	Version  string
	Listen   string
	DBPath   string
	Profile  string
	Hostname string
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
	state.app = app
	state.titleUpdater = newTerminalTitleUpdater(ctx, time.Second, func(title string) {
		app.SetTitle(title)
	})
	state.refreshTerminalTitle(cfg)

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

	// Initial visible page is pairing; dashboard builder sets focus/defaults but
	// should not affect current page state used by auto-switch logic.
	state.setCurrentPage("pairing")
	state.setActiveMainTab("server")

	app.SetRoot(pages, true)

	app.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		return state.handleGlobalInput(app, pages, cfg, ev)
	})
	app.SetMouseCapture(func(ev *tcell.EventMouse, action tview.MouseAction) (*tcell.EventMouse, tview.MouseAction) {
		if ev != nil && inputEventIsStale(ev.When(), time.Now(), maxInputEventAge) {
			return nil, action
		}
		return ev, action
	})

	// Drain API events immediately, then render their latest state at a bounded rate.
	evCh, cancel := cfg.API.SubscribeEvents(256)
	defer cancel()
	coalescer := newUIEventCoalescer()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case e, ok := <-evCh:
				if !ok {
					return
				}
				coalescer.Add(e)
			}
		}
	}()

	go func() {
		tick := time.NewTicker(uiRefreshInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				app.QueueUpdateDraw(func() { app.Stop() })
				return
			case <-tick.C:
				batch, dirty := coalescer.Take()
				if !dirty {
					continue
				}
				app.QueueUpdateDraw(func() {
					state.applyEventBatch(batch)
					state.refresh()
					state.refreshTerminalTitle(cfg)
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
	app   *tview.Application

	mu sync.Mutex

	page string

	// Dashboard widgets.
	mainTabs     []*tview.TextView
	pendingList  *tview.List
	filter       *tview.InputField
	details      *tview.TextView
	jobsList     *tview.List
	statusBars   []*tview.TextView
	jobsModeBtn  *tview.Button
	titleUpdater *terminalTitleUpdater

	// Job view widgets.
	jobHeader *tview.TextView
	jobLog    *tview.TextView
	jobTabs   *tview.TextView
	jobMode   string
	follow    bool

	// Focus cycle order.
	focus []tview.Primitive

	// Selected IDs.
	selectedPending    string
	pendingDetailsID   string
	pendingDetailsText string
	selectedJob        string
	pendingIDs         []string
	jobIDs             []string
	jobListSig         string
	showAllJobs        bool
	activeMainTab      string
	pairingAutoSwitch  bool
	serverFocus        tview.Primitive

	// Optional page refresh hooks (for non-dashboard pages).
	rulesRefresh   func()
	historyRefresh func()
	pairingRefresh func()

	// Last toast.
	toastUntil time.Time
	toastText  string

	decisionRunner   func(string, string) error
	decisionInFlight bool
	decisionGuardTil time.Time

	// Overlay (e.g. copy mode) close handler.
	overlayClose func()
}

func newUIState(api *httpapi.API, st *store.Store) *uiState {
	s := &uiState{api: api, store: st, follow: true, page: "pairing", showAllJobs: true, activeMainTab: "server", pairingAutoSwitch: true, jobMode: "combined"}
	if api != nil {
		s.decisionRunner = api.DecideForTUI
	}
	return s
}

func (s *uiState) setCurrentPage(p string) {
	s.mu.Lock()
	s.page = p
	s.mu.Unlock()
}

func (s *uiState) currentPage() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.page
}

func (s *uiState) handleGlobalInput(app *tview.Application, pages *tview.Pages, cfg ServeUIConfig, ev *tcell.EventKey) *tcell.EventKey {
	if ev == nil || inputEventIsStale(ev.When(), time.Now(), maxInputEventAge) {
		return nil
	}
	if ev.Key() == tcell.KeyEsc {
		if s.closeOverlay(pages) {
			return nil
		}
	}
	if s.overlayClose != nil {
		return ev
	}
	switch ev.Key() {
	case tcell.KeyTAB:
		s.cycleFocus(app)
		return nil
	case tcell.KeyF1:
		s.openHelp(app, pages)
		return nil
	case tcell.KeyEsc:
		s.back(app, pages)
		return nil
	}
	if s.currentPage() != "job" {
		switch ev.Rune() {
		case '0':
			s.showServer(app, pages)
			return nil
		case '1':
			s.showDashboard(app, pages)
			return nil
		case '2':
			s.showDashboard(app, pages)
			if s.jobsList != nil {
				app.SetFocus(s.jobsList)
			}
			return nil
		case '3':
			s.showRules(app, pages)
			return nil
		case '4':
			s.showHistory(app, pages)
			return nil
		}
	}
	if s.currentPage() == "dashboard" && (app == nil || app.GetFocus() != s.filter) {
		if s.handlePendingActionHotkey(app, pages, ev) {
			return nil
		}
	}
	switch hotkeyRune(ev.Rune()) {
	case 'q':
		if cfg.ExitFunc != nil {
			cfg.ExitFunc()
		}
		if app != nil {
			app.Stop()
		}
		return nil
	}
	return ev
}

func (s *uiState) handlePendingActionHotkey(app *tview.Application, pages *tview.Pages, ev *tcell.EventKey) bool {
	switch hotkeyRune(ev.Rune()) {
	case 'a':
		if unicode.IsUpper(ev.Rune()) {
			s.openRuleScopeOverlay(app, pages, "ALLOW_ALWAYS")
		} else {
			s.doDecision("ALLOW_ONCE")
		}
		return true
	case 's':
		s.openRuleScopeOverlay(app, pages, "ALLOW_SESSION")
		return true
	case 'd':
		s.doDecision("DENY")
		return true
	default:
		return false
	}
}

func (s *uiState) refreshTerminalTitle(cfg ServeUIConfig) {
	if s.titleUpdater == nil || s.api == nil {
		return
	}
	pending := len(s.api.ListPendingForTUI())
	running := len(s.api.ListRunningForTUI())
	s.titleUpdater.Update(terminalTitle(cfg.Version, serverIdentity(cfg.Profile, cfg.Hostname, cfg.Listen), pending, running, 0))
}

type terminalTitleUpdater struct {
	updates chan string
}

func newTerminalTitleUpdater(ctx context.Context, cooldown time.Duration, setTitle func(string)) *terminalTitleUpdater {
	u := &terminalTitleUpdater{updates: make(chan string, 1)}
	go func() {
		last := ""
		for {
			var title string
			select {
			case <-ctx.Done():
				return
			case title = <-u.updates:
			}
			if title == last {
				continue
			}
			setTitle(title)
			last = title

			timer := time.NewTimer(cooldown)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-timer.C:
			}
		}
	}()
	return u
}

func (u *terminalTitleUpdater) Update(title string) {
	select {
	case u.updates <- title:
		return
	default:
	}
	select {
	case <-u.updates:
	default:
	}
	select {
	case u.updates <- title:
	default:
	}
}

func terminalTitle(version, identity string, pending, running, frame int) string {
	_ = frame
	base := fmt.Sprintf("RACG v%s", version)
	if identity != "" {
		base += " · " + identity
	}
	if pending == 0 && running == 0 {
		return base
	}
	if pending > 0 {
		title := fmt.Sprintf("[APPROVAL %d] %s", pending, base)
		if running > 0 {
			title += fmt.Sprintf(" · running=%d", running)
		}
		return title
	}
	return fmt.Sprintf("[RUN %d] %s", running, base)
}

func serverIdentity(profile, hostname, listen string) string {
	endpoint := strings.TrimSpace(listen)
	if host := strings.TrimSpace(hostname); host != "" {
		if _, port, err := net.SplitHostPort(endpoint); err == nil && port != "" {
			endpoint = net.JoinHostPort(host, port)
		} else {
			endpoint = host
		}
	}
	if profile = strings.TrimSpace(profile); profile != "" {
		if endpoint == "" {
			return profile
		}
		return profile + " @ " + endpoint
	}
	return endpoint
}

func serverInfoText(cfg ServeUIConfig) string {
	listen := strings.TrimSpace(cfg.Listen)
	if listen != "" && !strings.Contains(listen, "://") {
		listen = "http://" + listen
	}
	profile := strings.TrimSpace(cfg.Profile)
	if profile == "" {
		profile = "(default)"
	}
	return fmt.Sprintf("RACG serve v%s\nidentity: %s\nhostname: %s\nprofile: %s\nlistening: %s\ndb: %s\n",
		cfg.Version,
		serverIdentity(cfg.Profile, cfg.Hostname, cfg.Listen),
		cfg.Hostname,
		profile,
		listen,
		cfg.DBPath,
	)
}

func hotkeyRune(r rune) rune {
	r = unicode.ToLower(r)
	switch r {
	case 'й':
		return 'q'
	case 'ц':
		return 'w'
	case 'у':
		return 'e'
	case 'к':
		return 'r'
	case 'е':
		return 't'
	case 'н':
		return 'y'
	case 'г':
		return 'u'
	case 'ш':
		return 'i'
	case 'щ':
		return 'o'
	case 'з':
		return 'p'
	case 'ф':
		return 'a'
	case 'ы':
		return 's'
	case 'в':
		return 'd'
	case 'а':
		return 'f'
	case 'п':
		return 'g'
	case 'р':
		return 'h'
	case 'о':
		return 'j'
	case 'л':
		return 'k'
	case 'д':
		return 'l'
	case 'я':
		return 'z'
	case 'ч':
		return 'x'
	case 'с':
		return 'c'
	case 'м':
		return 'v'
	case 'и':
		return 'b'
	case 'т':
		return 'n'
	case 'ь':
		return 'm'
	default:
		return r
	}
}

func (s *uiState) switchMainPage(pages *tview.Pages, name string) {
	if pages == nil {
		return
	}
	s.closeOverlay(pages)
	for _, p := range []string{"pairing", "dashboard", "rules", "history", "help", "copy", "confirm_kill", "rule_scope"} {
		pages.HidePage(p)
	}
	pages.ShowPage(name)
	pages.SendToFront(name)
}

func (s *uiState) renderMainTabs() string {
	type tab struct {
		page  string
		key   string
		name  string
		label string
	}
	tabs := []tab{
		{page: "pairing", key: "0", name: "server", label: "Server"},
		{page: "dashboard", key: "1", name: "pending", label: "Pending"},
		{page: "dashboard", key: "2", name: "jobs", label: "Jobs"},
		{page: "rules", key: "3", name: "rules", label: "Rules"},
		{page: "history", key: "4", name: "history", label: "History"},
	}
	var b strings.Builder
	for i, t := range tabs {
		if i > 0 {
			b.WriteString("   ")
		}
		text := t.key + " " + t.label
		if s.activeMainTab == t.name || (s.activeMainTab == "" && s.currentPage() == t.page && t.name != "jobs") {
			b.WriteString("[" + text + "]")
			continue
		}
		b.WriteString(text)
	}
	return b.String()
}

func (s *uiState) setActiveMainTab(name string) {
	s.activeMainTab = name
	s.refreshMainTabs()
}

func (s *uiState) refreshMainTabs() {
	for _, tabs := range s.mainTabs {
		if tabs != nil {
			tabs.SetText(s.renderMainTabs())
		}
	}
}

func (s *uiState) buildMainTabs(app *tview.Application, pages *tview.Pages) *tview.TextView {
	tabs := tview.NewTextView().SetDynamicColors(false).SetTextAlign(tview.AlignLeft)
	tabs.SetText(s.renderMainTabs())
	tabs.SetMouseCapture(func(action tview.MouseAction, event *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
		if action != tview.MouseLeftClick {
			return action, event
		}
		x, y := event.Position()
		if !tabs.InRect(x, y) {
			return action, event
		}
		rectX, _, _, _ := tabs.GetRect()
		switch mainTabAt(x-rectX, tabs.GetText(false)) {
		case "server":
			s.showServer(app, pages)
		case "pending":
			s.showDashboard(app, pages)
		case "jobs":
			s.switchMainPage(pages, "dashboard")
			s.setCurrentPage("dashboard")
			s.setActiveMainTab("jobs")
			s.refresh()
			if app != nil && s.jobsList != nil {
				app.SetFocus(s.jobsList)
			}
		case "rules":
			s.showRules(app, pages)
		case "history":
			s.showHistory(app, pages)
		default:
			return action, event
		}
		return tview.MouseConsumed, nil
	})
	s.mainTabs = append(s.mainTabs, tabs)
	return tabs
}

func mainTabAt(x int, text string) string {
	if x < 0 {
		return ""
	}
	for _, tab := range []struct {
		name  string
		label string
	}{
		{name: "server", label: "0 Server"},
		{name: "pending", label: "1 Pending"},
		{name: "jobs", label: "2 Jobs"},
		{name: "rules", label: "3 Rules"},
		{name: "history", label: "4 History"},
	} {
		start := strings.Index(text, tab.label)
		if start < 0 {
			continue
		}
		end := start + len(tab.label)
		if start > 0 && text[start-1] == '[' {
			start--
		}
		if end < len(text) && text[end] == ']' {
			end++
		}
		if x >= start && x < end {
			return tab.name
		}
	}
	return ""
}

func pendingActionHint() string {
	return "Actions: a once | s session | A always | d deny | mouse"
}

func jobViewModeLabel(mode string) string {
	modes := []string{"combined", "stdout", "stderr", "meta"}
	labels := map[string]string{"combined": "Combined", "stdout": "stdout", "stderr": "stderr", "meta": "meta"}
	var b strings.Builder
	for i, m := range modes {
		if i > 0 {
			b.WriteString(" ")
		}
		label := labels[m]
		if mode == m {
			b.WriteString("[" + label + "]")
		} else {
			b.WriteString(label)
		}
	}
	return b.String()
}

func jobFollowLabel(follow bool) string {
	if follow {
		return "Follow: on"
	}
	return "Follow: off"
}

func jobHeaderText(info httpapi.TUIRequestInfo, follow bool) string {
	exitCode := ""
	if info.Result != nil {
		exitCode = fmt.Sprintf("  exit_code=%d  duration_ms=%d", info.Result.ExitCode, info.Result.DurationMs)
	}
	header := fmt.Sprintf("job: %s  status=%s%s  follow=%s  client=%s", info.ID, info.Status, exitCode, boolLabel(follow), info.ClientID)
	if strings.TrimSpace(info.Summary) != "" {
		header += "\ncmd: " + info.Summary
	}
	return header
}

func boolLabel(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

func (s *uiState) showDashboard(app *tview.Application, pages *tview.Pages) {
	s.closeOverlay(pages)
	s.switchMainPage(pages, "dashboard")
	s.setCurrentPage("dashboard")
	s.setActiveMainTab("pending")
	s.refresh()
	if app != nil {
		s.cycleFocusTo(app, s.pendingList)
	}
}

func (s *uiState) showServer(app *tview.Application, pages *tview.Pages) {
	s.closeOverlay(pages)
	s.switchMainPage(pages, "pairing")
	s.setCurrentPage("pairing")
	s.setActiveMainTab("server")
	s.pairingAutoSwitch = false
	if s.pairingRefresh != nil {
		s.pairingRefresh()
	}
	if app != nil && s.serverFocus != nil {
		app.SetFocus(s.serverFocus)
	}
}

func (s *uiState) maybeAutoSwitchToDashboard(app *tview.Application, pages *tview.Pages, pendingCount int) bool {
	if s.currentPage() != "pairing" || !s.pairingAutoSwitch || pendingCount <= 0 {
		return false
	}
	s.showDashboard(app, pages)
	return true
}

func (s *uiState) showRules(app *tview.Application, pages *tview.Pages) {
	s.closeOverlay(pages)
	s.switchMainPage(pages, "rules")
	s.setCurrentPage("rules")
	s.setActiveMainTab("rules")
	if s.rulesRefresh != nil {
		s.rulesRefresh()
	}
}

func (s *uiState) showHistory(app *tview.Application, pages *tview.Pages) {
	s.closeOverlay(pages)
	s.switchMainPage(pages, "history")
	s.setCurrentPage("history")
	s.setActiveMainTab("history")
	if s.historyRefresh != nil {
		s.historyRefresh()
	}
}

func (s *uiState) back(app *tview.Application, pages *tview.Pages) {
	page := s.currentPage()
	if page == "dashboard" || page == "pairing" {
		return
	}
	if page == "job" {
		s.leaveJobPage(app, pages, s.jobsList)
		return
	}
	s.showDashboard(app, pages)
}

func (s *uiState) leaveJobPage(app *tview.Application, pages *tview.Pages, focus tview.Primitive) {
	s.closeOverlay(pages)
	if pages != nil {
		// Keep a normal page visible before removing "job". tview otherwise
		// auto-shows the last remaining page, which is the hidden help overlay.
		pages.ShowPage("dashboard")
		pages.RemovePage("job")
		pages.HidePage("help")
		pages.SendToFront("dashboard")
	}
	s.setCurrentPage("dashboard")
	s.setActiveMainTab("jobs")
	s.refresh()
	if app != nil && focus != nil {
		app.SetFocus(focus)
	}
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

func (s *uiState) closeOverlay(pages *tview.Pages) bool {
	closed := false
	if s.overlayClose != nil {
		close := s.overlayClose
		close()
		closed = true
	}
	if pages != nil {
		if pageVisible(pages, "help") {
			pages.HidePage("help")
			closed = true
		}
		if pageVisible(pages, "copy") {
			pages.RemovePage("copy")
			closed = true
		}
		if pageVisible(pages, "confirm_kill") {
			pages.RemovePage("confirm_kill")
			closed = true
		}
		if pageVisible(pages, "rule_scope") {
			pages.RemovePage("rule_scope")
			closed = true
		}
	}
	return closed
}

func pageVisible(pages *tview.Pages, name string) bool {
	for _, visible := range pages.GetPageNames(true) {
		if visible == name {
			return true
		}
	}
	return false
}

func (s *uiState) openHelp(app *tview.Application, pages *tview.Pages) {
	s.closeOverlay(pages)
	var prevFocus tview.Primitive
	if app != nil {
		prevFocus = app.GetFocus()
	}
	pages.ShowPage("help")
	pages.SendToFront("help")
	if app != nil {
		if p := pages.GetPage("help"); p != nil {
			app.SetFocus(p)
		}
	}
	s.overlayClose = func() {
		pages.HidePage("help")
		s.overlayClose = nil
		if app != nil && prevFocus != nil {
			app.SetFocus(prevFocus)
		}
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

func centered(p tview.Primitive, width int, height int) tview.Primitive {
	return tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(nil, 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexColumn).
			AddItem(nil, 0, 1, false).
			AddItem(p, width, 0, true).
			AddItem(nil, 0, 1, false), height, 0, true).
		AddItem(nil, 0, 1, false)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
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
	s.jobListSig = ""
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

func (s *uiState) applyEventBatch(batch uiEventBatch) {
	if batch.LatestCreated == nil {
		return
	}
	s.toastText = fmt.Sprintf("New request from %s", batch.LatestCreated.ClientID)
	s.toastUntil = time.Now().Add(3 * time.Second)
}

func (s *uiState) refresh() {
	s.refreshMainTabs()
	if s.pendingList != nil {
		s.refreshPending()
	}
	if s.jobsList != nil {
		s.refreshJobs()
	}
	s.refreshStatus()
	if s.details != nil && s.selectedPending != "" {
		s.refreshDetails(s.selectedPending)
	}
	if s.jobHeader != nil && s.selectedJob != "" {
		s.refreshJobHeader(s.selectedJob)
	}
	if s.jobLog != nil && s.selectedJob != "" {
		s.refreshJobLog(s.selectedJob)
	}
}

func (s *uiState) refreshStatus() {
	for _, statusBar := range s.statusBars {
		s.refreshStatusBar(statusBar)
	}
}

func (s *uiState) refreshStatusBar(statusBar *tview.TextView) {
	if statusBar == nil || s.api == nil {
		return
	}
	pn := len(s.api.ListPendingForTUI())
	rn := len(s.api.ListRunningForTUI())
	line := fmt.Sprintf("F1 help | 0 server | 1 pending | 2 jobs | 3 rules | 4 history | Esc back | q quit   pending=%d running=%d", pn, rn)
	if time.Now().Before(s.toastUntil) && s.toastText != "" {
		line = s.toastText + "   |   " + line
	}
	statusBar.SetText(line)
}

func (s *uiState) buildStatusBar() *tview.TextView {
	statusBar := tview.NewTextView().SetDynamicColors(false)
	s.statusBars = append(s.statusBars, statusBar)
	s.refreshStatusBar(statusBar)
	return statusBar
}

func (s *uiState) refreshPending() {
	filter := strings.TrimSpace(s.filter.GetText())
	items := s.api.ListPendingForTUI()
	prevSelectedID := s.selectedPending
	prevIndex := s.pendingList.GetCurrentItem()

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
	idx := pendingSelectionIndex(s.pendingIDs, prevSelectedID, prevIndex)
	if idx < 0 {
		s.selectedPending = ""
		s.details.SetText("")
		return
	}
	s.selectedPending = s.pendingIDs[idx]
	s.pendingList.SetCurrentItem(idx)
}

func pendingSelectionIndex(ids []string, prevSelectedID string, prevIndex int) int {
	if len(ids) == 0 {
		return -1
	}
	if prevSelectedID != "" {
		for i, id := range ids {
			if id == prevSelectedID {
				return i
			}
		}
	}
	if prevIndex >= 0 && prevIndex < len(ids) {
		return prevIndex
	}
	return 0
}

func (s *uiState) refreshDetails(requestID string) {
	text, ok := s.cachedPendingDetails(requestID, func() (string, bool) {
		info, found := s.api.GetRequestInfoForTUI(requestID)
		if !found {
			return "", false
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
		return b.String(), true
	})
	if !ok {
		s.details.SetText("")
		return
	}
	s.details.SetText(text)
}

func (s *uiState) cachedPendingDetails(requestID string, load func() (string, bool)) (string, bool) {
	if requestID == s.pendingDetailsID {
		return s.pendingDetailsText, true
	}
	text, ok := load()
	if !ok {
		return "", false
	}
	s.pendingDetailsID = requestID
	s.pendingDetailsText = text
	return text, true
}

func (s *uiState) refreshJobs() {
	items := s.api.ListJobsForTUI(s.showAllJobs)
	sig := jobListSignature(s.showAllJobs, items)
	if sig == s.jobListSig {
		return
	}
	prevIndex := s.jobsList.GetCurrentItem()
	s.jobsList.Clear()
	s.jobIDs = s.jobIDs[:0]
	for _, it := range items {
		label := fmt.Sprintf("%s · %-7s · %s", trimTime(it.CreatedAt), shortStatus(it.Status), it.Summary)
		s.jobIDs = append(s.jobIDs, it.ID)
		s.jobsList.AddItem(label, it.ClientID, 0, nil)
	}
	if len(s.jobIDs) == 0 {
		s.selectedJob = ""
		s.jobListSig = sig
		return
	}
	idx := jobSelectionIndex(s.jobIDs, s.selectedJob, prevIndex)
	s.selectedJob = s.jobIDs[idx]
	s.jobsList.SetCurrentItem(idx)
	s.jobListSig = sig
}

func jobListSignature(showAll bool, items []httpapi.TUIRequest) string {
	var b strings.Builder
	if showAll {
		b.WriteString("all")
	} else {
		b.WriteString("running")
	}
	b.WriteByte('\x00')
	for _, it := range items {
		b.WriteString(it.ID)
		b.WriteByte('\x00')
		b.WriteString(it.Status)
		b.WriteByte('\x00')
		b.WriteString(it.CreatedAt)
		b.WriteByte('\x00')
		b.WriteString(it.ClientID)
		b.WriteByte('\x00')
		b.WriteString(it.Summary)
		b.WriteByte('\x00')
	}
	return b.String()
}

func jobSelectionIndex(ids []string, prevSelectedID string, prevIndex int) int {
	if len(ids) == 0 {
		return -1
	}
	if prevSelectedID != "" {
		for i, id := range ids {
			if id == prevSelectedID {
				return i
			}
		}
	}
	if prevIndex >= 0 && prevIndex < len(ids) {
		return prevIndex
	}
	return 0
}

func (s *uiState) refreshJobHeader(requestID string) {
	info, ok := s.api.GetRequestInfoForTUI(requestID)
	if !ok {
		s.jobHeader.SetText("")
		return
	}
	s.jobHeader.SetText(jobHeaderText(info, s.follow))
}

func (s *uiState) refreshJobLog(requestID string) {
	if s.jobLog == nil || s.api == nil {
		return
	}
	if s.jobTabs != nil {
		s.jobTabs.SetText("Streams: " + jobViewModeLabel(s.jobMode) + "    keys: 1 combined 2 stdout 3 stderr 4 meta | k kill | f follow | Esc/b back")
	}
	info, ok := s.api.GetRequestInfoForTUI(requestID)
	if !ok {
		s.jobLog.SetText("")
		return
	}
	combined, truncated := s.api.GetLiveJobOutput(requestID)
	text := jobViewText(s.jobMode, info, combined, truncated)
	s.jobLog.SetText(text)
	if s.follow {
		s.jobLog.ScrollToEnd()
	}
}

func buildPairingPage(ctx context.Context, app *tview.Application, pages *tview.Pages, s *uiState, cfg ServeUIConfig) tview.Primitive {
	title := tview.NewTextView().SetDynamicColors(false).SetTextAlign(tview.AlignLeft)
	code := tview.NewTextView().SetDynamicColors(false).SetTextAlign(tview.AlignLeft)
	meta := tview.NewTextView().SetDynamicColors(false).SetTextAlign(tview.AlignLeft)

	goDashboard := func() {
		s.showDashboard(app, pages)
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
		s.openCopyOverlay(app, pages, "Pairing Info", PairingCopyText(listenURL, pc, cfg.Version))
	}
	btnCopy := tview.NewButton("Copy").SetSelectedFunc(copy)

	btns := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(btnDash, 0, 1, false).
		AddItem(btnCopy, 0, 1, false).
		AddItem(btnRegen, 0, 1, false).
		AddItem(btnQuit, 0, 1, false)

	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(s.buildMainTabs(app, pages), 1, 0, false).
		AddItem(title, 6, 0, false).
		AddItem(code, 4, 0, false).
		AddItem(meta, 0, 1, false).
		AddItem(btns, 1, 0, true)

	refresh := func() {
		title.SetText(serverInfoText(cfg))
		pc := cfg.API.PairingCode()
		code.SetText("PAIRING CODE:\n" + pc + "\n\nRACG_CODE=" + pc + "\nopen_session --code " + pc + "\n")
		meta.SetText(fmt.Sprintf("expires in %s\npending=%d  running=%d\n",
			formatMMSS(cfg.API.PairingExpiresIn()),
			len(cfg.API.ListPendingForTUI()),
			len(cfg.API.ListRunningForTUI()),
		))
	}
	s.pairingRefresh = refresh
	refresh()

	// Pairing page-specific keys.
	root.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyEnter:
			goDashboard()
			return nil
		}
		switch hotkeyRune(ev.Rune()) {
		case 'r':
			regen()
			return nil
		case 'c':
			copy()
			return nil
		}
		return ev
	})

	// Pairing metadata changes with time, but only needs redraws while visible.
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if s.currentPage() != "pairing" {
					continue
				}
				app.QueueUpdateDraw(refresh)
			}
		}
	}()

	s.setCurrentPage("pairing")
	s.serverFocus = btnDash
	s.focus = []tview.Primitive{btnDash, btnCopy, btnRegen, btnQuit}
	return root
}

func buildDashboardPage(app *tview.Application, pages *tview.Pages, s *uiState, cfg ServeUIConfig) tview.Primitive {
	s.filter = tview.NewInputField().SetLabel("filter: ")
	s.pendingList = tview.NewList().ShowSecondaryText(false)
	s.details = tview.NewTextView().SetDynamicColors(true).SetScrollable(true)
	s.jobsList = tview.NewList().ShowSecondaryText(true)
	s.jobsModeBtn = tview.NewButton("").SetSelectedFunc(func() {
		s.toggleJobsMode()
		s.setActiveMainTab("jobs")
		app.SetFocus(s.jobsList)
	})
	s.setJobsModeLabel()

	s.filter.SetChangedFunc(func(text string) { s.refreshPending() })
	s.filter.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			app.SetFocus(s.pendingList)
		}
	})
	s.filter.SetFocusFunc(func() { s.setActiveMainTab("pending") })
	s.pendingList.SetFocusFunc(func() { s.setActiveMainTab("pending") })
	s.details.SetFocusFunc(func() { s.setActiveMainTab("pending") })
	s.jobsList.SetFocusFunc(func() { s.setActiveMainTab("jobs") })
	s.jobsModeBtn.SetFocusFunc(func() { s.setActiveMainTab("jobs") })

	left := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(s.filter, 1, 0, false).
		AddItem(s.pendingList, 0, 1, true)
	left.SetBorder(true).SetTitle("Pending approvals")

	center := tview.NewFlex().SetDirection(tview.FlexRow)
	center.SetBorder(true).SetTitle("Request details")
	center.AddItem(s.details, 0, 1, false)
	actionHint := tview.NewTextView().SetDynamicColors(false).SetText(pendingActionHint())
	center.AddItem(actionHint, 1, 0, false)

	btnOnce := tview.NewButton("Allow once").SetSelectedFunc(func() { s.doDecision("ALLOW_ONCE") })
	btnSess := tview.NewButton("Allow session").SetSelectedFunc(func() { s.openRuleScopeOverlay(app, pages, "ALLOW_SESSION") })
	btnAlways := tview.NewButton("Allow always").SetSelectedFunc(func() { s.openRuleScopeOverlay(app, pages, "ALLOW_ALWAYS") })
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
	right.SetBorder(true).SetTitle("Jobs")

	body := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(left, 0, 3, true).
		AddItem(center, 0, 5, false).
		AddItem(right, 0, 3, false)

	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(s.buildMainTabs(app, pages), 1, 0, false).
		AddItem(body, 0, 1, true).
		AddItem(s.buildStatusBar(), 1, 0, false)

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
		if s.handlePendingActionHotkey(app, pages, ev) {
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
	s.jobsList.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch hotkeyRune(ev.Rune()) {
		case 'm':
			s.toggleJobsMode()
			return nil
		}
		return ev
	})

	root.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Rune() {
		case '1':
			s.setActiveMainTab("pending")
			app.SetFocus(s.pendingList)
			return nil
		case '2':
			s.setActiveMainTab("jobs")
			app.SetFocus(s.jobsList)
			return nil
		case '3':
			s.showRules(app, pages)
			return nil
		case '4':
			s.showHistory(app, pages)
			return nil
		}
		return ev
	})

	s.focus = []tview.Primitive{s.pendingList, s.details, s.jobsList}
	s.setCurrentPage("dashboard")
	s.refresh()
	return root
}

func (s *uiState) doDecision(dec string) {
	queue := func(update func()) {
		if s.app == nil {
			update()
			return
		}
		s.app.QueueUpdateDraw(update)
	}
	s.tryStartDecision(dec, queue)
}

func (s *uiState) tryStartDecision(decision string, queue func(func())) bool {
	if s.selectedPending == "" || s.decisionInFlight || time.Now().Before(s.decisionGuardTil) || s.decisionRunner == nil || queue == nil {
		return false
	}

	requestID := s.selectedPending
	s.decisionInFlight = true
	s.decisionGuardTil = time.Now().Add(maxInputEventAge)
	s.toastText = fmt.Sprintf("Applying %s to %s...", strings.ToLower(decision), requestID)
	s.toastUntil = time.Now().Add(10 * time.Second)
	s.refreshStatus()

	go func() {
		err := s.decisionRunner(requestID, decision)
		queue(func() {
			s.decisionInFlight = false
			if err != nil {
				s.toastText = fmt.Sprintf("Decision failed for %s: %v", requestID, err)
			} else {
				s.toastText = fmt.Sprintf("Decision applied to %s", requestID)
				if s.selectedPending == requestID {
					s.selectedPending = ""
				}
			}
			s.toastUntil = time.Now().Add(5 * time.Second)
			s.refresh()
		})
	}()
	return true
}

func (s *uiState) openRuleScopeOverlay(app *tview.Application, pages *tview.Pages, decision string) {
	if s.selectedPending == "" || app == nil || pages == nil {
		return
	}
	requestID := s.selectedPending
	candidates, scopeProblem := s.api.RuleScopeAnalysisForTUI(requestID)

	prevFocus := app.GetFocus()
	title := "Allow scope"
	if decision == "ALLOW_ALWAYS" {
		title = "Allow always scope"
	} else if decision == "ALLOW_SESSION" {
		title = "Allow session scope"
	}
	if len(candidates) == 0 {
		message := "A reusable rule cannot be created for this request."
		if strings.TrimSpace(scopeProblem) != "" {
			message += "\n\nReason: " + scopeProblem
		}
		message += "\n\nUse Allow once, or rewrite the request without the unsupported construct."
		body := tview.NewTextView().SetDynamicColors(false).SetText(message)
		btnClose := tview.NewButton("Close")
		root := tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(body, 0, 1, false).
			AddItem(btnClose, 1, 0, true)
		root.SetBorder(true).SetTitle(title)
		close := func() {
			pages.RemovePage("rule_scope")
			s.overlayClose = nil
			if prevFocus != nil {
				app.SetFocus(prevFocus)
			}
		}
		btnClose.SetSelectedFunc(close)
		root.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
			if ev.Key() == tcell.KeyEsc {
				close()
				return nil
			}
			return ev
		})
		s.overlayClose = close
		pages.AddPage("rule_scope", centered(root, 92, 10), true, true)
		app.SetFocus(btnClose)
		return
	}

	info := tview.NewTextView().SetDynamicColors(false)
	infoText := ruleScopeHelpText(candidates)
	if strings.TrimSpace(scopeProblem) != "" {
		infoText += "\nSkipped: " + scopeProblem
	}
	info.SetText(infoText)

	segmentsText := tview.NewTextView().SetDynamicColors(false)
	if len(candidates) > 0 {
		var b strings.Builder
		for i, c := range candidates {
			fmt.Fprintf(&b, "%d. %s\n", i+1, c.Segment)
		}
		segmentsText.SetText(strings.TrimRight(b.String(), "\n"))
	}

	checks := make([]*tview.Checkbox, 0, len(candidates))
	inputs := make([]*tview.InputField, 0, len(candidates))
	inputRows := tview.NewFlex().SetDirection(tview.FlexRow)
	for i, c := range candidates {
		check := tview.NewCheckbox().
			SetLabel(fmt.Sprintf("save %d: ", i+1)).
			SetChecked(true)
		input := tview.NewInputField().
			SetLabel(fmt.Sprintf("scope %d: ", i+1)).
			SetText(c.Pattern)
		checks = append(checks, check)
		inputs = append(inputs, input)
		row := tview.NewFlex().SetDirection(tview.FlexColumn).
			AddItem(check, 12, 0, i == 0).
			AddItem(input, 0, 1, false)
		inputRows.AddItem(row, 1, 0, i == 0)
	}
	errText := tview.NewTextView().SetDynamicColors(false).SetTextColor(tcell.ColorRed)

	close := func() {
		pages.RemovePage("rule_scope")
		s.overlayClose = nil
		if prevFocus != nil {
			app.SetFocus(prevFocus)
		}
	}
	save := func() {
		patterns := make([]string, 0, len(inputs))
		for i, input := range inputs {
			if i < len(checks) && !checks[i].IsChecked() {
				continue
			}
			scope := strings.TrimSpace(input.GetText())
			if scope == "" {
				continue
			}
			patterns = append(patterns, scope)
		}
		if len(patterns) == 0 {
			errText.SetText("at least one scope is required")
			return
		}
		if err := s.api.DecideWithRulePatternsForTUI(requestID, decision, patterns); err != nil {
			errText.SetText(err.Error())
			return
		}
		close()
		if s.selectedPending == requestID {
			s.selectedPending = ""
		}
		s.refresh()
	}

	btnSave := tview.NewButton("Save").SetSelectedFunc(save)
	btnCancel := tview.NewButton("Cancel").SetSelectedFunc(close)
	buttons := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(btnSave, 0, 1, false).
		AddItem(btnCancel, 0, 1, false)
	focusables := make([]tview.Primitive, 0, len(inputs)*2+2)
	for i, input := range inputs {
		if i < len(checks) {
			focusables = append(focusables, checks[i])
		}
		focusables = append(focusables, input)
	}
	focusables = append(focusables, btnSave, btnCancel)
	nextFocus := func() {
		cur := app.GetFocus()
		for i, p := range focusables {
			if p == cur {
				app.SetFocus(focusables[(i+1)%len(focusables)])
				return
			}
		}
		if len(focusables) > 0 {
			app.SetFocus(focusables[0])
		}
	}
	setFocusIndex := func(idx int) {
		if len(focusables) == 0 {
			return
		}
		if idx < 0 {
			idx = len(focusables) - 1
		}
		app.SetFocus(focusables[idx%len(focusables)])
	}
	for i, check := range checks {
		idx := i * 2
		check.SetDoneFunc(func(key tcell.Key) {
			switch key {
			case tcell.KeyTAB, tcell.KeyDown, tcell.KeyEnter:
				setFocusIndex(idx + 1)
			case tcell.KeyBacktab, tcell.KeyUp:
				setFocusIndex(idx - 1)
			}
		})
	}
	for i, input := range inputs {
		idx := i*2 + 1
		input.SetDoneFunc(func(key tcell.Key) {
			switch key {
			case tcell.KeyTAB, tcell.KeyDown, tcell.KeyEnter:
				setFocusIndex(idx + 1)
			case tcell.KeyBacktab, tcell.KeyUp:
				setFocusIndex(idx - 1)
			}
		})
		input.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
			switch ev.Key() {
			case tcell.KeyTAB, tcell.KeyDown:
				setFocusIndex(idx + 1)
				return nil
			case tcell.KeyBacktab, tcell.KeyUp:
				setFocusIndex(idx - 1)
				return nil
			}
			return ev
		})
	}

	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(info, 2, 0, false).
		AddItem(segmentsText, maxInt(1, len(candidates)), 0, false).
		AddItem(inputRows, len(inputs), 0, true).
		AddItem(errText, 1, 0, false).
		AddItem(buttons, 1, 0, false)
	root.SetBorder(true).SetTitle(title)
	root.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyTAB:
			nextFocus()
			return nil
		case tcell.KeyEsc:
			close()
			return nil
		case tcell.KeyEnter:
			save()
			return nil
		}
		return ev
	})

	s.overlayClose = close
	pages.AddPage("rule_scope", centered(root, 88, 9+len(inputs)+maxInt(1, len(candidates))), true, true)
	if len(focusables) > 0 {
		app.SetFocus(focusables[0])
	}
}

func jobViewText(mode string, info httpapi.TUIRequestInfo, combined string, liveTruncated bool) string {
	if mode == "" {
		mode = "combined"
	}
	switch mode {
	case "stdout":
		if info.Result == nil {
			return "stdout is available after the request finishes.\n"
		}
		return outputfilter.Redact(info.Result.Stdout)
	case "stderr":
		if info.Result == nil {
			return "stderr is available after the request finishes.\n"
		}
		return outputfilter.Redact(info.Result.Stderr)
	case "meta":
		var b strings.Builder
		fmt.Fprintf(&b, "request_id: %s\nstatus: %s\nclient_id: %s\nsession_id: %s\ncreated_at: %s\n",
			info.ID, info.Status, info.ClientID, info.SessionID, info.CreatedAt)
		if len(info.RiskFlags) > 0 {
			fmt.Fprintf(&b, "risk: %s\n", strings.Join(info.RiskFlags, ", "))
		}
		if info.Decision != nil {
			fmt.Fprintf(&b, "\ndecision: %s\nsource: %s\nrule_id: %s\ndecided_at: %s\n",
				info.Decision.Decision, info.Decision.DecisionSource, info.Decision.RuleID, info.Decision.DecidedAt)
		}
		if info.Result != nil {
			fmt.Fprintf(&b, "\nresult: %s\nexit_code: %d\nduration_ms: %d\nstdout_truncated: %t\nstderr_truncated: %t\nstdout_sha256: %s\nstderr_sha256: %s\n",
				info.Result.Status, info.Result.ExitCode, info.Result.DurationMs, info.Result.StdoutTruncated, info.Result.StderrTruncated, info.Result.StdoutSHA256, info.Result.StderrSHA256)
		}
		return b.String()
	default:
		if combined == "" && info.Result != nil {
			combined = "O: " + outputfilter.Redact(info.Result.Stdout)
			if info.Result.Stderr != "" {
				combined += "E: " + outputfilter.Redact(info.Result.Stderr)
			}
		}
		if liveTruncated {
			return "[live output truncated; showing tail]\n" + combined
		}
		return combined
	}
}

func ruleScopeHelpText(candidates []httpapi.RuleScopeCandidate) string {
	if len(candidates) > 0 {
		const wildcardHelp = " Edit the path; * creates a glob, while a leading = keeps it literal."
		switch candidates[0].OpType {
		case "fs.read":
			return "Allow reading this server file path for the selected scope." + wildcardHelp
		case "fs.patch_unified":
			return "Allow patching this server file path for the selected scope. The diff itself is not scoped." + wildcardHelp
		case "fs.upload":
			return "Allow uploading to this server file path for the selected scope." + wildcardHelp
		case "fs.download":
			return "Allow downloading this server file path for the selected scope." + wildcardHelp
		case "fs.append_block":
			return "Allow appending managed blocks to this file path for the selected scope." + wildcardHelp
		case "fs.replace_literal":
			return "Allow literal replacements in this file path for the selected scope." + wildcardHelp
		case "conf.set":
			return "Allow structured config edits for this file path for the selected scope." + wildcardHelp
		case "conf.set_kv":
			return "Allow key/value config edits for this file path for the selected scope." + wildcardHelp
		}
	}
	return "Edit one scope per command segment. Shell separators like &&, |, ; are rejected.\nExamples: docker stop nginx | docker stop n*"
}

func buildJobPage(app *tview.Application, pages *tview.Pages, s *uiState, cfg ServeUIConfig, requestID string) tview.Primitive {
	s.selectedJob = requestID
	activeRequestID := requestID
	s.jobHeader = tview.NewTextView().SetDynamicColors(false)
	s.jobLog = tview.NewTextView().SetDynamicColors(false).SetScrollable(true)
	s.jobTabs = tview.NewTextView().SetDynamicColors(false).SetTextAlign(tview.AlignLeft)
	s.jobMode = "combined"
	s.follow = true
	tabs := tview.NewTextView().SetDynamicColors(false).SetTextAlign(tview.AlignLeft)
	tabs.SetText(s.renderJobTabs(activeRequestID))

	openKillConfirm := func() {
		m := tview.NewModal().
			SetText("Kill selected job?").
			AddButtons([]string{"Cancel", "Kill"}).
			SetDoneFunc(func(ix int, _ string) {
				pages.RemovePage("confirm_kill")
				if ix == 1 {
					_ = cfg.API.KillForTUI(activeRequestID)
				}
			})
		m.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
			if ev.Key() == tcell.KeyEsc {
				pages.RemovePage("confirm_kill")
				return nil
			}
			return ev
		})
		pages.AddPage("confirm_kill", m, true, true)
	}
	btnKill := tview.NewButton("Kill").SetSelectedFunc(openKillConfirm)
	btnFollow := tview.NewButton(jobFollowLabel(s.follow))
	toggleFollow := func() {
		s.follow = !s.follow
		btnFollow.SetLabel(jobFollowLabel(s.follow))
		s.refreshJobHeader(activeRequestID)
	}
	btnFollow.SetSelectedFunc(toggleFollow)

	back := func() {
		s.leaveJobPage(app, pages, s.jobsList)
	}
	btnBack := tview.NewButton("Back").SetSelectedFunc(back)
	btns := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(btnKill, 0, 1, false).
		AddItem(btnFollow, 0, 1, false).
		AddItem(btnBack, 0, 1, false)

	header := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tabs, 1, 0, false).
		AddItem(s.jobTabs, 1, 0, false).
		AddItem(s.jobHeader, 2, 0, false).
		AddItem(btns, 1, 0, true)
	log := s.jobLog
	log.SetBorder(true).SetTitle("Output")

	s.refreshJobHeader(activeRequestID)
	s.refreshJobLog(activeRequestID)

	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(header, 5, 0, true).
		AddItem(log, 0, 1, true)

	setMode := func(mode string) {
		s.jobMode = mode
		s.refreshJobLog(activeRequestID)
	}
	root.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyEsc:
			back()
			return nil
		}
		switch ev.Rune() {
		case '1':
			setMode("combined")
			return nil
		case '2':
			setMode("stdout")
			return nil
		case '3':
			setMode("stderr")
			return nil
		case '4':
			setMode("meta")
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
		switch hotkeyRune(ev.Rune()) {
		case 'b':
			back()
			return nil
		case 'f':
			toggleFollow()
			return nil
		case 'k':
			openKillConfirm()
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
		SetText(helpText()).
		AddButtons([]string{"Close"}).
		SetDoneFunc(func(_ int, _ string) {
			if s.overlayClose != nil {
				s.closeOverlay(pages)
				return
			}
			pages.HidePage("help")
		})
	m.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEsc {
			if s.overlayClose != nil {
				s.closeOverlay(pages)
				return nil
			}
			pages.HidePage("help")
			return nil
		}
		return ev
	})
	return m
}

func helpText() string {
	return "Keys:\n" +
		"  Tab focus\n" +
		"  0 server / 1 pending / 2 jobs / 3 rules / 4 history\n" +
		"  pending: a once / s session / A always / d deny\n" +
		"  rules: a add always / s add session\n" +
		"  job view: 1 combined / 2 stdout / 3 stderr / 4 meta\n" +
		"  job view: b or Esc back / k kill / f follow\n" +
		"  q quit / F1 help\n"
}

var manualRuleOperations = []string{
	"cmd.run",
	"fs.read",
	"fs.patch_unified",
	"fs.upload",
	"fs.download",
	"fs.append_block",
	"fs.replace_literal",
	"conf.set",
	"conf.set_kv",
}

func manualRuleMatchOptions(opType string) []string {
	if opType == "cmd.run" {
		return []string{"command"}
	}
	return []string{"exact", "prefix", "glob"}
}

func manualRuleSessionLabel(sess httpapi.TUIRuleSession) string {
	clientID := strings.TrimSpace(sess.ClientID)
	if clientID == "" {
		clientID = "unknown-client"
	}
	shortID := sess.ID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	return fmt.Sprintf("%s · %s · %s", clientID, shortID, sess.StartedAt.Local().Format("2006-01-02 15:04:05"))
}

func (s *uiState) openManualRuleOverlay(app *tview.Application, pages *tview.Pages, cfg ServeUIConfig, source string, onSaved func()) {
	if app == nil || pages == nil || cfg.API == nil {
		return
	}
	prevFocus := app.GetFocus()
	selectedSessionID := ""
	selectedOp := manualRuleOperations[0]
	selectedMatch := manualRuleMatchOptions(selectedOp)[0]

	formRows := tview.NewFlex().SetDirection(tview.FlexRow)
	focusables := make([]tview.Primitive, 0, 6)
	if source == "session" {
		sessions, err := cfg.API.ListManualRuleSessionsForTUI()
		sessionDrop := tview.NewDropDown().SetLabel("session: ")
		labels := make([]string, 0, len(sessions))
		for _, sess := range sessions {
			labels = append(labels, manualRuleSessionLabel(sess))
		}
		sessionDrop.SetOptions(labels, func(_ string, index int) {
			if index >= 0 && index < len(sessions) {
				selectedSessionID = sessions[index].ID
			}
		})
		if len(sessions) > 0 {
			selectedSessionID = sessions[0].ID
			sessionDrop.SetCurrentOption(0)
		}
		formRows.AddItem(sessionDrop, 1, 0, true)
		focusables = append(focusables, sessionDrop)
		if err != nil {
			selectedSessionID = ""
		}
	}

	matchDrop := tview.NewDropDown().SetLabel("match: ")
	setMatchOptions := func(opType string) {
		options := manualRuleMatchOptions(opType)
		selectedMatch = options[0]
		matchDrop.SetOptions(options, func(text string, _ int) {
			selectedMatch = text
		})
		matchDrop.SetCurrentOption(0)
	}
	setMatchOptions(selectedOp)

	opDrop := tview.NewDropDown().SetLabel("operation: ")
	opDrop.SetOptions(manualRuleOperations, func(text string, _ int) {
		selectedOp = text
		setMatchOptions(text)
	})
	opDrop.SetCurrentOption(0)
	scopeInput := tview.NewInputField().SetLabel("scope: ")
	formRows.AddItem(opDrop, 1, 0, len(focusables) == 0)
	formRows.AddItem(matchDrop, 1, 0, false)
	formRows.AddItem(scopeInput, 1, 0, false)
	focusables = append(focusables, opDrop, matchDrop, scopeInput)

	errText := tview.NewTextView().SetDynamicColors(false).SetTextColor(tcell.ColorRed)
	close := func() {
		pages.RemovePage("manual_rule")
		s.overlayClose = nil
		if prevFocus != nil {
			app.SetFocus(prevFocus)
		}
	}
	save := func() {
		input := httpapi.ManualRuleInput{
			Source: source, SessionID: selectedSessionID, OpType: selectedOp,
			Match: selectedMatch, Pattern: scopeInput.GetText(),
		}
		ruleID, err := cfg.API.AddManualRuleForTUI(input)
		if err != nil {
			errText.SetText(err.Error())
			return
		}
		close()
		s.toastText = "Rule added: " + ruleID
		s.toastUntil = time.Now().Add(5 * time.Second)
		if onSaved != nil {
			onSaved()
		}
	}
	btnSave := tview.NewButton("Save").SetSelectedFunc(save)
	btnCancel := tview.NewButton("Cancel").SetSelectedFunc(close)
	buttons := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(btnSave, 0, 1, false).
		AddItem(btnCancel, 0, 1, false)
	focusables = append(focusables, btnSave, btnCancel)

	moveFocus := func(delta int) {
		current := app.GetFocus()
		for i, primitive := range focusables {
			if primitive == current {
				next := (i + delta + len(focusables)) % len(focusables)
				app.SetFocus(focusables[next])
				return
			}
		}
		app.SetFocus(focusables[0])
	}
	title := "Add always rule"
	if source == "session" {
		title = "Add session rule"
	}
	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(formRows, formRows.GetItemCount(), 0, true).
		AddItem(errText, 1, 0, false).
		AddItem(buttons, 1, 0, false)
	root.SetBorder(true).SetTitle(title)
	root.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyTAB:
			moveFocus(1)
			return nil
		case tcell.KeyBacktab:
			moveFocus(-1)
			return nil
		case tcell.KeyEsc:
			close()
			return nil
		}
		return ev
	})
	s.overlayClose = close
	height := 7
	if source == "session" {
		height++
	}
	pages.AddPage("manual_rule", centered(root, 92, height), true, true)
	app.SetFocus(focusables[0])
}

func buildRulesPage(app *tview.Application, pages *tview.Pages, s *uiState, cfg ServeUIConfig) tview.Primitive {
	list := tview.NewList().ShowSecondaryText(false)
	details := tview.NewTextView().SetScrollable(true)
	list.SetMainTextColor(tcell.ColorWhite)
	details.SetTextColor(tcell.ColorWhite)
	list.SetBorder(true).SetTitle("Rules")
	details.SetBorder(true).SetTitle("Details")

	var rows []store.RuleRow
	selectedIndex := -1

	refreshDetails := func() {
		if selectedIndex < 0 || selectedIndex >= len(rows) {
			if len(rows) == 0 {
				details.SetText("rules: 0")
			} else {
				details.SetText(fmt.Sprintf("rules: %d\nselect a rule", len(rows)))
			}
			return
		}
		r := rows[selectedIndex]
		en := "0"
		if r.Enabled {
			en = "1"
		}
		var b strings.Builder
		b.WriteString(fmt.Sprintf("rule_id=%s\n", r.RuleID))
		b.WriteString(fmt.Sprintf("enabled=%s\n", en))
		b.WriteString(fmt.Sprintf("op=%s\n", r.OpType))
		b.WriteString(fmt.Sprintf("scope=%s\n", ruleScopeLabel(r)))
		b.WriteString(fmt.Sprintf("source=%s\n", r.Source))
		if r.CreatedAt.IsZero() {
			b.WriteString("created_at=-\n")
		} else {
			b.WriteString(fmt.Sprintf("created_at=%s\n", r.CreatedAt.UTC().Format(time.RFC3339)))
		}
		if strings.HasPrefix(r.Source, "session") {
			b.WriteString("\nSession rules are in-memory and expire when the server/session ends.\n")
		}
		details.SetText(b.String())
	}

	refresh := func() {
		list.Clear()
		rows = nil
		selectedIndex = -1
		if cfg.Store == nil {
			details.SetText("store is not configured")
			return
		}
		dbRows, err := cfg.Store.ListRules(context.Background(), 1000)
		if err != nil {
			details.SetText("error: " + err.Error())
			return
		}
		rows = append(rows, dbRows...)
		if cfg.API != nil {
			rows = append(rows, cfg.API.ListSessionRulesForTUI()...)
		}
		if len(rows) == 0 {
			details.SetText("rules: 0")
			list.AddItem("No rules", "", 0, nil)
			return
		}
		for i, r := range rows {
			en := "0"
			if r.Enabled {
				en = "1"
			}
			source := r.Source
			if strings.HasPrefix(source, "session:") {
				source = "session"
			}
			title := fmt.Sprintf("[%s] %s  %s  %s", en, source, r.OpType, ruleScopeLabel(r))
			list.AddItem(title, "", 0, nil)
			if i == 0 {
				selectedIndex = 0
			}
		}
		refreshDetails()
	}
	refresh()
	s.rulesRefresh = refresh

	list.SetChangedFunc(func(index int, _ string, _ string, _ rune) {
		selectedIndex = index
		refreshDetails()
	})

	btnToggle := tview.NewButton("Enable/Disable").SetSelectedFunc(func() {
		if cfg.API == nil || selectedIndex < 0 || selectedIndex >= len(rows) {
			return
		}
		r := rows[selectedIndex]
		if strings.HasPrefix(r.Source, "session") {
			return
		}
		if err := cfg.API.SetAlwaysRuleEnabledForTUI(r.RuleID, !r.Enabled); err != nil {
			details.SetText("error: " + err.Error())
			return
		}
		refresh()
	})

	btnDelete := tview.NewButton("Delete").SetSelectedFunc(func() {
		if cfg.API == nil || selectedIndex < 0 || selectedIndex >= len(rows) {
			return
		}
		rule := rows[selectedIndex]
		ruleID := rule.RuleID
		m := tview.NewModal().
			SetText("Delete rule " + ruleID + "?").
			AddButtons([]string{"Cancel", "Delete"}).
			SetDoneFunc(func(ix int, _ string) {
				pages.RemovePage("confirm_delete_rule")
				if ix == 1 {
					if err := cfg.API.DeleteRuleForTUI(rule.Source, ruleID); err != nil {
						details.SetText("error: " + err.Error())
						return
					}
					refresh()
				}
			})
		pages.AddPage("confirm_delete_rule", m, true, true)
	})
	btnAddSession := tview.NewButton("Add Session").SetSelectedFunc(func() {
		s.openManualRuleOverlay(app, pages, cfg, "session", refresh)
	})
	btnAddAlways := tview.NewButton("Add Always").SetSelectedFunc(func() {
		s.openManualRuleOverlay(app, pages, cfg, "always", refresh)
	})

	back := func() {
		s.showDashboard(app, pages)
	}
	btnBack := tview.NewButton("Back").SetSelectedFunc(back)

	body := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(list, 0, 2, true).
		AddItem(details, 0, 3, false)
	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(s.buildMainTabs(app, pages), 1, 0, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexColumn).
			AddItem(body, 0, 1, true).
			AddItem(tview.NewFlex().SetDirection(tview.FlexColumn).
				AddItem(btnAddSession, 0, 1, false).
				AddItem(btnAddAlways, 0, 1, false).
				AddItem(btnToggle, 0, 1, false).
				AddItem(btnDelete, 0, 1, false).
				AddItem(btnBack, 0, 1, true), 1, 0, true), 0, 1, true).
		AddItem(s.buildStatusBar(), 1, 0, false)

	root.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEsc {
			back()
			return nil
		}
		switch hotkeyRune(ev.Rune()) {
		case 's':
			s.openManualRuleOverlay(app, pages, cfg, "session", refresh)
			return nil
		case 'a':
			s.openManualRuleOverlay(app, pages, cfg, "always", refresh)
			return nil
		}
		return ev
	})
	return root
}

func ruleScopeLabel(r store.RuleRow) string {
	if r.PathExact != nil && *r.PathExact != "" {
		return "path=" + *r.PathExact
	}
	if r.PathPrefix != nil && *r.PathPrefix != "" {
		return "path_prefix=" + *r.PathPrefix
	}
	if r.PathGlob != nil && *r.PathGlob != "" {
		return "path_glob=" + *r.PathGlob
	}
	if r.CmdArgvJSON != nil && *r.CmdArgvJSON != "" {
		return "argv=" + *r.CmdArgvJSON
	}
	return "-"
}

func buildHistoryPage(app *tview.Application, pages *tview.Pages, s *uiState, cfg ServeUIConfig) tview.Primitive {
	left := tview.NewList().ShowSecondaryText(false)
	details := tview.NewTextView().SetDynamicColors(false).SetScrollable(true)
	left.SetMainTextColor(tcell.ColorWhite)
	details.SetTextColor(tcell.ColorWhite)
	left.SetBorder(true).SetTitle("Sessions")
	details.SetBorder(true).SetTitle("Details")

	var sessions []store.Session

	showSession := func(index int) {
		if index < 0 || index >= len(sessions) {
			details.SetText("No session selected.")
			return
		}
		sess := sessions[index]
		details.SetText(renderSessionHistoryText(cfg.Store, sess))
	}

	refresh := func() {
		if cfg.Store == nil {
			left.Clear()
			left.AddItem("No sessions found", "", 0, nil)
			details.SetText("History is unavailable: store is not configured.")
			return
		}
		ss, err := cfg.Store.ListSessions(context.Background(), 100)
		if err != nil {
			left.Clear()
			left.AddItem("No sessions found", "", 0, nil)
			details.SetText("History load error: " + err.Error())
			return
		}
		sessions = ss
		left.Clear()
		if len(ss) == 0 {
			left.AddItem("No sessions found", "", 0, nil)
			details.SetText("No history yet.")
			return
		}

		for i, sess := range ss {
			left.AddItem(historySessionLabel(sess), "", 0, nil)
			if i == 0 {
				showSession(0)
			}
		}
	}
	refresh()
	s.historyRefresh = refresh
	left.SetChangedFunc(func(index int, _ string, _ string, _ rune) {
		showSession(index)
	})

	back := func() {
		s.showDashboard(app, pages)
	}
	btnBack := tview.NewButton("Back").SetSelectedFunc(back)

	body := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(left, 0, 2, true).
		AddItem(details, 0, 3, false)
	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(s.buildMainTabs(app, pages), 1, 0, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexColumn).
			AddItem(body, 0, 1, true).
			AddItem(btnBack, 1, 0, true), 0, 1, true).
		AddItem(s.buildStatusBar(), 1, 0, false)

	root.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyEsc {
			back()
			return nil
		}
		return ev
	})
	return root
}

func renderSessionHistoryText(st *store.Store, sess store.Session) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("session_id: %s\n", sess.ID))
	b.WriteString(fmt.Sprintf("started_at: %s\n", sess.StartedAt.UTC().Format(time.RFC3339)))
	if sess.EndedAt != nil {
		b.WriteString(fmt.Sprintf("ended_at: %s\n", sess.EndedAt.UTC().Format(time.RFC3339)))
	}

	if st == nil {
		b.WriteString("\nHistory is unavailable: store is not configured.")
		return b.String()
	}
	items, err := st.ListSessionHistoryItems(context.Background(), sess.ID, 200)
	if err != nil {
		b.WriteString("\n\nhistory_error: " + err.Error())
		return b.String()
	}
	if len(items) == 0 {
		b.WriteString("\n\noperations: 0")
		return b.String()
	}

	b.WriteString(fmt.Sprintf("\n\noperations: %d\n", len(items)))
	for idx, item := range items {
		b.WriteString(fmt.Sprintf("%d) %s  %s\n", idx+1, item.CreatedAt.UTC().Format(time.RFC3339), historyOpSummary(item.OpJSON)))
		b.WriteString(fmt.Sprintf("   client: %s  request: %s\n", item.ClientID, item.RequestID))
		if item.Decision != nil {
			b.WriteString(fmt.Sprintf("   decision: %s", *item.Decision))
			if item.DecisionSource != nil && *item.DecisionSource != "" {
				b.WriteString(fmt.Sprintf(" (%s)", *item.DecisionSource))
			}
			b.WriteByte('\n')
		} else {
			b.WriteString("   decision: -\n")
		}
		if item.ExecutionStatus != nil {
			b.WriteString(fmt.Sprintf("   result: %s", *item.ExecutionStatus))
			if item.ExitCode != nil {
				b.WriteString(fmt.Sprintf(" exit=%d", *item.ExitCode))
			}
			if item.DurationMs != nil {
				b.WriteString(fmt.Sprintf(" duration_ms=%d", *item.DurationMs))
			}
			b.WriteByte('\n')
		} else {
			b.WriteString(fmt.Sprintf("   result: %s\n", item.Status))
		}
		b.WriteByte('\n')
	}

	return strings.TrimSpace(b.String())
}

func historySessionLabel(sess store.Session) string {
	return fmt.Sprintf("%s  %s", sess.ID, sess.StartedAt.UTC().Format(time.RFC3339))
}

func historyOpSummary(opJSON string) string {
	var op rules.Op
	if err := json.Unmarshal([]byte(opJSON), &op); err != nil {
		return "<invalid op>"
	}
	switch op.Type {
	case "cmd.run":
		var p struct {
			Argv []string `json:"argv"`
		}
		_ = json.Unmarshal(op.Payload, &p)
		if len(p.Argv) == 0 {
			return "cmd.run <empty argv>"
		}
		return "cmd.run " + strings.Join(p.Argv, " ")
	case "fs.read":
		var p struct {
			Path string `json:"path"`
		}
		_ = json.Unmarshal(op.Payload, &p)
		if p.Path == "" {
			return "fs.read"
		}
		return "fs.read " + p.Path
	case "fs.patch_unified":
		var p struct {
			Path string `json:"path"`
		}
		_ = json.Unmarshal(op.Payload, &p)
		if p.Path == "" {
			return "fs.patch_unified"
		}
		return "fs.patch_unified " + p.Path
	case "fs.upload", "fs.download":
		var p struct {
			Path string `json:"path"`
		}
		_ = json.Unmarshal(op.Payload, &p)
		if p.Path == "" {
			return op.Type
		}
		return op.Type + " " + p.Path
	case "conf.set", "conf.set_kv":
		var p struct {
			Path string `json:"path"`
			Key  string `json:"key"`
		}
		_ = json.Unmarshal(op.Payload, &p)
		if p.Path != "" && p.Key != "" {
			return op.Type + " " + p.Path + " " + p.Key
		}
		return op.Type
	default:
		if strings.TrimSpace(op.Type) == "" {
			return "<unknown op>"
		}
		return op.Type
	}
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
