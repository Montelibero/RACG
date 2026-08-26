# Manual TUI Rules Implementation Plan

**Goal:** Allow an operator to create session and always rules directly from the Rules TUI without submitting a request first.

**Architecture:** Add a typed in-process API that validates manual rule input, creates a command or path rule, persists always rules, and installs both sources into the live rule engine. Persisted rules retain the existing `allow_always_for_dangerous` policy. Add a Rules-page modal for source, session, operation, match mode, and scope. Keep session rules in memory and always rules in SQLite, matching existing lifecycle semantics.

**Tech Stack:** Go, tview/tcell, SQLite, existing RACG rule engine.

## Tasks

1. Add failing HTTP API tests for manual always/session rules and invalid command scopes.
2. Implement manual rule construction and live installation in `internal/httpapi`.
3. Add failing TUI helper/navigation tests for session options, operation modes, and help text.
4. Implement mouse-accessible `Add Session` and `Add Always` buttons, `s`/`a` hotkeys, and a focus-trapped modal.
5. Update README, quickstart, TUI help, and the RACG agent skill.
6. Run unit, race, vet, cross-architecture build, diff checks, and independent review.
7. Commit the completed feature without pushing.
