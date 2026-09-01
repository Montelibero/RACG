# RACG Project Instructions

## User-Facing Changes

- Every public command, flag, workflow, status, and behavior must be discoverable from the relevant `racg --help` or `racg <command> --help` output without requiring the README.
- When user-facing behavior changes, update all applicable surfaces in the same task: root help, subcommand help, README, `docs/agent-quickstart.md`, OpenAPI, and `skills/racg-client-ops/`.
- Add or update tests that assert the important help text so documentation cannot silently drift from the implementation.
- Keep examples consistent across help, documentation, and the skill. Examples are not validation restrictions.

## Release Gate

Before bumping or tagging a version:

1. Review user-facing changes since the previous release.
2. Run `racg --help` and `racg <changed-command> --help` for every changed command.
3. Verify README, quickstart, OpenAPI, and the repository skill describe the released behavior.
4. Run the repository test, vet, and release-build checks.
5. Do not push commits or tags unless the user explicitly requests publication.

