# Changelog

## [2.6.2] - 2026-05-09

### Fixed
- reverse-shell detector no longer false-positives on benign `import socket` Python scripts; signatures now require socket-creation AND exec/redirect proximity (#incident-20260509004453373-1434)

### Added
- `[process] dev_parent_allowlist` — downgrades severity to Medium and action to Alert when the parent process is a known interactive dev tool (claude, code, cursor, vim/nvim, jupyter, jetbrains IDEs, etc.). Threat is still recorded; only the auto-action is softened. Demoted events carry `degraded_by_dev_parent: true`.
- `[process] strict_under_dev_tools` — opt back into full severity for dev-tool parents (default false).
- `[response] desktop_notifications` — `notify-send` / libnotify on kill/block (default true). Best-effort; failure to deliver never crashes the response engine. Disable in headless deployments.
