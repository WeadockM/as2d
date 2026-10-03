# Changelog

All notable changes to as2d are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Until 1.0, minor versions may
change configuration or APIs; any such change is called out below.

## [Unreleased]

## [0.3.0] - 2026-10-03

### Added
- Dashboard user accounts with three roles: **viewer** (read only),
  **operator** (also retry and send) and **admin** (also users and audit
  log). Turned on by `password_pepper_file` and `state_dir`; without them
  the dashboard signs in with `api_token` as before.
- Passwords are hashed with Argon2id after being combined with a secret
  pepper kept in its own file. Peppers can be rotated with
  `previous_pepper_files`.
- **Users** page for admins: add users (each gets a one-time password),
  change roles, reset passwords, disable accounts. Disabling or resetting
  signs the user out at once. The last active admin can't be demoted or
  disabled.
- **Audit log** page: sign-ins, failed sign-ins, password changes, user
  changes, and files sent or messages retried from the dashboard.
- Sign-in throttling: 5 wrong passwords for an account (or 20 from one
  address) in 15 minutes block further attempts for the rest of that window.
- `as2d -create-admin <name>`, `-reset-password <name>` and
  `-generate-pepper`.

### Changed
- Once user accounts exist, `api_token` no longer signs in to the
  dashboard. It still works for scripts and Boomi as a bearer token, with
  operator rights.

### Fixed
- Release pages include the notes from this changelog. The v0.2.2 release
  was published without them because of a release configuration mistake.

## [0.2.2] - 2026-10-03

The `v0.2.1` tag exists, but its release build failed, so nothing was
published under it. This release contains those changes plus the fix to the
release workflow.

### Security
- Built with Go 1.26.8. Versions 0.1.0 and 0.2.0 were built with Go 1.26.1,
  whose standard library has 14 known vulnerabilities that as2d's code can
  reach, in TLS, X.509 certificate and ASN.1 parsing, HTTP, and URL and
  header handling (GO-2026-4866 to GO-2026-6218; run `govulncheck` for the
  list). **Upgrading is recommended for all users.**
- `go.mod` now names the toolchain (`toolchain go1.26.8`), so building or
  `go install`-ing as2d with an older Go automatically uses 1.26.8. CI and
  release builds use the newest Go 1.26 patch release and run `govulncheck`
  on every change.

### Added
- Release archives built automatically for Linux (amd64 and arm64) and
  Windows (amd64). Each includes the README, licence, changelog, the systemd
  unit and example configuration, and the release lists SHA-256 checksums.

### Changed
- On Windows, `-config` defaults to `config.json` next to the program, so
  as2d can be started by double-clicking it. On Linux the default is still
  `/etc/as2d/config.json`.
- Double-clicking `as2d.exe`, `as2send.exe` or `as2keygen.exe` no longer
  flashes a window that closes at once: if the program can't run, the window
  explains how to run it and stays open until Enter is pressed. Behaviour
  from a terminal or as a service is unchanged.

## [0.2.0] - 2026-10-02

### Added
- Web dashboard on the API listener: search and filter messages, view
  details and download files, retry failed sends and forwards, watch the
  queue, review partners and certificates, and send files. Sign-in uses
  `api_token`.
- SQLite index of the archive (`index_db`, default `<archive_dir>/as2d.db`)
  for searching and duplicate detection. It is built automatically from the
  archive on first start, and `as2d -reindex` rebuilds it on demand.
- Warnings, in the log and the dashboard, for certificates that expire
  within 30 days.
- `-version` flag on `as2d`, `as2send` and `as2keygen`.

### Changed
- Duplicate detection uses the index instead of `<archive_dir>/.index/`,
  which is no longer used and can be deleted after upgrading.
- The API listener now starts whenever `api_listen` is set, even if no
  partner has outbound settings, so the dashboard is always available.

## [0.1.0] - 2026-10-02

First release.

### Added
- Receiving: decryption, signature verification, compression (RFC 5402),
  sync and async MDNs (signed on request), duplicate detection, archive and
  inbox folder.
- Sending: persistent queue with retries and backoff, outbox folder,
  submission API with `wait=` for the MDN result, status webhook, and
  correlation IDs.
- Forwarding received payloads to an HTTP endpoint such as a Boomi Web
  Services Server listener, in `queued` or `before_mdn` mode.
- `as2send` for one-off test sends, and `as2keygen` for certificates.

[Unreleased]: https://github.com/WeadockM/as2d/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/WeadockM/as2d/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/WeadockM/as2d/compare/v0.2.0...v0.2.2
[0.2.0]: https://github.com/WeadockM/as2d/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/WeadockM/as2d/releases/tag/v0.1.0
