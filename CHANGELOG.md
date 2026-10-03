# Changelog

All notable changes to as2d are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Until 1.0, minor versions may
change configuration or APIs; any such change is called out below.

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

[0.2.0]: https://github.com/WeadockM/as2d/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/WeadockM/as2d/releases/tag/v0.1.0
