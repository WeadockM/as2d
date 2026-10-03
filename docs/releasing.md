# Releasing

Releases are built and published by GitHub Actions when a version tag is
pushed. Nothing needs to be built by hand.

1. In `CHANGELOG.md`, move the entries under **Unreleased** into a new
   section headed `## [X.Y.Z] - YYYY-MM-DD`, and add the comparison link at
   the bottom. That section becomes the release notes, and the release fails
   if it is missing.
2. Commit and push to `main`, and wait for CI to pass.
3. Tag and push the tag:

   ```sh
   git tag -a vX.Y.Z -m "as2d vX.Y.Z"
   git push origin vX.Y.Z
   ```

The [release workflow](../.github/workflows/release.yml) then runs the tests,
builds `as2d`, `as2send` and `as2keygen` for Linux (amd64, arm64) and Windows
(amd64) with the version built in, packages them with the docs and example
configuration, and publishes the release with a `SHA256SUMS` file. It takes a
few minutes; progress is on the repository's **Actions** tab.

Tags with a suffix, such as `v0.3.0-rc.1`, are published as pre-releases.

## Trying the release build locally

[GoReleaser](https://goreleaser.com) can do the same build without
publishing anything. The output goes to `dist/`:

```sh
go run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean
```

## If a release fails

**Don't move or delete a tag once it is pushed.** Go's module mirror
permanently records the code behind a version the first time anyone fetches
it, so changing what a tag points to can break `go install ...@vX.Y.Z` for
everyone with a checksum error. Instead, fix the problem, add a section for
the next patch version to `CHANGELOG.md` (noting that the failed tag was not
released), and tag that.

- **"CHANGELOG.md has no section for X.Y.Z":** the release stops before
  building anything. Add the changelog section and release the next patch
  version.
- **Permission errors creating the release:** in the repository settings,
  under Actions → General → Workflow permissions, allow read and write, then
  re-run the failed workflow from the Actions tab. A re-run uses the same
  tag, which is fine because the tag itself did not change.
- **Anything else:** the GoReleaser step's log is on the Actions tab (it
  needs you to be signed in to GitHub).
