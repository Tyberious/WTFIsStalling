# Releasing

How versions are numbered, when a release is made, and the steps to make one.

## Version numbers

WTFIsStalling uses [semantic versioning](https://semver.org): `MAJOR.MINOR.PATCH`.

- **Before 1.0 the numbers keep counting**: after 0.9 comes 0.10, 0.11 and so on. Semantic
  versioning puts no limit on them, so reaching 0.9 says nothing about 1.0 being next.
- **A minor version** (0.10.0, 0.11.0) is a milestone: a capability a user will notice, finished
  and tested.
- **A patch version** (0.10.1, 0.10.2) fixes things and never adds features.
- **A beta** (`0.10.0-beta.1`, `-beta.2`, ...) is a build for field testing before a minor
  version. GitHub shows it as a pre-release. It is never marked "latest", so the README badge and
  the latest-download links keep pointing at the last final version.
- **Between releases `main` says `-dev`** (for example `0.10.0-dev`), so an exe built from the
  source never passes itself off as a released version.

The version lives in one place, `Cargo.toml`. The executables' version resource, the report
header and the saved `.wtfis` data files all take it from there. Windows' numeric file version
drops the suffix (`0.10.0-beta.1` and `0.10.0` are both `0.10.0.0`); the text version keeps it.

## When to release

- **A minor version only when it is ready**: its features are in, they have been seen working on
  at least one real PC besides the developer's (a beta run by someone else counts), and the
  pre-release checks below have passed. No more than about one minor version every two weeks;
  work that is ready sooner waits for the next one or goes out as a beta.
- **A patch whenever a fix matters to users** (a wrong verdict, a crash, a privacy problem). Those
  do not wait.
- **A beta whenever someone can test it**, usually to get a field report on a machine with the
  problem a feature was built for.

## What 1.0 requires

1.0 is a promise, so it waits until all of these are true:

1. The command-line flags and the `.wtfis` data format are stable: any later change is
   backward-compatible or clearly documented in the changelog.
2. Field reports from several real PCs have confirmed the main verdicts, including a PC with
   whole-PC freezes.
3. The executables are code-signed.
4. No open issue says the tool blames the wrong thing.

## Steps

### Before any release

1. `main` is clean and CI is green.
2. A review pass over everything since the last release, and a live elevated run on a real PC
   (the CLI with `--debug`, and one run through the app window).
3. `CHANGELOG.md`: the new version's section is complete.

### Making it

1. In `Cargo.toml`, set the version to the release (`0.10.0`, or `0.10.0-beta.1` for a beta).
   Build once so `Cargo.lock` follows, then commit. Name the commit for what the release changes
   for users.
2. Tag and push: `git tag v0.10.0 && git push origin v0.10.0`. The release workflow refuses a tag
   that does not match `Cargo.toml`, and any `-dev` version.
3. When the workflow is green, check the published files:
   - `sha256sum -c SHA256SUMS.txt`
   - `gh attestation verify <exe> --repo Tyberious/WTFIsStalling` for both executables (it prints
     nothing when run without a terminal; check its exit code)
   - a Microsoft Defender scan of the downloads
   - the version resource of both executables
4. Replace the generated notes with written ones (`gh release edit vX.Y.Z --notes-file ...`): what
   is new for users, fixes, known limits, and the verification and download sections.
5. For a final release, date its section in `CHANGELOG.md`.
6. Set `main` to the next `-dev` version (`0.11.0-dev`) and commit.
