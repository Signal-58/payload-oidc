# Changelog

All notable changes to this package are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0]

The first public release. The plugin's code and behaviour are those of 0.1.0, which ran as a
private workspace package; only the packaging changed.

### Changed

- Published to npm, built to `dist/` as ESM JavaScript with type declarations. Relative imports
  are fully specified, so Node can load the package without a bundler (Payload's CLI and job
  runner do).
- `jose` is a dependency rather than a development dependency, because
  `@signal58/payload-oidc/testing` imports it.

### Added

- README: an "Adopting in an app" checklist, and the callback path stated with Payload's
  `routes.api` (`${serverURL}${routes.api}/<collection>/oidc/callback`), which the code already
  used.
- Tests: an end-to-end case with a non-default `routes.api`, and CI across Payload 3.91.0 and
  3.92.1.

## [0.1.0]

Private release, used as a workspace package only.

[Unreleased]: https://github.com/Signal-58/payload-oidc/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Signal-58/payload-oidc/releases/tag/v0.2.0
