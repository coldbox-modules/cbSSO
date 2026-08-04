# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

* * *

## [Unreleased]

### Changed

- **BREAKING** `SSOAuthorizationResponse.getName()` returned `FirstName` instead of `Name`, so the value
  written by `setName()` could never be read back - `GitHubProvider` sets only `Name`, making its display
  name unreachable. It now returns `Name`, falling back to `FirstName LastName` for providers that set
  those instead (`MicrosoftSAMLProvider` sets no `Name`). Consumers reading `getName()` for a first name
  will now receive a full name.
- `Auth` resolves the requested provider in a `preHandler`, which stores it in `prc.ssoProvider` for
  every action instead of each action resolving it for itself.

### Fixed

- [#16](https://github.com/coldbox-modules/cbSSO/issues/16) An unregistered provider name threw a
  `KeyNotFoundException` from `ProviderService.get()` before the handler's `isNull()` guard could run,
  so `CBSSOMissingProvider` was never announced from `Auth.start()` or `Auth.authorize()`. The
  provider is now gated on `ProviderService.missing()`, which announces `CBSSOMissingProvider` and
  redirects to `errorRedirect`. `get()`'s contract is unchanged for other callers.
- [#17](https://github.com/coldbox-modules/cbSSO/issues/17) `SSOAuthorizationResponse` getters threw on
  a failed authorization, where only `wasSuccessful` and `ErrorMessage` are ever populated. Every
  property is now seeded in `init()`, so the getters read back cleanly. `wasSuccessful()` is
  type-guarded for the property/method name collision, and the `getWasSuccessful()` accessor that
  `accessors=true` generates delegates to it rather than returning the method itself.
- `SSOAuthorizationResponse.getRawResponseData()` now returns an empty struct rather than an empty
  string when unpopulated, matching the struct every provider sets on the populated path.

## [2.1.0] - 2026-05-08

- Fix several bugs
- Change SAMLParser to respect both claims/emailaddress and claims/name

## [2.0.0] - 2025-12-05

## [1.0.7] - 2024-12-06

## [1.0.7] - 2024-09-12

## [1.0.7] - 2024-09-05

## [1.0.6] - 2024-09-04

## [1.0.5] - 2024-09-04

## [1.0.4] - 2024-09-04

## [1.0.3] - 2024-09-04

## [1.0.2] - 2024-09-04

## [1.0.1] - 2024-09-04

## [1.0.0] - 2024-09-04

- Add support for several SSO IP integrations

[Unreleased]: https://github.com/coldbox-modules/cbSSO/compare/v2.1.0...HEAD

[2.1.0]: https://github.com/coldbox-modules/cbSSO/compare/v2.0.0...v2.1.0

[2.0.0]: https://github.com/coldbox-modules/cbSSO/compare/v1.0.7...v2.0.0

[1.0.7]: https://github.com/coldbox-modules/cbSSO/compare/v1.0.7...v1.0.7

[1.0.6]: https://github.com/coldbox-modules/cbSSO/compare/v1.0.5...v1.0.6

[1.0.5]: https://github.com/coldbox-modules/cbSSO/compare/v1.0.4...v1.0.5

[1.0.4]: https://github.com/coldbox-modules/cbSSO/compare/v1.0.3...v1.0.4

[1.0.3]: https://github.com/coldbox-modules/cbSSO/compare/v1.0.2...v1.0.3

[1.0.2]: https://github.com/coldbox-modules/cbSSO/compare/v1.0.1...v1.0.2

[1.0.1]: https://github.com/coldbox-modules/cbSSO/compare/v1.0.0...v1.0.1

[1.0.0]: https://github.com/coldbox-modules/cbSSO/compare/ea53937f976749c7a0057038dc6174671e838579...v1.0.0
