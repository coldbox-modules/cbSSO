# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

* * *

## [Unreleased]

## [3.0.0] - 2026-08-25

### Added

- Add `getClaims()` and `getClaim()` authorization response accessors.
- Add `getNameId()` and `getNameIdFormat()` authorization response accessors.
- Include claims, NameID, and NameID format in `SAMLParsingService.extractIdentity()`.
- Populate SAML claims only after successful response validation.

### Changed

- Request persistent SAML NameIDs.
- Reject SAML responses larger than 1 MB before parsing.
- **BREAKING** Fix `SSOAuthorizationResponse.getName()` to return `Name`, with a first/last name fallback.
- Resolve the requested provider in `Auth`'s `preHandler`.
- **BREAKING** Make SAML display-name claims optional; use `objectidentifier` or NameID for identification.
- **BREAKING** Replace `extractUserInfo()` with `extractStatus()` and `extractIdentity()`.
- Reject transient NameIDs when no other subject identifier is available.

### Fixed

- **SECURITY** Harden SAML XML parsing against XXE, DOCTYPE declarations, non-XML input, and deeply nested documents.
- **SECURITY** Require a successful response with one signed, non-encrypted assertion and a matching issuer.
- **SECURITY** Bind assertions to the configured audience and ACS recipient; require bearer confirmation and an `AuthnStatement`.
- **SECURITY** Validate the SAML signature profile and bind its reference to the validated assertion.
- **SECURITY** Enforce assertion and bearer confirmation validity windows, including a required expiry.
- Add metadata fetch timeouts and robust, namespace-aware certificate parsing.
- Improve signature verification errors and preserve cached certificates when metadata refreshes fail.
- Read SAML identity only from the validated assertion.
- Report clear errors for documents that are not SAML responses.
- Match prefixed SAML claims and collect repeated or multi-valued claims.
- [#16](https://github.com/coldbox-modules/cbSSO/issues/16) Fix missing-provider handling and events.
- [#17](https://github.com/coldbox-modules/cbSSO/issues/17) Initialize failed authorization response properties safely.
- Return an empty struct from `getRawResponseData()` when no response exists.

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

[Unreleased]: https://github.com/coldbox-modules/cbSSO/compare/v3.0.0...HEAD

[3.0.0]: https://github.com/coldbox-modules/cbSSO/compare/v2.1.0...v3.0.0

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
