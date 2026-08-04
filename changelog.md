# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

* * *

## [Unreleased]

### Added

- `ISSOAuthorizationResponse.getClaims()` and `getClaim( name, defaultValue )` expose everything the IdP
  asserted, keyed by the name the IdP used - the WS-Federation claim URIs for SAML, the id token or user
  info keys for oAuth. The typed getters are a lowest common denominator of the four providers, so an
  Entra group or role claim, a Google `hd`, or a customer's employee-number claim had nowhere to go and no
  way to be read: a consumer had to re-parse `getRawResponseData()` itself. One map means the interface
  does not grow a getter per claim, and it reads the same way for a SAML attribute as for an oAuth claim.
- `ISSOAuthorizationResponse.getNameId()` and `getNameIdFormat()` expose the Subject's NameID, which no
  attribute can substitute for and which the response could not reach at all. The Format comes with it
  because it decides what the value means: Entra's default is a pairwise identifier scoped to one app
  registration, so the same person arrives under a different NameID at a second registration in the same
  tenant. Treat one as an identifier without reading the Format and you have keyed identity to a value
  that is not portable.
- `SAMLParsingService.extractUserInfo()` returns `claims`, `nameId` and `nameIdFormat` alongside the
  existing fields. A claim always holds an array, since a SAML attribute may carry several
  AttributeValues - Entra's `authnmethodsreferences` and its group claims do - and an IdP may split one
  claim across repeated `Attribute` elements. Values are trimmed, which pretty-printed assertions need.
- `MicrosoftSAMLProvider` sets the claims on the success path only. An assertion whose signature did not
  verify has asserted nothing, so a consumer reading a claim off a failed response would be trusting
  whoever sent it rather than the IdP.

### Changed

- **BREAKING** `SSOAuthorizationResponse.getName()` returned `FirstName` instead of `Name`, so the value
  written by `setName()` could never be read back - `GitHubProvider` sets only `Name`, making its display
  name unreachable. It now returns `Name`, falling back to `FirstName LastName` for providers that set
  those instead (`MicrosoftSAMLProvider` sets no `Name`). Consumers reading `getName()` for a first name
  will now receive a full name.
- `Auth` resolves the requested provider in a `preHandler`, which stores it in `prc.ssoProvider` for
  every action instead of each action resolving it for itself.

### Fixed

- `SAMLParsingService` matched `//Attribute[@Name='...']`, which only resolves when the assertion carries
  the SAML namespace as its default - `extractUserInfo()` strips default namespace declarations, and
  nothing else. An IdP that prefixes its elements, as ADFS and Shibboleth do and Entra can be configured
  to, therefore yielded no first name, surname or object identifier, and the whole response was reported
  as `Failed to extract user information`. The typed fields are now derived from the claim set, which is
  matched on `local-name()`.

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
