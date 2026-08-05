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
- `SAMLParsingService.extractIdentity()` returns `claims`, `nameId` and `nameIdFormat` alongside the
  existing fields. A claim always holds an array, since a SAML attribute may carry several
  AttributeValues - Entra's `authnmethodsreferences` and its group claims do - and an IdP may split one
  claim across repeated `Attribute` elements. Values are trimmed, which pretty-printed assertions need.
- `MicrosoftSAMLProvider` sets the claims on the success path only. An assertion whose signature did not
  verify has asserted nothing, so a consumer reading a claim off a failed response would be trusting
  whoever sent it rather than the IdP.

### Changed

- `AuthNRequestGenerator` requests a persistent NameID rather than a transient one. The two halves
  contradicted each other: the request asked for `transient`, and `SAMLParsingService.extractUserId()`
  refuses a transient NameID when no `objectidentifier` claim is present, since the specification defines a
  transient identifier as valid for a single session. An IdP that returns exactly what was asked for and
  does not assert Microsoft's `objectidentifier` - which is precisely the ADFS or Shibboleth deployment the
  relaxed claim handling was meant to support - was therefore refused. Entra masks it by always asserting
  `objectidentifier`.
- `MicrosoftSAMLProvider` refuses a `SAMLResponse` that decodes to more than 1MB with
  `MicrosoftSAMLProvider.ResponseTooLarge`, before it is parsed. `extractStatus()` is the one place
  attacker-supplied XML reaches a CFML parser rather than the hardened Java one, and `xmlParse` accepts no
  size or depth limit.
- **BREAKING** `SSOAuthorizationResponse.getName()` returned `FirstName` instead of `Name`, so the value
  written by `setName()` could never be read back - `GitHubProvider` sets only `Name`, making its display
  name unreachable. It now returns `Name`, falling back to `FirstName LastName` for providers that set
  those instead (`MicrosoftSAMLProvider` sets no `Name`). Consumers reading `getName()` for a first name
  will now receive a full name.
- `Auth` resolves the requested provider in a `preHandler`, which stores it in `prc.ssoProvider` for
  every action instead of each action resolving it for itself.
- **BREAKING** `SAMLParsingService` treated a missing `givenname`, `surname` or `objectidentifier` claim as
  a fatal error, failing the whole response. SAML 2.0 requires none of them: an `<AttributeStatement>` is
  optional throughout Core, the Web Browser SSO profile (Profiles 4.1.4.2) asks only for a `<Subject>`
  carrying a bearer `<SubjectConfirmation>`, and all three names are WS-Federation or Microsoft URIs that
  only an Entra-shaped IdP asserts - so a conformant assertion from ADFS, Shibboleth or Okta was refused
  over a display name, while the identifier the profile does point at went unread. The display names are
  now optional, and the subject is identified by the `objectidentifier` claim where the IdP asserts one and
  by the Subject's NameID where it does not. `firstName` and `lastName` may now be empty on a successful
  response, where before they were either populated or the response failed.
- **BREAKING** `SAMLParsingService.extractUserInfo()` is replaced by two methods: `extractStatus(
  rawSAMLResponse )`, which reads the Response's `samlp` Status and returns `success` and `errorMessage`,
  and `extractIdentity( assertionXML )`, which reads identity out of the assertion it is handed and nothing
  else. One method reading both out of the same unvalidated document is what allowed identity to be taken
  from nodes the IdP never signed - see the security fix below. The status is still read from the raw
  response, because when the IdP itself rejects a login there is no assertion to validate and the
  StatusMessage the IdP wrote is the only account of why. `extractIdentity()` throws
  `SAMLParsingService.NoSubjectIdentifier` instead of returning a `success` flag: there is no partial
  identity worth handing back, and its caller is already inside a try/catch because validation throws.
  A caller of `extractUserInfo()` now makes two calls, and must take the assertion from the validator
  rather than the response it arrived in.
- A transient NameID is not accepted as a subject identifier, and an assertion carrying no other is
  refused with `SAMLParsingService.NoSubjectIdentifier`. The specification defines a transient identifier
  as valid for a single session, so keying identity to one enrols the same person again on every login.
  Whether the identifier that *is* returned is portable remains the caller's to judge from `nameIdFormat`:
  Entra's persistent NameID is pairwise, scoped to one app registration.

### Fixed

- **SECURITY** `AuthResponseValidator.parseAndValidate()` performed its signature check inside
  `for ( Assertion a : res.getAssertions() )`, so a response carrying **no** `Assertion` at all ran an empty
  loop and was returned as valid. The only other check compared the Response's `Issuer` - a string in the
  document the sender supplied - against the expected one. A self-authored, unsigned `samlp:Response` naming
  the expected issuer, with a Success status and its claims in any element outside an Assertion, therefore
  authenticated as whoever those claims named. The method is replaced by `parseAndValidateAssertion()`,
  which requires a Success status, a matching issuer, no `EncryptedAssertion` elements, exactly one
  `Assertion`, and a signature on that assertion, and returns the assertion it verified so no caller can
  read identity from anything else.
- **SECURITY** The assertion is now bound to this service provider, not merely to the IdP.
  `parseAndValidateAssertion()` takes the expected audience and recipient, and requires a
  `Conditions/AudienceRestriction` naming that audience, a bearer `SubjectConfirmationData/@Recipient`
  matching the ACS endpoint - compared without case, since an IdP echoes the Reply URL exactly as registered
  while this module derives the expected one through `name.lcase()` - and at least one `AuthnStatement`.
  Without those, an assertion the same IdP issued
  for a different service provider - a second app registration in the same Entra tenant, say - verified
  cleanly here, because it carries the same signature key. Profiles 4.1.4.2 requires all three of Web
  Browser SSO. An unset audience or recipient is named as a provider misconfiguration rather than reported
  as the assertion failing validation.
- **SECURITY** Both `DocumentBuilderFactory` instances set `maxElementDepth` to 25 and
  `elementAttributeLimit` to 30, the defaults OpenSAML itself adopted in 5.2.2 following its 13 May 2026
  advisory on unauthenticated memory and CPU exhaustion from maliciously crafted XML. Upgrading the library
  would not have covered this path: those defaults govern OpenSAML's own decoders and `ParserPool`, while
  `parseResponse()` builds its own factory. Disabling DOCTYPE already ruled out entity expansion, but
  nesting depth needs no DTD at all. Secure processing is enabled alongside them.
- `cacheCerts()` sets a 10 second connect timeout and a 10 second request timeout. The metadata fetch is
  lazy, so it happens on a user's first sign-in - an unresponsive IdP previously occupied that request
  thread indefinitely.
- **SECURITY** The expected issuer is now matched against the **Assertion's** `Issuer`, which Core 2.3.3
  makes mandatory and which sits inside the signed element. The only issuer checked before was the
  Response's - optional per the schema, outside the signature, and therefore whatever the sender chose to
  write. The Response-level check is kept because it fails an obvious misconfiguration cheaply, but it is
  not what the trust decision rests on any more.
- **SECURITY** The assertion signature is now checked against `SAMLSignatureProfileValidator` before any
  cryptographic verification, and the signature's single `Reference` URI must equal `##` plus the ID of the
  assertion whose contents are used. Verifying a signature proves only that *something* in the document was
  signed; without binding the reference to the element being read, XML Signature Wrapping lets an attacker
  keep a genuine signed assertion and add a second, unsigned one for the code to read.
- **SECURITY** `validateConditions()` was only reachable for a response that already had an assertion, and
  dereferenced `getNotBefore()` and `getNotOnOrAfter()` without a null check, so an assertion omitting
  either threw a `NullPointerException` and one omitting `Conditions` entirely threw before any window was
  checked. `validateValidityWindow()` enforces every bound that is present, with 60s of clock skew, and
  requires at least one upper bound - `Conditions/@NotOnOrAfter` or a bearer
  `SubjectConfirmationData/@NotOnOrAfter`, which Profiles 4.1.4.2 makes mandatory anyway. The module has no
  replay protection, so an assertion with no expiry would otherwise be replayable for good.
- `verifySignature()` caught `Exception` per certificate, so a bug in the verification path - not just a
  non-matching certificate - was indistinguishable from "try the next one", and the failure it finally threw
  was a bare `SignatureException` with no message. Only `SignatureException` is now swallowed per
  certificate, an empty certificate list is named as such rather than reported as a signature failure, and
  the thrown message says how many certificates were tried.
- `cacheCerts()` matched `IDPSSODescriptor` and `X509Certificate` with `getElementsByTagName()`, which is
  namespace-blind and therefore missed both in metadata that prefixes them - as Entra's does - and read only
  each certificate node's first child, truncating a value split across text nodes. Both are matched on
  namespace wildcard and read with `getTextContent()`, a non-200 metadata response and a document yielding
  no certificates are now errors instead of silently leaving the validator with none, and the certificate
  list is replaced only once parsing has succeeded so a failed refresh cannot empty a working one. The
  response-code `System.out.println` is gone.
- Both SAML `DocumentBuilderFactory` instances now disallow DOCTYPE declarations, external entities and
  XInclude. A SAML response is attacker-supplied XML parsed before anything about it has been verified,
  which is exactly the XXE case.
- `OpenSAMLUtils.parseResponse()` cast the unmarshalled object to `Response` without checking, so a document
  that is not a `samlp:Response` failed with a `ClassCastException`, or a `NullPointerException` when no
  unmarshaller existed for its root element. Both are named now.
- `MicrosoftSAMLProvider` read the identity out of the whole SAML response before that response was
  validated, matching `Attribute` and `NameID` nodes anywhere in the document. Only the Assertion is
  signed, so a `samlp:Extensions` element - or anything else outside the Assertion - could supply the
  email address, the object identifier or the NameID, and whoever posted the response chose who signed in.
  The order is now: read the status, return the IdP's own message if the IdP rejected the login, validate,
  and only then read the identity - out of the assertion `parseAndValidateAssertion()` returns, which is
  the one element whose signature verified. Nothing outside it is read at all.
- `SAMLParsingService` matched `//Attribute[@Name='...']`, which only resolves when the assertion carries
  the SAML namespace as its default - the parsing strips default namespace declarations, and
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
