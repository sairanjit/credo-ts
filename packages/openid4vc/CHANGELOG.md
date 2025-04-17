# Changelog

## 0.6.0

### Minor Changes

- 81dbbec: fix: typo statefull -> stateful in configuration of OpenID4VCI module
- 9f78a6e: feat(openid4vc): openid4vp alpha
- 5f08bc6: feat: allow dynamicaly providing x509 certificates for all types of verifications
- 9f78a6e: resolveIssuanceAuthorizationRequest has been renamed to resolveOpenId4VciAuthorizationRequest
- 9f78a6e: feat(openid4vc): add support for new dcql query syntax for oid4vp
- 9f78a6e: refactor: Support for SIOPv2 has been removed and all interfaces and classes that included Siop in the name (such as OpenId4VcSiopHolderService) have been renamed to OpenId4Vp (so OpenId4VpHolderService)
- 70c849d: update target for tsc compiler to ES2020. Generally this should not have an impact for the supported environments (Node.JS / React Native). However this will have to be tested in React Native
- 8baa7d7: changed the `v1.draft11-13` and `v1.draft13` versions for credential offers to `v1.draft11-15` and `v1.draft15`. `v1.draft15` is compatible with draft 13, but you're responsible for correctly configuring the credential configurations supported.
- 17ec6b8: feat(openid4vc): oid4vci authorization code flow, presentation during issuance and batch issuance.

  This is a big change to OpenID4VCI in Credo, with the neccsary breaking changes since we first added it to the framework. Over time the spec has changed significantly, but also our understanding of the standards and protocols.

  **Authorization Code Flow**
  Credo now supports the authorization code flow, for both issuer and holder. An issuer can configure multiple authorization servers, and work with external authorization servers as well. The integration is based on OAuth2, with several extension specifications, mainly the OAuth2 JWT Access Token Profile, as well as Token Introspection (for opaque access tokens). Verification works out of the box, as longs as the authorization server has a `jwks_uri` configured. For Token Introspection it's also required to provide a `clientId` and `clientSecret` in the authorization server config.

  To use an external authorization server, the authorization server MUST include the `issuer_state` parameter from the credential offer in the access token. Otherwise it's not possible for Credo to correlate the authorization session to the offer session.

  The demo-openid contains an example with external authorization server, which can be used as reference. The Credo authorization server supports DPoP and PKCE.

  **Batch Issuance**
  The credential request to credential mapper has been updated to support multiple proofs, and also multiple credential instances. The client can now also handle batch issuance.

  **Presentation During Issuance**
  The presenation during issuance allows to request presentation using OID4VP before granting authorization for issuance of one or more credentials. This flow is automatically handled by the `resolveAuthorizationRequest` method on the oid4vci holder service.

- 9f78a6e: OpenID4VP draft 24 is supported along with transaction data, DCQL, and other features. This has impact on the API, but draft 21 is still supported by providing the `version` param when creating a request
- 9f78a6e: the default value for `responseMode` has changed from `direct_post` (unencrypted) to `direct_post.jwt` (encrypted)
- 9f78a6e: fixed an issue where expectedUpdate in an mdoc would be set to undefined. This is a breaking change as previously issued mDOCs containing expectedUpdate values of undefined are not valid anymore, and will cause issues during verification
- 9f78a6e: refactor: changed the DIF Presentation Exchnage returned credential entry `type` to `claimFormat` to better align with the DC API. In addition the selected credentials type for DIF PEX was changes from an array of credential records, to an object containig the record, claimFormat and disclosed payload
- 8baa7d7: add support for OID4VCI draft 15, including wallet and key attestations. With this we have made changes to several APIs to better align with key attestations, and how credential binding resolving works. Instead of calling the holder binding resolver for each credential that will be requested once, it will in total be called once and you can return multiple keys, or a single key attestation. APIs have been simplified to better align with changes in the OID4VCI protocols, but OID4VCI draft 11 and 13 are still fully supported. Support for dc+sd-jwt format has also been added. Note that there have been incompatible metadata display/claim changes in the metadata structure between draft 14 and 15 and thus if you want to support both draft 15 and older drafts you have to make sure you're handling this correctly (e.g. by creating separate configurations to be used with draft 13 or 15), and make sure you're using dc+sd-jwt with draft and vc+sd-jwt with draft 13.
- decbcac: The mdoc device response now verifies each document separately based on the trusted certificates callback. This ensures only the trusted certificates for that specific document are used. In addition, only ONE document per device response is supported for openid4vp verifications from now on, this is expected behaviour according to ISO 18013-7
- 9f78a6e: support for creating authorization requests based on `x509_san_uri` client id scheme has been removed. The holder services still support the client id scheme. The client id scheme is removed starting from draft 25 (and replaced with x509_hash, which will be supported in a future version), and is incompatible with the new url structure of Credo.

### Patch Changes

- 13cd8cb: feat: support node 22
- 17ec6b8: fix(openid4vc): use `vp_formats` in client_metadata instead of `vp_formats supported` (#2089)
- 607659a: feat: fetch sd-jwt type metadata
- 90caf61: feat: support mdoc device response containing multiple documents for OpenID4VP presentation
- 17ec6b8: feat(openid4vc): support jwk thumbprint for openid token issuer
- 27f971d: fix: only include supported mdoc algs in vp_formats metadata
- Updated dependencies [2d10ec3]
- Updated dependencies [6d83136]
- Updated dependencies [312a7b2]
- Updated dependencies [297d209]
- Updated dependencies [11827cc]
- Updated dependencies [9f78a6e]
- Updated dependencies [297d209]
- Updated dependencies [bea846b]
- Updated dependencies [13cd8cb]
- Updated dependencies [15acc49]
- Updated dependencies [90caf61]
- Updated dependencies [dca4fdf]
- Updated dependencies [14673b1]
- Updated dependencies [607659a]
- Updated dependencies [44b1866]
- Updated dependencies [5f08bc6]
- Updated dependencies [27f971d]
- Updated dependencies [2d10ec3]
- Updated dependencies [1a4182e]
- Updated dependencies [90caf61]
- Updated dependencies [9f78a6e]
- Updated dependencies [8baa7d7]
- Updated dependencies [decbcac]
- Updated dependencies [9df09fa]
- Updated dependencies [70c849d]
- Updated dependencies [897c834]
- Updated dependencies [a53fc54]
- Updated dependencies [edd2edc]
- Updated dependencies [9f78a6e]
- Updated dependencies [e80794b]
- Updated dependencies [9f78a6e]
- Updated dependencies [9f78a6e]
- Updated dependencies [8baa7d7]
- Updated dependencies [decbcac]
- Updated dependencies [27f971d]
  - @credo-ts/core@0.6.0

## 0.5.13

### Patch Changes

- 595c3d6: feat: mdoc device response and presentation over oid4vp
- Updated dependencies [595c3d6]
  - @credo-ts/core@0.5.13

## 0.5.12

### Patch Changes

- 1d83159: feat: add jarm-support
- Updated dependencies [3c85565]
- Updated dependencies [3c85565]
- Updated dependencies [7d51fcb]
- Updated dependencies [9756a4a]
  - @credo-ts/core@0.5.12

## 0.5.11

### Patch Changes

- 6c2dd88: add support for cose_key as cryptographic_binding_methods_supported value
  - @credo-ts/core@0.5.11

## 0.5.10

### Patch Changes

- 2110e4a: fix: incorrect generation of code verifier for pkce
- 2110e4a: fix: include client_id when requesting credential using authorization_code flow
- 35a04e3: fix v11 metadata typing and update v11<->v13 tranformation logic accordingly
- fa62b74: Add support for Demonstrating Proof of Possesion (DPoP) when receiving credentials using OpenID4VCI
- a093150: fix: pass the `clientId` in the `requestCredentials` method from the API down to the service
- Updated dependencies [fa62b74]
  - @credo-ts/core@0.5.10

## 0.5.9

### Patch Changes

- a12d80c: feat: update to openid4vc v1 draft 13, with v11 compatibility
  - @credo-ts/core@0.5.9

## 0.5.8

### Patch Changes

- 3819eb2: Adds support for issuance and verification of SD-JWT VCs using x509 certificates over OpenID4VC, as well as adds support for the `x509_san_uri` and `x509_san_dns` values for `client_id_scheme`. It also adds support for OpenID4VP Draft 20
- Updated dependencies [3819eb2]
- Updated dependencies [15d0a54]
- Updated dependencies [a5235e7]
  - @credo-ts/core@0.5.8

## 0.5.7

### Patch Changes

- 2173952: Fix an issue where `express` was being bundled in React Native applications even though the `OpenId4VcIssuerModule` and `OpenId4VcVerifierModule` were not used, causing runtime errors.
- Updated dependencies [352383f]
- Updated dependencies [1044c9d]
  - @credo-ts/core@0.5.7

## 0.5.6

### Patch Changes

- 66e696d: Fix build issue causing error with importing packages in 0.5.5 release
- Updated dependencies [66e696d]
  - @credo-ts/core@0.5.6

## 0.5.5

### Patch Changes

- 482a630: - feat: allow serving dids from did record (#1856)
  - fix: set created at for anoncreds records (#1862)
  - feat: add goal to public api for credential and proof (#1867)
  - fix(oob): only reuse connection if enabled (#1868)
  - fix: issuer id query anoncreds w3c (#1870)
  - feat: sd-jwt issuance without holder binding (#1871)
  - chore: update oid4vci deps (#1873)
  - fix: query for qualified/unqualified forms in revocation notification (#1866)
  - fix: wrong schema id is stored for credentials (#1884)
  - fix: process credential or proof problem report message related to connectionless or out of band exchange (#1859)
  - fix: unqualified indy revRegDefId in migration (#1887)
  - feat: verify SD-JWT Token status list and SD-JWT VC fixes (#1872)
  - fix(anoncreds): combine creds into one proof (#1893)
  - fix: AnonCreds proof requests with unqualified dids (#1891)
  - fix: WebSocket priority in Message Pick Up V2 (#1888)
  - fix: anoncreds predicate only proof with unqualified dids (#1907)
  - feat: add pagination params to storage service (#1883)
  - feat: add message handler middleware and fallback (#1894)
- Updated dependencies [3239ef3]
- Updated dependencies [d548fa4]
- Updated dependencies [482a630]
  - @credo-ts/core@0.5.5

## [0.5.3](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.2...v0.5.3) (2024-05-01)

**Note:** Version bump only for package @credo-ts/openid4vc

## [0.5.2](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.1...v0.5.2) (2024-04-26)

### Bug Fixes

- access token can only be used for offer ([#1828](https://github.com/openwallet-foundation/credo-ts/issues/1828)) ([f54b90b](https://github.com/openwallet-foundation/credo-ts/commit/f54b90b0530b43a04df6299a39414a142d73276e))
- oid4vp can be used separate from idtoken ([#1827](https://github.com/openwallet-foundation/credo-ts/issues/1827)) ([ca383c2](https://github.com/openwallet-foundation/credo-ts/commit/ca383c284e2073992a1fd280fca99bee1c2e19f8))
- **openid4vc:** update verified state for more states ([#1831](https://github.com/openwallet-foundation/credo-ts/issues/1831)) ([958bf64](https://github.com/openwallet-foundation/credo-ts/commit/958bf647c086a2ca240e9ad140defc39b7f20f43))

### Features

- add disclosures so you know which fields are disclosed ([#1834](https://github.com/openwallet-foundation/credo-ts/issues/1834)) ([6ec43eb](https://github.com/openwallet-foundation/credo-ts/commit/6ec43eb1f539bd8d864d5bbd2ab35459809255ec))
- apply new version of SD JWT package ([#1787](https://github.com/openwallet-foundation/credo-ts/issues/1787)) ([b41e158](https://github.com/openwallet-foundation/credo-ts/commit/b41e158098773d2f59b5b5cfb82cc6be06a57acd))
- openid4vc issued state per credential ([#1829](https://github.com/openwallet-foundation/credo-ts/issues/1829)) ([229c621](https://github.com/openwallet-foundation/credo-ts/commit/229c62177c04060c7ca4c19dfd35bab328035067))

## [0.5.1](https://github.com/openwallet-foundation/credo-ts/compare/v0.5.0...v0.5.1) (2024-03-28)

### Bug Fixes

- **openid4vc:** several fixes and improvements ([#1795](https://github.com/openwallet-foundation/credo-ts/issues/1795)) ([b83c517](https://github.com/openwallet-foundation/credo-ts/commit/b83c5173070594448d92f801331b3a31c7ac8049))

# [0.5.0](https://github.com/openwallet-foundation/credo-ts/compare/v0.4.2...v0.5.0) (2024-03-13)

### Features

- anoncreds w3c migration ([#1744](https://github.com/openwallet-foundation/credo-ts/issues/1744)) ([d7c2bbb](https://github.com/openwallet-foundation/credo-ts/commit/d7c2bbb4fde57cdacbbf1ed40c6bd1423f7ab015))
- **openid4vc:** persistance and events ([#1793](https://github.com/openwallet-foundation/credo-ts/issues/1793)) ([f4c386a](https://github.com/openwallet-foundation/credo-ts/commit/f4c386a6ccf8adb829cad30b81d524e6ffddb029))
