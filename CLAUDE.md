# X448 Extension for JWX

## Overview

This module (`github.com/jwx-go/x448/v4`) provides X448 ECDH-ES key agreement, HPKE, and JWK support for `github.com/lestrrat-go/jwx`.

X448 is not included in the main jwx module because Go's standard library does not support X448, requiring the external `github.com/cloudflare/circl` dependency. Importing this package registers X448 JWK key import/export, ECDH-ES key agreement, and HPKE algorithms (HPKE-5-KE, HPKE-6-KE) with the jwx library.

## Architecture

This module registers X448 support via jwx's extension point system in its `init()` function. It provides `PublicKey` and `PrivateKey` wrapper types that implement `jwebb.ECDHESKeyGenerator` and `jwebb.ECDHESKeyDeriver` for ECDH-ES, as well as `jwebb.HPKEKeyEncrypter` and `jwebb.HPKEKeyDecrypter` for HPKE.

### Registration Points

| JWX Package | Registration Function | Purpose |
|-------------|----------------------|---------|
| `jwk` | `RegisterKeyExporter()` | Export OKP:X448 JWK to raw x448 key |
| `jwk` | `RegisterOKPRawKeyImporter()` | Import raw x448 key to OKP JWK |
| `jwk` | `RegisterKeyImporter()` | Import `*PublicKey` / `*PrivateKey` to JWK |
| `jwa` | `RegisterKeyEncryptionAlgorithm()` | Register HPKE-5-KE, HPKE-6-KE |
| `jwebb` | `RegisterHPKEAlgorithm()` | Mark HPKE-5-KE, HPKE-6-KE as HPKE algorithms |

### Sub-packages

| Package | Purpose |
|---------|---------|
| `dhkem` | DHKEM(X448, HKDF-SHA512) per RFC 9180, Section 4.1 |
| `hpke` | HPKE Base mode with DHKEM(X448, HKDF-SHA512) per RFC 9180 |

## Build / Test

Requires `GOEXPERIMENT=jsonv2` (jwx v4 dependency):

```
GOEXPERIMENT=jsonv2 go test ./...
```

## Files

| File | Purpose |
|------|---------|
| `x448.go` | Package doc, key types, `init()` registration, ECDH-ES and HPKE implementations, JWK import/export |
| `x448_test.go` | Tests |
| `dhkem/dhkem.go` | DHKEM(X448, HKDF-SHA512) implementation |
| `dhkem/dhkem_test.go` | DHKEM tests |
| `hpke/hpke.go` | HPKE Base mode implementation |
| `hpke/hpke_test.go` | HPKE tests |

## Branch Policy

| Branch | Purpose |
|--------|---------|
| `v*` (e.g. `v4`) | Release tags only. NEVER commit directly to these branches. |
| `develop/v*` (e.g. `develop/v4`) | Active development. All feature branches merge here. |
| Feature branches | Branch from `develop/v*`, merge back via PR. |

- Tags are cut from `v*` branches.
- `v*` branches should never be directly worked on.
- Regular development happens on `develop/v*` and feature branches.
