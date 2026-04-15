# github.com/jwx-go/x448/v4 [![Go Reference](https://pkg.go.dev/badge/github.com/jwx-go/x448/v4.svg)](https://pkg.go.dev/github.com/jwx-go/x448/v4)

X448 key agreement, HPKE, and JWK support for [github.com/lestrrat-go/jwx/v4](https://github.com/lestrrat-go/jwx), powered by [cloudflare/circl](https://github.com/cloudflare/circl).

This is a companion module to `github.com/lestrrat-go/jwx/v4` and has no stability guarantees of its own. Its API may change without notice to track changes in `github.com/lestrrat-go/jwx/v4`.

# Features

Importing this module registers the following with jwx/v4:

- **JWK**: OKP keys with curve `X448` (import, export, thumbprint)
- **ECDH-ES**: X448 key agreement for all ECDH-ES algorithms (`ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW`)
- **HPKE**: Two HPKE key encryption algorithms using DHKEM(X448, HKDF-SHA512) per [draft-ietf-jose-hpke-encrypt](https://datatracker.ietf.org/doc/draft-ietf-jose-hpke-encrypt/):
  - `HPKE-5-KE` — HKDF-SHA512 + AES-256-GCM
  - `HPKE-6-KE` — HKDF-SHA512 + ChaCha20Poly1305

All features activate via a blank import:

```go
import _ "github.com/jwx-go/x448/v4"
```

# Why a separate module?

Go's standard library does not include X448 support. The only viable implementation comes from `github.com/cloudflare/circl`, which is a large dependency. Rather than forcing every `jwx` user to pull in `circl`, X448 support is provided as an opt-in companion module.

# Backend

This module is implemented on top of `github.com/cloudflare/circl` (tested against `v1.6.3`). The wrapper relies on one security-critical contract: circl's `x448.Shared` MUST return `false` when the input would produce a low-order / all-zero shared secret, per [RFC 7748 §6.2](https://www.rfc-editor.org/rfc/rfc7748#section-6.2). Every `x448.Shared` call site in this module checks that return value; any backend swap (upgrade, fork, or a hypothetical future `crypto/ecdh` X448) must preserve an equivalent signal and continue to have it checked.

# Installation

```
go get github.com/jwx-go/x448/v4
```
