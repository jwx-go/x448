# github.com/jwx-go/x448/v4 [![Go Reference](https://pkg.go.dev/badge/github.com/jwx-go/x448/v4.svg)](https://pkg.go.dev/github.com/jwx-go/x448/v4)

X448 ECDH-ES key agreement and JWK support for [github.com/lestrrat-go/jwx/v4](https://github.com/lestrrat-go/jwx), powered by [cloudflare/circl](https://github.com/cloudflare/circl).

This is a companion module to `github.com/lestrrat-go/jwx/v4` and has no stability guarantees of its own. Its API may change without notice to track changes in `github.com/lestrrat-go/jwx/v4`.

# Why a separate module?

Go's standard library does not include X448 support. The only viable implementation comes from `github.com/cloudflare/circl`, which is a large dependency. Rather than forcing every `jwx` user to pull in `circl`, X448 support is provided as an opt-in companion module.

# Installation

```
go get github.com/jwx-go/x448/v4
```
