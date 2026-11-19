# JWK Set verification-key selection migration

Signature verification previously resolved a key from a `JSONWebKeySet` with
`tryJWKS`: it looked up the token's `kid`, took the **first** matching record,
and verified with it. Key use, advertised algorithm and key type were not
considered, and two equally-valid records for one `kid` were silently resolved
by import order.

Verification now runs through a candidate arbiter
(`selectVerificationKeyFromJWKS` / `verificationKeyFromSet` in `signing.go`).
Only the key set supplied on the call is considered; no remote address carried
by a token or a key record is ever dereferenced. The JWE decryption path still
uses the original `tryJWKS` and is unchanged.

## Selection rules (new entry path)

1. The signature header must carry a `kid`. Without one, selection fails with
   `JWKSVerificationErrorMissingKid`.
2. Records with that `kid` are collected. A record is a candidate only when it:
   - has no `use`, or `use == "sig"` (an `enc`-only record is excluded);
   - holds an asymmetric **public** key — private and symmetric (signing-only)
     material never participates;
   - either advertises no `alg`, or advertises the signature's algorithm, which
     is already restricted to the caller's explicitly allowed algorithms at
     parse time (the token cannot widen that scope);
   - has a public key type compatible with that algorithm.
3. Exactly one candidate: it is returned and verification proceeds.
4. No candidates: `JWKSVerificationErrorNoMatchingKey`.
5. More than one candidate: `JWKSVerificationErrorAmbiguousKey`, returned before
   any cryptographic check. The result is independent of record import order.

Selection errors carry only a failure kind (`JWKSVerificationErrorKind`) and the
public `kid`; they never contain token contents. Missing-`kid` and
no-matching-key errors still satisfy `errors.Is(err, ErrJWKSKidNotFound)` for
backward compatibility; ambiguity is deliberately distinct.

## Case-by-case: old entry vs new entry

| Acceptance case | Old entry (`tryJWKS`, single bare key/JWK unchanged) | New entry (JWK Set arbiter) |
| --- | --- | --- |
| Single candidate success | First `kid` match is used; verifies | Same result; the sole eligible key verifies |
| Same `kid`, only one usable (others `enc`/private/wrong `alg`/wrong key type/symmetric) | First record taken regardless of use/type; could pick an unusable or wrong key | Ineligible records filtered; the one usable key verifies, in either import order |
| Two records both eligible (`ambiguous-signer-selection-boundary`) | First record wins; ambiguity hidden and order-dependent | `JWKSVerificationErrorAmbiguousKey` before verification, identical in either order |
| Unique candidate whose signature does not verify | `ErrCryptoFailure` | `ErrCryptoFailure` (selection succeeded; only the crypto check fails) |
| Header missing `kid` | `ErrJWKSKidNotFound` | `JWKSVerificationErrorMissingKid`, also `errors.Is(…, ErrJWKSKidNotFound)` |
| `kid` present but no eligible record | `ErrJWKSKidNotFound` | `JWKSVerificationErrorNoMatchingKey`, also `errors.Is(…, ErrJWKSKidNotFound)` |
| Bare public key / single `JSONWebKey` argument | Verified directly, no set lookup | Unchanged: non-set arguments bypass the arbiter entirely (`TestLegacySingleKeyVerification`) |

No new key service is introduced and no additional signature algorithms are
enabled; the arbiter reuses the algorithms and key types already supported by
the library's verifiers.
