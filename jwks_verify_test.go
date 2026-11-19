/*-
 * Copyright 2026 The Go JOSE Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/url"
	"strings"
	"testing"
)

// signEdDSAWithKid produces a compact EdDSA JWS carrying the given "kid".
func signEdDSAWithKid(t *testing.T, kid string, key ed25519.PrivateKey, payload []byte) *JSONWebSignature {
	t.Helper()
	signer, err := NewSigner(SigningKey{
		Algorithm: EdDSA,
		Key:       &JSONWebKey{KeyID: kid, Key: key},
	}, nil)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("signing payload: %v", err)
	}
	return obj
}

// signEdDSAWithoutKid produces a compact EdDSA JWS with no "kid" header.
func signEdDSAWithoutKid(t *testing.T, key ed25519.PrivateKey, payload []byte) *JSONWebSignature {
	t.Helper()
	signer, err := NewSigner(SigningKey{Algorithm: EdDSA, Key: key}, nil)
	if err != nil {
		t.Fatalf("creating signer: %v", err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("signing payload: %v", err)
	}
	return obj
}

func parseEdDSA(t *testing.T, obj *JSONWebSignature) *JSONWebSignature {
	t.Helper()
	serialized, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("serializing JWS: %v", err)
	}
	parsed, err := ParseSigned(serialized, []SignatureAlgorithm{EdDSA})
	if err != nil {
		t.Fatalf("parsing JWS: %v", err)
	}
	return parsed
}

func generateEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 key: %v", err)
	}
	return pub, priv
}

func expectJWKSVerificationError(t *testing.T, err error, kind JWKSVerificationErrorKind, kid string) {
	t.Helper()
	var keyErr *JWKSVerificationError
	if !errors.As(err, &keyErr) {
		t.Fatalf("expected *JWKSVerificationError, got %T: %v", err, err)
	}
	if keyErr.Kind != kind {
		t.Errorf("error kind = %v, want %v", keyErr.Kind, kind)
	}
	if keyErr.KeyID != kid {
		t.Errorf("error KeyID = %q, want %q", keyErr.KeyID, kid)
	}
}

// TestJWKSVerifySingleCandidate covers the single-candidate success case: the
// set holds several keys but exactly one matches the token's "kid".
func TestJWKSVerifySingleCandidate(t *testing.T) {
	payload := []byte("Lorem ipsum dolor sit amet")
	pubA, privA := generateEd25519(t)
	pubB, _ := generateEd25519(t)

	obj := parseEdDSA(t, signEdDSAWithKid(t, "key-a", privA, payload))

	jwks := &JSONWebKeySet{Keys: []JSONWebKey{
		{KeyID: "key-a", Key: pubA, Use: "sig"},
		{KeyID: "key-b", Key: pubB, Use: "sig"},
	}}

	out, err := obj.Verify(jwks)
	if err != nil {
		t.Fatalf("Verify with JWK Set failed: %v", err)
	}
	if string(out) != string(payload) {
		t.Errorf("payload = %q, want %q", out, payload)
	}

	// The value (non-pointer) form of a set must behave identically.
	if _, err := obj.Verify(*jwks); err != nil {
		t.Errorf("Verify with value JWK Set failed: %v", err)
	}
}

// TestJWKSVerifySameKidOneUsable shares one "kid" across several records but
// arranges for exactly one to be eligible. The signing-only, wrong-purpose,
// wrong-algorithm and wrong-key-type records must all be filtered out before
// verification, regardless of import order.
func TestJWKSVerifySameKidOneUsable(t *testing.T) {
	payload := []byte("Lorem ipsum dolor sit amet")
	pub, priv := generateEd25519(t)
	otherPub, _ := generateEd25519(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	const kid = "shared"
	eligible := JSONWebKey{KeyID: kid, Key: pub, Use: "sig"}

	cases := map[string]JSONWebKey{
		"enc use is not verifiable":         {KeyID: kid, Key: otherPub, Use: "enc"},
		"private key is signing-only":       {KeyID: kid, Key: priv, Use: "sig"},
		"advertised alg outside scope":      {KeyID: kid, Key: otherPub, Use: "sig", Algorithm: "ES256"},
		"wrong public key type for EdDSA":   {KeyID: kid, Key: &ecKey.PublicKey, Use: "sig"},
		"symmetric key cannot verify EdDSA": {KeyID: kid, Key: []byte("a-shared-secret-that-is-long-enough"), Use: "sig"},
	}

	for name, ineligible := range cases {
		t.Run(name, func(t *testing.T) {
			obj := parseEdDSA(t, signEdDSAWithKid(t, kid, priv, payload))

			for _, keys := range [][]JSONWebKey{
				{eligible, ineligible},
				{ineligible, eligible}, // swapped import order
			} {
				jwks := &JSONWebKeySet{Keys: keys}
				out, err := obj.Verify(jwks)
				if err != nil {
					t.Fatalf("expected the single eligible key to verify: %v", err)
				}
				if string(out) != string(payload) {
					t.Errorf("payload = %q, want %q", out, payload)
				}
			}
		})
	}
}

// TestJWKSVerifyAmbiguous covers the case where two records are both eligible:
// selection must end with an ambiguity error before any signature check runs,
// and swapping the records must not change that outcome.
func TestJWKSVerifyAmbiguous(t *testing.T) {
	payload := []byte("Lorem ipsum dolor sit amet")
	pubA, privA := generateEd25519(t)
	pubB, _ := generateEd25519(t)

	obj := parseEdDSA(t, signEdDSAWithKid(t, "shared", privA, payload))

	// pubA would actually verify the token; the old first-match behavior would
	// therefore have accepted this set. The arbiter must reject it instead.
	orderings := [][]JSONWebKey{
		{
			{KeyID: "shared", Key: pubA, Use: "sig"},
			{KeyID: "shared", Key: pubB, Use: "sig"},
		},
		{
			{KeyID: "shared", Key: pubB, Use: "sig"},
			{KeyID: "shared", Key: pubA, Use: "sig"},
		},
	}

	for i, keys := range orderings {
		jwks := &JSONWebKeySet{Keys: keys}
		_, err := obj.Verify(jwks)
		expectJWKSVerificationError(t, err, JWKSVerificationErrorAmbiguousKey, "shared")
		if errors.Is(err, ErrCryptoFailure) {
			t.Errorf("ordering %d: ambiguity must be reported instead of running verification", i)
		}
		if errors.Is(err, ErrJWKSKidNotFound) {
			t.Errorf("ordering %d: ambiguity is distinct from a missing/unmatched kid", i)
		}
	}
}

// TestJWKSVerifyAmbiguousMulti makes VerifyMulti surface the same ambiguity
// error rather than silently skipping the signature.
func TestJWKSVerifyAmbiguousMulti(t *testing.T) {
	payload := []byte("Lorem ipsum dolor sit amet")
	pubA, privA := generateEd25519(t)
	pubB, _ := generateEd25519(t)

	signer, err := NewMultiSigner([]SigningKey{
		{Algorithm: EdDSA, Key: &JSONWebKey{KeyID: "shared", Key: privA}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSigned(signed.FullSerialize(), []SignatureAlgorithm{EdDSA})
	if err != nil {
		t.Fatal(err)
	}

	jwks := &JSONWebKeySet{Keys: []JSONWebKey{
		{KeyID: "shared", Key: pubA, Use: "sig"},
		{KeyID: "shared", Key: pubB, Use: "sig"},
	}}

	_, _, _, err = parsed.VerifyMulti(jwks)
	expectJWKSVerificationError(t, err, JWKSVerificationErrorAmbiguousKey, "shared")
}

// TestJWKSVerifyUniqueCandidateFails proves that a uniquely selected key really
// enters verification: a wrong key yields the cryptographic failure rather than
// a selection error.
func TestJWKSVerifyUniqueCandidateFails(t *testing.T) {
	payload := []byte("Lorem ipsum dolor sit amet")
	_, priv := generateEd25519(t)
	wrongPub, _ := generateEd25519(t)

	obj := parseEdDSA(t, signEdDSAWithKid(t, "key-a", priv, payload))

	jwks := &JSONWebKeySet{Keys: []JSONWebKey{
		{KeyID: "key-a", Key: wrongPub, Use: "sig"},
	}}

	_, err := obj.Verify(jwks)
	if !errors.Is(err, ErrCryptoFailure) {
		t.Fatalf("expected ErrCryptoFailure from the unique candidate, got %v", err)
	}
	var keyErr *JWKSVerificationError
	if errors.As(err, &keyErr) {
		t.Errorf("a failed signature check must not be reported as a selection error: %v", keyErr)
	}
}

// TestJWKSVerifyMissingKid covers a signature header without a key identifier.
func TestJWKSVerifyMissingKid(t *testing.T) {
	payload := []byte("Lorem ipsum dolor sit amet")
	pub, priv := generateEd25519(t)

	obj := parseEdDSA(t, signEdDSAWithoutKid(t, priv, payload))

	jwks := &JSONWebKeySet{Keys: []JSONWebKey{
		{KeyID: "key-a", Key: pub, Use: "sig"},
	}}

	_, err := obj.Verify(jwks)
	expectJWKSVerificationError(t, err, JWKSVerificationErrorMissingKid, "")
	if !errors.Is(err, ErrJWKSKidNotFound) {
		t.Errorf("missing kid should still match ErrJWKSKidNotFound, got %v", err)
	}
}

// TestJWKSVerifyNoMatchingKey covers a present "kid" that no eligible record
// answers: no record at all, or only filtered records.
func TestJWKSVerifyNoMatchingKey(t *testing.T) {
	payload := []byte("Lorem ipsum dolor sit amet")
	pub, priv := generateEd25519(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	obj := parseEdDSA(t, signEdDSAWithKid(t, "key-a", priv, payload))

	cases := map[string]*JSONWebKeySet{
		"no record with the kid": {Keys: []JSONWebKey{
			{KeyID: "other", Key: pub, Use: "sig"},
		}},
		"only enc-use record": {Keys: []JSONWebKey{
			{KeyID: "key-a", Key: pub, Use: "enc"},
		}},
		"only private record": {Keys: []JSONWebKey{
			{KeyID: "key-a", Key: priv},
		}},
		"only wrong key type": {Keys: []JSONWebKey{
			{KeyID: "key-a", Key: &ecKey.PublicKey, Use: "sig"},
		}},
	}

	for name, jwks := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := obj.Verify(jwks)
			expectJWKSVerificationError(t, err, JWKSVerificationErrorNoMatchingKey, "key-a")
			if !errors.Is(err, ErrJWKSKidNotFound) {
				t.Errorf("unmatched kid should still match ErrJWKSKidNotFound, got %v", err)
			}
		})
	}
}

// TestJWKSVerifyErrorLeaksNoTokenContent checks that selection errors carry
// only the failure kind and the public kid, never token contents.
func TestJWKSVerifyErrorLeaksNoTokenContent(t *testing.T) {
	payload := []byte("super-secret-claim-value")
	_, priv := generateEd25519(t)

	noKid := parseEdDSA(t, signEdDSAWithoutKid(t, priv, payload))
	_, missingKidErr := noKid.Verify(&JSONWebKeySet{
		Keys: []JSONWebKey{{KeyID: "key-a", Key: nil}},
	})
	if missingKidErr == nil {
		t.Fatal("expected missing-kid error")
	}
	if strings.Contains(missingKidErr.Error(), string(payload)) {
		t.Errorf("missing-kid error leaked token content: %v", missingKidErr)
	}

	withKid := parseEdDSA(t, signEdDSAWithKid(t, "key-a", priv, payload))
	_, noMatchErr := withKid.Verify(&JSONWebKeySet{
		Keys: []JSONWebKey{{KeyID: "other", Key: nil}},
	})
	if noMatchErr == nil {
		t.Fatal("expected no-matching-key error")
	}
	if strings.Contains(noMatchErr.Error(), string(payload)) {
		t.Errorf("no-match error leaked token content: %v", noMatchErr)
	}
}

// TestJWKSVerifyIgnoresRemoteAddresses ensures key selection never dereferences
// remote pointers carried by set entries: an unroutable x5u URL is harmless.
func TestJWKSVerifyIgnoresRemoteAddresses(t *testing.T) {
	payload := []byte("Lorem ipsum dolor sit amet")
	pub, priv := generateEd25519(t)

	obj := parseEdDSA(t, signEdDSAWithKid(t, "key-a", priv, payload))

	jwks := &JSONWebKeySet{Keys: []JSONWebKey{{
		KeyID:           "key-a",
		Key:             pub,
		Use:             "sig",
		CertificatesURL: &url.URL{Scheme: "https", Host: "invalid.example.invalid", Path: "/cert.pem"},
	}}}

	if _, err := obj.Verify(jwks); err != nil {
		t.Fatalf("verification must not fetch remote addresses: %v", err)
	}
}

// TestLegacySingleKeyVerification keeps the old entry path working: callers
// passing a bare public key or a single JWK bypass set selection entirely.
func TestLegacySingleKeyVerification(t *testing.T) {
	payload := []byte("Lorem ipsum dolor sit amet")
	pub, priv := generateEd25519(t)

	obj := parseEdDSA(t, signEdDSAWithKid(t, "key-a", priv, payload))

	if _, err := obj.Verify(pub); err != nil {
		t.Errorf("bare public key verification failed: %v", err)
	}
	if _, err := obj.Verify(&JSONWebKey{KeyID: "key-a", Key: pub}); err != nil {
		t.Errorf("single *JSONWebKey verification failed: %v", err)
	}
	if err := obj.DetachedVerify(payload, pub); err != nil {
		t.Errorf("DetachedVerify with bare public key failed: %v", err)
	}
}
