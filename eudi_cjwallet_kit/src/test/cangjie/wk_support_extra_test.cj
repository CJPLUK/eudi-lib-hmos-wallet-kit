/*
 * wk_support_extra_test.cj
 *
 * Additional pure-logic coverage for wallet-kit support:
 *   - sdjwt_utils.cj   (parseCompact / extractJwtPayload / sdAlgorithm /
 *                       resolveDisclosures / buildClaimMap / DisclosedClaim)
 *                       via a hand-built compact SD-JWT round-trip (offline,
 *                       no network, deterministic).
 *   - transaction_log.cj (TransactionLogUtils.getTimestamp non-empty)
 *   - trusted_chain_validator.cj (TrustedChainValidator ctor / fromDer / fromPem
 *                       on empty roots, and isValid on empty chain = false —
 *                       offline, no real cert material required for these paths)
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.support

import std.unittest.*
import std.unittest.testmacro.*
import std.collection.HashMap

import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.CoreBase64UrlImpl
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.model.Disclosure

import ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.{
    SdJwtUtils,
    DisclosedClaim,
    TransactionLogUtils,
    TrustedChainValidator
}

// ---------------------------------------------------------------------------
// Helper: build a minimal valid compact SD-JWT for offline parsing.
//   <b64url(header)>.<b64url(payload)>.<b64url(sig)>~<encoded-disclosure>~
// The payload carries _sd_alg=sha-256 and a single disclosure for "given_name".
// ---------------------------------------------------------------------------
func buildCompactSdJwt(): String {
    let b64 = CoreBase64UrlImpl()
    let header = b64.encode("{\"alg\":\"ES256\",\"typ\":\"vc+sd-jwt\"}".toArray())
    let payload = b64.encode("{\"iss\":\"https://issuer.example\",\"_sd_alg\":\"sha-256\",\"_sd\":[]}".toArray())
    let sig = b64.encode([0xDEu8, 0xADu8, 0xBEu8, 0xEFu8])
    let jwt = header + "." + payload + "." + sig
    // Object-property disclosure: salt, name "given_name", value "\"Alice\""
    let disc = Disclosure(salt: "saltsaltsalt", name: "given_name", value: "\"Alice\"")
    let encDisc = disc.encodeWith(b64)
    return jwt + "~" + encDisc + "~"
}

// ===========================================================================
// SdJwtUtils round-trip
// ===========================================================================
@Test
class WkSupportSdJwtUtilsUT {

    @TestCase
    func parseCompactYieldsOneDisclosure(): Unit {
        let signed = SdJwtUtils.parseCompact(buildCompactSdJwt())
        @Expect(signed.disclosures.size, 1)
    }

    @TestCase
    func extractJwtPayloadContainsIssuer(): Unit {
        let payload = SdJwtUtils.extractJwtPayload(buildCompactSdJwt())
        @Expect(payload.contains("https://issuer.example"), true)
        @Expect(payload.contains("_sd_alg"), true)
    }

    @TestCase
    func sdAlgorithmReadsField(): Unit {
        @Expect(SdJwtUtils.sdAlgorithm(buildCompactSdJwt()), "sha-256")
    }

    @TestCase
    func sdAlgorithmDefaultsWhenAbsent(): Unit {
        let b64 = CoreBase64UrlImpl()
        let header = b64.encode("{\"alg\":\"ES256\"}".toArray())
        let payload = b64.encode("{\"iss\":\"x\"}".toArray())   // no _sd_alg
        let sig = b64.encode([0x01u8])
        let compact = header + "." + payload + "." + sig + "~"
        // Default per SD-JWT spec is sha-256.
        @Expect(SdJwtUtils.sdAlgorithm(compact), "sha-256")
    }

    @TestCase
    func resolveDisclosuresProducesDisclosedClaim(): Unit {
        let claims = SdJwtUtils.resolveDisclosures(buildCompactSdJwt())
        @Expect(claims.size, 1)
        let c = claims[0]
        match (c.name) {
            case Some(n) => @Expect(n, "given_name")
            case None => @Expect("none", "some")
        }
        @Expect(c.value, "\"Alice\"")
        @Expect(c.digest.size > 0, true)
    }

    @TestCase
    func buildClaimMapHasGivenName(): Unit {
        let map = SdJwtUtils.buildClaimMap(buildCompactSdJwt())
        @Expect(map.contains("given_name"), true)
        @Expect(map["given_name"], "\"Alice\"")
    }

    @TestCase
    func disclosedClaimConstruction(): Unit {
        let dc = DisclosedClaim(name: Some("family_name"), value: "\"Doe\"", digest: "abc123")
        @Expect(dc.value, "\"Doe\"")
        @Expect(dc.digest, "abc123")
        match (dc.name) {
            case Some(n) => @Expect(n, "family_name")
            case None => @Expect("none", "some")
        }
    }
}

// ===========================================================================
// TransactionLogUtils.getTimestamp
// ===========================================================================
@Test
class WkSupportGetTimestampUT {

    @TestCase
    func timestampNonEmpty(): Unit {
        let ts = TransactionLogUtils.getTimestamp()
        @Expect(ts.size > 0, true)
    }
}

// ===========================================================================
// TrustedChainValidator offline paths
// ===========================================================================
@Test
class WkSupportTrustedChainValidatorUT {

    @TestCase
    func ctorWithNoRoots(): Unit {
        let v = TrustedChainValidator([])
        @Expect(v.trustedRoots.size, 0)
    }

    @TestCase
    func emptyChainIsInvalid(): Unit {
        let v = TrustedChainValidator([])
        // Empty chain cannot be validated -> false (logged, no throw).
        @Expect(v.isValid([]), false)
    }

    @TestCase
    func garbageLeafIsInvalid(): Unit {
        let v = TrustedChainValidator([])
        // Non-base64 / non-DER leaf -> parse fails -> false (no throw).
        @Expect(v.isValid(["not-a-cert"]), false)
    }

    @TestCase
    func fromDerEmptyRoots(): Unit {
        let v = TrustedChainValidator.fromDer([])
        @Expect(v.trustedRoots.size, 0)
    }

    @TestCase
    func fromPemEmptyRoots(): Unit {
        let v = TrustedChainValidator.fromPem([])
        @Expect(v.trustedRoots.size, 0)
    }
}
