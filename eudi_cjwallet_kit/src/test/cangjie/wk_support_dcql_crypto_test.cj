/*
 * wk_support_dcql_crypto_test.cj
 *
 * Unit tests for wallet-kit support pure logic:
 *   - dcql_queryable.cj   (FlowType / DocTypedData / PopUsage enums,
 *                          pathKey serialisation, DefaultDcqlQueryable query logic)
 *   - secure_area_signer.cj (jwsAlgorithmName, base64UrlEncode, SecureAreaSigner
 *                            constructor validation for EdDSA/UNSET)
 *   - document_status_service.cj (IgnoreVerifier no-op, DocumentStatusService defaults)
 *   - sdjwt_utils.cj       (computeHash digest lengths via CoreDigestImpl)
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.support

import std.unittest.*
import std.unittest.testmacro.*
import std.collection.HashMap

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.{ClaimPath, ClaimName, ClaimPathElement}

import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.{SigningAlgorithm, CoseEcCurve, SecureArea, SecureKeyStorage, KeyBatchInfo, CredentialOptions, KeyOptions}

import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.WalletError

import ohos_app_cangjie_eudi_cjstatium.statium.model.StatusListTokenFormat

import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.CoreDigestImpl
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.model.SdJwtVerifierError

// Symbols under test (wallet.support) — explicit import for entry package.
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.{
    FlowType,
    DocTypedData,
    PopUsage,
    pathKey,
    DefaultDcqlQueryable,
    jwsAlgorithmName,
    base64UrlEncode,
    SecureAreaSigner,
    DocumentStatusService,
    SdJwtUtils
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func singlePath(name: String): ClaimPath {
    let elems: Array<ClaimPathElement> = [ClaimName(name)]
    return ClaimPath(elems)
}

func nestedPath(a: String, b: String): ClaimPath {
    let elems: Array<ClaimPathElement> = [ClaimName(a), ClaimName(b)]
    return ClaimPath(elems)
}

// Minimal SecureArea test double (fake). SecureAreaSigner's constructor validates the signing
// algorithm BEFORE touching the secure area, so none of these methods are invoked
// in our tests; methods with non-trivial return types throw (never reached).
class DummySecureArea <: SecureArea {
    public func getName(): String { return "dummy" }
    public func getDefaultEcCurve(): CoseEcCurve { return CoseEcCurve.P256 }
    public func getSupportedEcCurves(): Array<CoseEcCurve> { return [CoseEcCurve.P256] }
    public func getStorage(): SecureKeyStorage { throw Exception("not used by these tests") }
    public func createKeyBatch(id: String, credentialOptions: CredentialOptions, keyOptions: ?KeyOptions): KeyBatchInfo {
        throw Exception("not used by these tests")
    }
    public func getPublicKeyBytes(id: String, index: Int64, curve: CoseEcCurve): Array<UInt8> { return [] }
    public func unlockKey(id: String): ?Array<UInt8> { return None }
    public func deleteKeyBatch(id: String, startIndex: Int64, batchSize: Int64): Unit {}
    public func deleteKeyInfo(id: String): Unit {}
    public func signature(id: String, index: Int64, algorithm: SigningAlgorithm, dataToSign: Array<UInt8>, unlockData: ?Array<UInt8>): Array<UInt8> {
        return []
    }
    public func keyAgreement(id: String, index: Int64, publicKeyBytes: Array<UInt8>, unlockData: ?Array<UInt8>): Array<UInt8> {
        return []
    }
    public func getKeyBatchInfo(id: String): KeyBatchInfo { throw Exception("not used by these tests") }
    public func defaultSigningAlgorithm(ecCurve: CoseEcCurve): SigningAlgorithm { return SigningAlgorithm.ES256 }
}

func makeDummySecureArea(): SecureArea {
    return DummySecureArea()
}

// ===========================================================================
// FlowType
// ===========================================================================
@Test
class WkSupportFlowTypeUT {

    @TestCase
    func rawValues(): Unit {
        @Expect(FlowType.Ble.rawValue(), "ble")
        @Expect(FlowType.OpenId4Vp(Array<UInt8>()).rawValue(), "openid4vp")
        @Expect(FlowType.Other.rawValue(), "other")
    }

    @TestCase
    func fromRawRoundTrip(): Unit {
        match (FlowType.fromRaw("openid4vp")) {
            case Some(f) => @Expect(f.rawValue(), "openid4vp")
            case None => @Expect("none", "some")
        }
        @Expect(FlowType.fromRaw("zzz").isNone(), true)
    }
}

// ===========================================================================
// DocTypedData
// ===========================================================================
@Test
class WkSupportDocTypedDataUT {

    @TestCase
    func msoMdocVariant(): Unit {
        let d = DocTypedData.MsoMdoc("org.iso.18013.5.1.mDL")
        @Expect(d.docType(), "org.iso.18013.5.1.mDL")
        @Expect(d.isMsoMdoc(), true)
        @Expect(d.isSdJwt(), false)
    }

    @TestCase
    func sdJwtVariant(): Unit {
        let d = DocTypedData.SdJwt("urn:pid:1")
        @Expect(d.docType(), "urn:pid:1")
        @Expect(d.isSdJwt(), true)
        @Expect(d.isMsoMdoc(), false)
    }
}

// ===========================================================================
// PopUsage
// ===========================================================================
@Test
class WkSupportPopUsageUT {

    @TestCase
    func rawValues(): Unit {
        @Expect(PopUsage.DPop.rawValue(), "dpop")
        @Expect(PopUsage.ClientAttestation.rawValue(), "client_attestation")
    }

    @TestCase
    func fromRaw(): Unit {
        match (PopUsage.fromRaw("client_attestation")) {
            case Some(p) => @Expect(p.rawValue(), "client_attestation")
            case None => @Expect("none", "some")
        }
        @Expect(PopUsage.fromRaw("nope").isNone(), true)
    }
}

// ===========================================================================
// pathKey + DefaultDcqlQueryable
// ===========================================================================
@Test
class WkSupportDcqlQueryableUT {

    @TestCase
    func pathKeySingleElement(): Unit {
        @Expect(pathKey(singlePath("given_name")), "given_name")
    }

    @TestCase
    func pathKeyNestedDotJoined(): Unit {
        @Expect(pathKey(nestedPath("address", "country")), "address.country")
    }

    @TestCase
    func fromFlatClaimsBuildsPaths(): Unit {
        let flat = HashMap<String, String>()
        flat["given_name"] = "\"Alice\""
        flat["age"] = "42"
        let q = DefaultDcqlQueryable.fromFlatClaims(flat)
        @Expect(q.getAllClaimPaths().size, 2)
    }

    @TestCase
    func hasClaimTrueForPresentPath(): Unit {
        let flat = HashMap<String, String>()
        flat["given_name"] = "\"Alice\""
        let q = DefaultDcqlQueryable.fromFlatClaims(flat)
        @Expect(q.hasClaim(singlePath("given_name")), true)
    }

    @TestCase
    func hasClaimFalseForAbsentPath(): Unit {
        let flat = HashMap<String, String>()
        flat["given_name"] = "\"Alice\""
        let q = DefaultDcqlQueryable.fromFlatClaims(flat)
        @Expect(q.hasClaim(singlePath("family_name")), false)
    }

    @TestCase
    func hasClaimWithValueMatches(): Unit {
        let flat = HashMap<String, String>()
        flat["given_name"] = "\"Alice\""
        let q = DefaultDcqlQueryable.fromFlatClaims(flat)
        @Expect(q.hasClaimWithValue(singlePath("given_name"), "\"Alice\""), true)
    }

    @TestCase
    func hasClaimWithValueMismatch(): Unit {
        let flat = HashMap<String, String>()
        flat["given_name"] = "\"Alice\""
        let q = DefaultDcqlQueryable.fromFlatClaims(flat)
        @Expect(q.hasClaimWithValue(singlePath("given_name"), "\"Bob\""), false)
    }

    @TestCase
    func hasClaimWithValueAbsentPath(): Unit {
        let flat = HashMap<String, String>()
        let q = DefaultDcqlQueryable.fromFlatClaims(flat)
        @Expect(q.hasClaimWithValue(singlePath("nope"), "\"x\""), false)
    }
}

// ===========================================================================
// secure_area_signer: jwsAlgorithmName + base64UrlEncode + ctor validation
// ===========================================================================
@Test
class WkSupportSecureAreaSignerUT {

    @TestCase
    func jwsAlgorithmNames(): Unit {
        @Expect(jwsAlgorithmName(SigningAlgorithm.ES256), "ES256")
        @Expect(jwsAlgorithmName(SigningAlgorithm.ES384), "ES384")
        @Expect(jwsAlgorithmName(SigningAlgorithm.ES512), "ES512")
        @Expect(jwsAlgorithmName(SigningAlgorithm.EDDSA), "EdDSA")
        @Expect(jwsAlgorithmName(SigningAlgorithm.UNSET), "none")
    }

    @TestCase
    func base64UrlEncodeKnownVectors(): Unit {
        // "" -> ""
        let empty: Array<UInt8> = []
        @Expect(base64UrlEncode(empty), "")
        // "f" -> "Zg" (no padding)
        let f: Array<UInt8> = [0x66u8]
        @Expect(base64UrlEncode(f), "Zg")
        // "fo" -> "Zm8"
        let fo: Array<UInt8> = [0x66u8, 0x6Fu8]
        @Expect(base64UrlEncode(fo), "Zm8")
        // "foo" -> "Zm9v"
        let foo: Array<UInt8> = [0x66u8, 0x6Fu8, 0x6Fu8]
        @Expect(base64UrlEncode(foo), "Zm9v")
        // "foobar" -> "Zm9vYmFy"
        let foobar: Array<UInt8> = [0x66u8, 0x6Fu8, 0x6Fu8, 0x62u8, 0x61u8, 0x72u8]
        @Expect(base64UrlEncode(foobar), "Zm9vYmFy")
    }

    @TestCase
    func base64UrlUsesUrlSafeAlphabet(): Unit {
        // 0xFB,0xFF,0xFE encodes to "+/+" in standard base64 -> "-_-" url-safe (well-known mapping)
        let bytes: Array<UInt8> = [0xFBu8, 0xFFu8, 0xBFu8]
        let enc = base64UrlEncode(bytes)
        // must not contain standard '+' or '/'
        @Expect(enc.contains("+"), false)
        @Expect(enc.contains("/"), false)
    }

    @TestCase
    func ctorRejectsEdDsa(): Unit {
        var threw = false
        // SecureArea cannot be instantiated; constructor validates algorithm
        // BEFORE touching the secure area, so EdDSA must throw on validation.
        // We use a dummy SecureArea-free path: validation happens first.
        try {
            let _ = SecureAreaSigner(makeDummySecureArea(), "id", 0, CoseEcCurve.P256, SigningAlgorithm.EDDSA, None)
            threw = false
        } catch (e: WalletError) {
            threw = true
        }
        @Expect(threw, true)
    }

    @TestCase
    func ctorRejectsUnset(): Unit {
        var threw = false
        try {
            let _ = SecureAreaSigner(makeDummySecureArea(), "id", 0, CoseEcCurve.P256, SigningAlgorithm.UNSET, None)
            threw = false
        } catch (e: WalletError) {
            threw = true
        }
        @Expect(threw, true)
    }

    @TestCase
    func ctorAcceptsEs256AndExposesFields(): Unit {
        let signer = SecureAreaSigner(makeDummySecureArea(), "cred-1", 3, CoseEcCurve.P256, SigningAlgorithm.ES256, None)
        @Expect(signer.id, "cred-1")
        @Expect(signer.index, 3)
        @Expect(signer.algorithmName(), "ES256")
    }
}

// ===========================================================================
// document_status_service: IgnoreVerifier + service defaults
// ===========================================================================
@Test
class WkSupportDocumentStatusServiceUT {

    @TestCase
    func serviceDefaultsToIgnoreWhenNoVerifier(): Unit {
        // No verifier injected: constructs successfully, falling back to the
        // internal no-op ignore (IgnoreVerifier is now package-internal, mirroring
        // iOS VerifyStatusListTokenSignatureIgnore — not publicly constructible).
        let svc = DocumentStatusService()
        @Expect(svc.clockSkew, 300.0)
    }

    @TestCase
    func serviceConvenienceCtorDefaults(): Unit {
        let svc = DocumentStatusService()
        @Expect(svc.clockSkew, 300.0)
        match (svc.preferredFormat) {
            case StatusListTokenFormat.Jwt => @Expect(true, true)
            case _ => @Expect("wrong-format", "Jwt")
        }
    }

    @TestCase
    func serviceFullCtorHoldsValues(): Unit {
        let svc = DocumentStatusService(clockSkew: 60.0, preferredFormat: StatusListTokenFormat.Cwt)
        @Expect(svc.clockSkew, 60.0)
        match (svc.preferredFormat) {
            case StatusListTokenFormat.Cwt => @Expect(true, true)
            case _ => @Expect("wrong-format", "Cwt")
        }
    }
}

// ===========================================================================
// sdjwt_utils: computeHash digest lengths + unknown-alg throw
// ===========================================================================
@Test
class WkSupportSdJwtComputeHashUT {

    @TestCase
    func sha256Length(): Unit {
        let data: Array<UInt8> = [0x61u8, 0x62u8, 0x63u8]
        let h = SdJwtUtils.computeHash("sha-256", data, CoreDigestImpl())
        @Expect(h.size, 32)
    }

    @TestCase
    func sha384Length(): Unit {
        let data: Array<UInt8> = [0x61u8]
        let h = SdJwtUtils.computeHash("sha-384", data, CoreDigestImpl())
        @Expect(h.size, 48)
    }

    @TestCase
    func sha512Length(): Unit {
        let data: Array<UInt8> = [0x61u8]
        let h = SdJwtUtils.computeHash("sha-512", data, CoreDigestImpl())
        @Expect(h.size, 64)
    }

    @TestCase
    func unknownAlgThrows(): Unit {
        var threw = false
        let data: Array<UInt8> = [0x00u8]
        try {
            let _ = SdJwtUtils.computeHash("md5", data, CoreDigestImpl())
        } catch (e: SdJwtVerifierError) {
            threw = true
        }
        @Expect(threw, true)
    }
}
