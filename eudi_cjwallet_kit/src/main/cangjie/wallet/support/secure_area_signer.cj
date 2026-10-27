/*
 * secure_area_signer.cj
 *
 * EUDI Wallet Kit — SecureAreaSigner.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Services/SecureAreaSigner.swift
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.support  (S-002)
 *
 * iOS SecureAreaSigner implements AsyncSignerProtocol (JOSESwift) and signs
 * JWT data using the mdoc SecureArea abstraction.
 *
 * Cangjie mapping:
 *   - SecureArea.signature() is synchronous (async iOS -> sync Cangjie per
 *     the SecureArea interface contract in mdoc-data-model).
 *   - No JOSE dependency; callers produce the signing input (base64url-encoded
 *     header.payload) and SecureAreaSigner returns raw ECDSA signature bytes.
 *   - SigningAlgorithm comes from ohos_app_cangjie_eudi_cjmdoc_data_model.
 *   - WalletError from wallet.models is used for error signalling.
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.support

import kit.PerformanceAnalysisKit.Hilog

import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.SecureArea
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.CoseEcCurve
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.SigningAlgorithm

import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.WalletError

// ===========================================================================
// Signing algorithm helpers
// ===========================================================================

/**
 * Validate that the given SigningAlgorithm is supported for JWT signing.
 * iOS getSignatureAlgorithm: throws for EdDSA (not JOSE-supported).
 * Cangjie: throws WalletError for EdDSA or UNSET.
 */
func validateJwsAlgorithm(algorithm: SigningAlgorithm): Unit {
    match (algorithm) {
        case SigningAlgorithm.ES256 => ()
        case SigningAlgorithm.ES384 => ()
        case SigningAlgorithm.ES512 => ()
        case SigningAlgorithm.EDDSA =>
            throw WalletError.withDescription("EdDSA is not supported for JWS signing in this implementation.")
        case SigningAlgorithm.UNSET =>
            throw WalletError.withDescription("Invalid signing algorithm: UNSET.")
    }
}

/**
 * Return a JWS algorithm name string for the given SigningAlgorithm.
 * iOS: JOSESwift.SignatureAlgorithm.rawValue ("ES256" / "ES384" / "ES512").
 */
public func jwsAlgorithmName(algorithm: SigningAlgorithm): String {
    match (algorithm) {
        case SigningAlgorithm.ES256 => return "ES256"
        case SigningAlgorithm.ES384 => return "ES384"
        case SigningAlgorithm.ES512 => return "ES512"
        case SigningAlgorithm.EDDSA => return "EdDSA"
        case SigningAlgorithm.UNSET => return "none"
    }
}

// ===========================================================================
// Base64URL helpers (no external deps)
// ===========================================================================

/** Base64URL encoding table (RFC 4648 §5, no padding). */
let B64URL_TABLE: Array<UInt8> = [
    0x41u8, 0x42u8, 0x43u8, 0x44u8, 0x45u8, 0x46u8, 0x47u8, 0x48u8,
    0x49u8, 0x4Au8, 0x4Bu8, 0x4Cu8, 0x4Du8, 0x4Eu8, 0x4Fu8, 0x50u8,
    0x51u8, 0x52u8, 0x53u8, 0x54u8, 0x55u8, 0x56u8, 0x57u8, 0x58u8,
    0x59u8, 0x5Au8, 0x61u8, 0x62u8, 0x63u8, 0x64u8, 0x65u8, 0x66u8,
    0x67u8, 0x68u8, 0x69u8, 0x6Au8, 0x6Bu8, 0x6Cu8, 0x6Du8, 0x6Eu8,
    0x6Fu8, 0x70u8, 0x71u8, 0x72u8, 0x73u8, 0x74u8, 0x75u8, 0x76u8,
    0x77u8, 0x78u8, 0x79u8, 0x7Au8, 0x30u8, 0x31u8, 0x32u8, 0x33u8,
    0x34u8, 0x35u8, 0x36u8, 0x37u8, 0x38u8, 0x39u8, 0x2Du8, 0x5Fu8
]

/**
 * Encode bytes as base64url (no padding).
 * Used to build the signing input: base64url(header) + "." + base64url(payload).
 */
public func base64UrlEncode(data: Array<UInt8>): String {
    let n = data.size
    let outLen = (n + 2) / 3 * 4
    let out = Array<UInt8>(outLen, repeat: 0u8)
    var i: Int64 = 0
    var o: Int64 = 0
    while (i + 2 < n) {
        let b0 = Int64(data[i])
        let b1 = Int64(data[i + 1])
        let b2 = Int64(data[i + 2])
        out[o]     = B64URL_TABLE[(b0 >> 2) & 0x3F]
        out[o + 1] = B64URL_TABLE[((b0 << 4) | (b1 >> 4)) & 0x3F]
        out[o + 2] = B64URL_TABLE[((b1 << 2) | (b2 >> 6)) & 0x3F]
        out[o + 3] = B64URL_TABLE[b2 & 0x3F]
        i += 3
        o += 4
    }
    if (i < n) {
        let b0 = Int64(data[i])
        let b1: Int64 = if (i + 1 < n) { Int64(data[i + 1]) } else { 0 }
        out[o]     = B64URL_TABLE[(b0 >> 2) & 0x3F]
        out[o + 1] = B64URL_TABLE[((b0 << 4) | (b1 >> 4)) & 0x3F]
        if (i + 1 < n) {
            out[o + 2] = B64URL_TABLE[(b1 << 2) & 0x3F]
            o += 3
        } else {
            o += 2
        }
    }
    return String.fromUtf8(out[0..o])
}

// ===========================================================================
// SecureAreaSigner
// ===========================================================================

/**
 * Signs JWT data using a SecureArea key batch entry.
 *
 * Mirrors iOS SecureAreaSigner (AsyncSignerProtocol).
 *
 * iOS async throws -> Cangjie synchronous throws.
 *
 * The caller constructs the JWT header+payload, then calls:
 *   signer.sign(signingInput)  — returns raw ECDSA bytes (r||s, 64B for ES256)
 *   signer.signJwtParts(header, payload)  — builds base64url(header).base64url(payload) then signs
 *
 * Note: this class does NOT hold a JWK public key (no JOSE dependency).
 * The caller is responsible for embedding the public key in the JWT header.
 */
public class SecureAreaSigner {

    /** Credential identifier (batch id). */
    public let id: String

    /** Index within the key batch. */
    public let index: Int64

    /** The SecureArea that holds the private key. */
    public let secureArea: SecureArea

    /** Curve of the key. */
    public let curve: CoseEcCurve

    /** Signing algorithm (ES256 / ES384 / ES512). */
    public let algorithm: SigningAlgorithm

    /** Optional unlock data (e.g. biometric challenge response). */
    public let unlockData: ?Array<UInt8>

    /**
     * Construct a SecureAreaSigner.
     *
     * Throws WalletError if the algorithm is EdDSA or UNSET (not supported for JWT signing).
     */
    public init(
        secureArea: SecureArea,
        id: String,
        index: Int64,
        curve: CoseEcCurve,
        algorithm: SigningAlgorithm,
        unlockData: ?Array<UInt8>
    ) {
        validateJwsAlgorithm(algorithm)
        this.id = id
        this.index = index
        this.secureArea = secureArea
        this.curve = curve
        this.algorithm = algorithm
        this.unlockData = unlockData
    }

    /**
     * Sign raw bytes with the secure area key.
     *
     * Returns raw ECDSA signature bytes (r||s, 64 bytes for ES256).
     * Mirrors iOS SecureAreaSigner.sign(_ signingInput: Data).
     */
    public func sign(signingInput: Array<UInt8>): Array<UInt8> {
        Hilog.info(0, "SecureAreaSigner", "sign id=" + id + " index=" + index.toString()
            + " alg=" + jwsAlgorithmName(algorithm))
        return secureArea.signature(id, index, algorithm, signingInput, unlockData)
    }

    /**
     * Sign a JWT by building base64url(header).base64url(payload) then calling sign().
     *
     * Mirrors iOS SecureAreaSigner.signAsync(_ header: Data, _ payload: Data).
     * header and payload are raw bytes of the JOSE header and JWT claims respectively.
     *
     * Returns raw ECDSA signature bytes.
     */
    public func signJwtParts(header: Array<UInt8>, payload: Array<UInt8>): Array<UInt8> {
        Hilog.info(0, "SecureAreaSigner", "signJwtParts id=" + id)
        let headerB64 = base64UrlEncode(header)
        let payloadB64 = base64UrlEncode(payload)
        let signingInput = (headerB64 + "." + payloadB64).toArray()
        return sign(signingInput)
    }

    /** JWS algorithm name string ("ES256" etc.) for embedding in the JWT header. */
    public func algorithmName(): String {
        return jwsAlgorithmName(algorithm)
    }
}
