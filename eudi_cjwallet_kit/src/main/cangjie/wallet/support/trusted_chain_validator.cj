/*
 * trusted_chain_validator.cj
 *
 * EUDI Wallet Kit — TrustedChainValidator.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Services/TrustedChainValidator.swift
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.support  (S-002)
 *
 * iOS TrustedChainValidator holds an array of root certificates (IACA roots)
 * and validates document x5chain arrays using SecureEnclave + iOS Security.
 *
 * Cangjie mapping:
 *   - Root certificates stored as Array<Cert> objects (pre-parsed from PEM/DER).
 *   - Chain validation uses `verifyChain(leaf:, intermediates:, roots:)` from
 *     ohos_app_cangjie_eudi_cjx509.x509.core.
 *   - Chain input: Array<String> where each string is a base64-encoded DER certificate.
 *     parts[0] = leaf, parts[1..n-1] = intermediates.
 *   - Base64 decoding: stdlib std.convert or std.encoding.base64 (standard padding).
 *     The x5chain uses standard base64 (with padding), not base64url.
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.support

import kit.PerformanceAnalysisKit.Hilog

import ohos_app_cangjie_eudi_cjx509.x509.core.Cert
import ohos_app_cangjie_eudi_cjx509.x509.core.CertError
import ohos_app_cangjie_eudi_cjx509.x509.core.verifyChain
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.config.CertChainTrust

import std.collection.ArrayList

// ===========================================================================
// Base64 (standard, with padding) — used for x5chain cert decoding
// ===========================================================================

/**
 * Decode a standard base64 string (padded, +/ alphabet) to bytes.
 *
 * x5chain entries are base64-encoded DER, NOT base64url.
 * Implemented inline without external dependency.
 */
func decodeBase64Standard(s: String): Array<UInt8> {
    let sBytes = s.toArray()
    let n = sBytes.size

    // Build lookup table: value 255 = invalid
    let lookup = Array<UInt8>(256, repeat: 255u8)
    var ci: Int64 = 0
    // 'A'-'Z' -> 0..25
    while (ci < 26) {
        lookup[Int64(0x41u8) + ci] = UInt8(ci)
        ci += 1
    }
    // 'a'-'z' -> 26..51
    ci = 0
    while (ci < 26) {
        lookup[Int64(0x61u8) + ci] = UInt8(26 + ci)
        ci += 1
    }
    // '0'-'9' -> 52..61
    ci = 0
    while (ci < 10) {
        lookup[Int64(0x30u8) + ci] = UInt8(52 + ci)
        ci += 1
    }
    // '+' -> 62, '/' -> 63
    lookup[0x2B] = 62u8
    lookup[0x2F] = 63u8

    // Strip whitespace and padding
    var clean = ArrayList<UInt8>()
    var si: Int64 = 0
    while (si < n) {
        let b = sBytes[si]
        if (b != 0x20u8 && b != 0x09u8 && b != 0x0Au8 && b != 0x0Du8 && b != 0x3Du8) {
            clean.add(b)
        }
        si += 1
    }
    let cleanArr = clean.toArray()
    let cn = cleanArr.size

    // Each group of 4 base64 chars produces 3 bytes (with padding)
    let outLen = (cn * 3) / 4
    let out = Array<UInt8>(outLen, repeat: 0u8)
    var i: Int64 = 0
    var o: Int64 = 0
    while (i + 3 < cn) {
        let v0 = Int64(lookup[Int64(cleanArr[i])])
        let v1 = Int64(lookup[Int64(cleanArr[i + 1])])
        let v2 = Int64(lookup[Int64(cleanArr[i + 2])])
        let v3 = Int64(lookup[Int64(cleanArr[i + 3])])
        out[o]     = UInt8((v0 << 2) | (v1 >> 4))
        out[o + 1] = UInt8(((v1 & 0xF) << 4) | (v2 >> 2))
        out[o + 2] = UInt8(((v2 & 0x3) << 6) | v3)
        i += 4
        o += 3
    }
    if (i + 1 < cn) {
        let v0 = Int64(lookup[Int64(cleanArr[i])])
        let v1 = Int64(lookup[Int64(cleanArr[i + 1])])
        out[o] = UInt8((v0 << 2) | (v1 >> 4))
        o += 1
        if (i + 2 < cn) {
            let v2 = Int64(lookup[Int64(cleanArr[i + 2])])
            out[o] = UInt8(((v1 & 0xF) << 4) | (v2 >> 2))
            o += 1
        }
    }
    return out[0..o]
}

// ===========================================================================
// TrustedChainValidator
// ===========================================================================

/**
 * Validates x5chain certificate chains against a set of trusted IACA root certificates.
 *
 * Mirrors iOS TrustedChainValidator struct.
 *
 * Usage:
 *   let roots: Array<Cert> = ...  // parsed from IACA root PEM/DER bytes
 *   let validator = TrustedChainValidator(trustedRoots: roots)
 *   let isValid = validator.isValid(chain: certBase64Strings)
 */
public class TrustedChainValidator <: CertChainTrust {

    /**
     * Trusted IACA root certificates (eager mode; empty in lazy mode).
     * Mirrors iOS `iacaRoots: [x5chain]`.
     */
    public let trustedRoots: Array<Cert>

    /**
     * Lazy anchor source: when present, roots are resolved on each isValid()
     * call from these DER anchors (e.g. accessTrustManager.trustAnchorsDer()).
     * A throwing/empty source degrades to a false verdict, never propagates —
     * mirrors iOS's injected CertificateChainTrust resolving anchors on demand.
     */
    private let lazyRootDers: ?(() -> Array<Array<UInt8>>)

    /**
     * Construct a validator with the given trusted root certificates (eager).
     *
     * @param trustedRoots  Array of pre-parsed root Cert objects.
     */
    public init(trustedRoots: Array<Cert>) {
        this.trustedRoots = trustedRoots
        this.lazyRootDers = None
    }

    /**
     * Construct a lazy validator: anchors are fetched (via the given closure)
     * only when a chain is actually validated, so startup never touches the
     * network. The closure returns DER anchors; a throw/empty result inside
     * isValid() yields a fail-closed `false`.
     */
    public init(lazyRootDers: () -> Array<Array<UInt8>>) {
        this.trustedRoots = Array<Cert>()
        this.lazyRootDers = lazyRootDers
    }

    /**
     * Validate a certificate chain against the trusted roots.
     *
     * @param chain  Array of base64-encoded DER certificates. chain[0] is the leaf;
     *               chain[1..n-1] are intermediate CAs.
     * @return true if the chain is valid and trusted; false otherwise.
     *
     * Mirrors iOS TrustedChainValidator.isValid(chain: [String]) -> Bool.
     */
    public func isValid(chain: Array<String>): Bool {
        if (chain.size == 0) {
            Hilog.warn(0, "TrustedChainValidator", "isValid: empty chain")
            return false
        }

        // Parse leaf certificate (chain[0])
        let leafCert: Cert
        try {
            let leafDer = decodeBase64Standard(chain[0])
            leafCert = Cert.fromDer(leafDer)
        } catch (e: Exception) {
            Hilog.warn(0, "TrustedChainValidator",
                "isValid: failed to parse leaf cert: " + e.message)
            return false
        }

        // Parse intermediates (chain[1..n-1])
        let intermediates = ArrayList<Cert>()
        var i: Int64 = 1
        while (i < chain.size) {
            try {
                let derBytes = decodeBase64Standard(chain[i])
                let cert = Cert.fromDer(derBytes)
                intermediates.add(cert)
            } catch (e: Exception) {
                Hilog.warn(0, "TrustedChainValidator",
                    "isValid: failed to parse intermediate[" + i.toString() + "]: "
                    + e.message)
                return false
            }
            i += 1
        }

        // Resolve roots for this call: lazy source (fail-closed on throw/empty)
        // or the eager set. Lazy mode is where LoTE anchors are pulled on demand.
        let roots: Array<Cert>
        match (this.lazyRootDers) {
            case Some(src) =>
                let ders = try {
                    src()
                } catch (e: Exception) {
                    Hilog.warn(0, "TrustedChainValidator",
                        "isValid: lazy root source threw: " + e.message)
                    return false
                }
                let parsed = ArrayList<Cert>()
                for (d in ders) {
                    try { parsed.add(Cert.fromDer(d)) } catch (_: Exception) { () }
                }
                if (parsed.size == 0) {
                    Hilog.warn(0, "TrustedChainValidator", "isValid: no usable lazy roots")
                    return false
                }
                roots = parsed.toArray()
            case None =>
                roots = this.trustedRoots
        }

        // Verify chain
        try {
            let interArray = intermediates.toArray()
            let result = verifyChain(
                leafCert,
                interArray,
                roots,
                date: None
            )
            Hilog.info(0, "TrustedChainValidator",
                "isValid: chain verification result=" + result.toString())
            return result
        } catch (e: Exception) {
            Hilog.warn(0, "TrustedChainValidator",
                "isValid: verifyChain threw: " + e.message)
            return false
        }
    }

    /**
     * Build a TrustedChainValidator from PEM-encoded root certificates.
     *
     * Each element of `pemStrings` may contain one or more PEM certificates.
     * Throws CertError if any PEM is malformed.
     */
    public static func fromPem(pemStrings: Array<String>): TrustedChainValidator {
        let roots = ArrayList<Cert>()
        var i: Int64 = 0
        while (i < pemStrings.size) {
            let certs = Cert.fromPem(pemStrings[i])
            var j: Int64 = 0
            while (j < certs.size) {
                roots.add(certs[j])
                j += 1
            }
            i += 1
        }
        return TrustedChainValidator(roots.toArray())
    }

    /**
     * Build a TrustedChainValidator from DER-encoded root certificates.
     *
     * Each element of `derArrays` is a raw DER byte array.
     * Throws CertError if any DER is malformed.
     */
    public static func fromDer(derArrays: Array<Array<UInt8>>): TrustedChainValidator {
        let roots = ArrayList<Cert>()
        var i: Int64 = 0
        while (i < derArrays.size) {
            let cert = Cert.fromDer(derArrays[i])
            roots.add(cert)
            i += 1
        }
        return TrustedChainValidator(roots.toArray())
    }
}
