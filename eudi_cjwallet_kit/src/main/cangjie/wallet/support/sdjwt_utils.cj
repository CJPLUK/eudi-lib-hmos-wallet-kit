/*
 * sdjwt_utils.cj
 *
 * EUDI Wallet Kit — SD-JWT utility helpers.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Services/SdJwtUtils.swift
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.support  (S-002)
 *
 * iOS SdJwtUtils is a static utility class that:
 *   1. Parses compact SD-JWT tokens using JOSESwift's CompactParser.
 *   2. Extracts the JWT payload, resolves nested `_sd` arrays from disclosures.
 *   3. Computes disclosure hashes (SHA-256/384/512) for `_sd_alg`-driven resolution.
 *
 * Cangjie mapping:
 *   - Uses CompactParser from ohos_app_cangjie_eudi_cjsdjwt.sdjwt.codec (seam-based).
 *   - Uses CoreBase64UrlImpl / CoreDigestImpl from sdjwt seam adapter.
 *   - JSON parsing is minimal: only extracts `_sd_alg` string and `_sd` string arrays.
 *     No full JSON library dependency; uses the same hand-coded patterns used in the
 *     existing sdjwt_verifier.cj.
 *   - `resolveDisclosures` returns a flat map of claimName -> jsonValue so callers can
 *     reconstruct the disclosed claim set.
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.support

import kit.PerformanceAnalysisKit.Hilog

import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.codec.CompactParser
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.model.Disclosure
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.model.SignedSdJwt
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.model.Keys
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.model.SdJwtVerifierError
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.Base64Url
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.CoreBase64UrlImpl
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.CoreDigestImpl

import std.collection.HashMap
import std.collection.ArrayList

// ===========================================================================
// DisclosedClaim — resolved claim from a disclosure
// ===========================================================================

/**
 * A single resolved claim extracted from an SD-JWT disclosure.
 *
 * An object-property disclosure contributes a (name, value) pair.
 * Array-element disclosures are ignored in this utility (array expansion
 * is a consumer concern).
 */
public class DisclosedClaim {
    /** Claim name (e.g. "given_name"). None for array-element disclosures. */
    public let name: ?String
    /** JSON-serialized claim value (e.g. `"Alice"`, `42`, `true`). */
    public let value: String
    /** The base64url-encoded digest of the disclosure (for `_sd` matching). */
    public let digest: String

    public init(name!: ?String, value!: String, digest!: String) {
        this.name = name
        this.value = value
        this.digest = digest
    }
}

// ===========================================================================
// Internal JSON helpers  (no external JSON library)
// ===========================================================================

/**
 * Extract the value of a simple string field from a flat JSON object.
 *
 * Pattern: `"<key>":"<value>"` (whitespace-insensitive) where value has
 * no inner escaped quotes.  Sufficient for `_sd_alg` which is always
 * an algorithm identifier string (e.g. "sha-256").
 *
 * Returns None if the key is absent or the value is not a string.
 */
func extractJsonStringField(json: String, key: String): ?String {
    let needle = "\"" + key + "\""
    let chars = json.toRuneArray()
    let keyBytes = needle.toArray()
    let keyLen = keyBytes.size

    // Scan for the key pattern
    let jsonBytes = json.toArray()
    let jsonLen = jsonBytes.size
    var i: Int64 = 0
    while (i + keyLen <= jsonLen) {
        // Check if jsonBytes[i..i+keyLen] matches keyBytes
        var isMatch = true
        var k: Int64 = 0
        while (k < keyLen) {
            if (jsonBytes[i + k] != keyBytes[k]) {
                isMatch = false
                break
            }
            k += 1
        }
        if (isMatch) {
            // Advance past key, skip whitespace and colon
            var j: Int64 = i + keyLen
            while (j < jsonLen && (jsonBytes[j] == 0x20u8 || jsonBytes[j] == 0x09u8
                    || jsonBytes[j] == 0x0Au8 || jsonBytes[j] == 0x0Du8)) {
                j += 1
            }
            if (j >= jsonLen || jsonBytes[j] != 0x3Au8) {
                // no colon — not our key
                i += 1
                continue
            }
            j += 1  // skip colon
            while (j < jsonLen && (jsonBytes[j] == 0x20u8 || jsonBytes[j] == 0x09u8
                    || jsonBytes[j] == 0x0Au8 || jsonBytes[j] == 0x0Du8)) {
                j += 1
            }
            if (j >= jsonLen || jsonBytes[j] != 0x22u8) {
                return None  // value is not a string
            }
            j += 1  // skip opening quote
            // Collect bytes until unescaped closing quote
            var valueBuf = Array<UInt8>(jsonLen, repeat: 0u8)
            var vLen: Int64 = 0
            var escape = false
            while (j < jsonLen) {
                let b = jsonBytes[j]
                if (escape) {
                    valueBuf[vLen] = b
                    vLen += 1
                    escape = false
                } else if (b == 0x5Cu8) {
                    escape = true
                } else if (b == 0x22u8) {
                    break
                } else {
                    valueBuf[vLen] = b
                    vLen += 1
                }
                j += 1
            }
            return Some(String.fromUtf8(valueBuf[0..vLen]))
        }
        i += 1
    }
    return None
}

/**
 * Decode the payload (middle) part of a compact JWS.
 *
 * Splits on "." and base64url-decodes parts[1].
 * Throws SdJwtVerifierError on malformed input.
 */
func decodeJwtPayloadJson(compact: String, b64: Base64Url): String {
    let parts = compact.split(".")
    if (parts.size != 3) {
        throw SdJwtVerifierError("Invalid compact JWS: expected 3 dot-separated parts; got "
            + parts.size.toString())
    }
    let payloadBytes = b64.decode(parts[1])
    return String.fromUtf8(payloadBytes)
}

// ===========================================================================
// SdJwtUtils
// ===========================================================================

/**
 * Utility functions for working with SD-JWT tokens.
 *
 * Mirrors iOS `enum SdJwtUtils` (static methods).
 *
 * All public methods are static-equivalent (free functions below the class
 * so callers use `SdJwtUtils.parseCompact(...)` style via the class methods).
 */
public class SdJwtUtils {

    // Private constructor: utility class — no instances.
    private init() {}

    // -----------------------------------------------------------------------
    // parseCompact: parse a compact SD-JWT string to SignedSdJwt
    // -----------------------------------------------------------------------

    /**
     * Parse a compact SD-JWT string into a SignedSdJwt.
     *
     * Format: `<JWT>~<disclosure1>~<disclosure2>~[<kbJwt>]`
     *
     * Uses CoreBase64UrlImpl backed by eudi_lib_core_crypto.
     *
     * Mirrors iOS CompactParser.parseCombined usage in SdJwtUtils.
     */
    public static func parseCompact(compact: String): SignedSdJwt {
        let b64 = CoreBase64UrlImpl()
        let parser = CompactParser(b64: b64)
        return parser.parse(compact)
    }

    // -----------------------------------------------------------------------
    // extractJwtPayload: get the payload JSON from the issuer-signed JWT part
    // -----------------------------------------------------------------------

    /**
     * Extract and decode the JWT payload JSON from the issuer-signed JWT.
     *
     * Returns the raw JSON string of the payload claims (e.g. `{"iss":"...","_sd":[...]}`).
     *
     * Mirrors iOS SdJwtUtils.extractJwtClaims usage.
     */
    public static func extractJwtPayload(compact: String): String {
        let b64 = CoreBase64UrlImpl()
        return decodeJwtPayloadJson(compact, b64)
    }

    // -----------------------------------------------------------------------
    // sdAlgorithm: extract `_sd_alg` from the JWT payload
    // -----------------------------------------------------------------------

    /**
     * Extract the `_sd_alg` claim from the JWT payload.
     *
     * Returns the algorithm identifier string, defaulting to "sha-256" if
     * the claim is absent (per SD-JWT spec §5.1.2).
     */
    public static func sdAlgorithm(compact: String): String {
        let payload = extractJwtPayload(compact)
        match (extractJsonStringField(payload, Keys.sdAlg)) {
            case Some(alg) => return alg
            case None => return Keys.defaultSdAlg
        }
    }

    // -----------------------------------------------------------------------
    // resolveDisclosures: build digest->claim map
    // -----------------------------------------------------------------------

    /**
     * Resolve all disclosures in a signed SD-JWT to DisclosedClaim objects.
     *
     * For each disclosure, compute its digest using the `_sd_alg` from the
     * JWT payload, then return the full set as an array.
     *
     * Mirrors iOS `SdJwtUtils.recreateSdJwtClaims` (disclosure resolution pass).
     *
     * callers can then cross-reference against `_sd` arrays in the JWT payload
     * to build the full claim set.
     */
    public static func resolveDisclosures(
        compact: String
    ): Array<DisclosedClaim> {
        let b64 = CoreBase64UrlImpl()
        let digest = CoreDigestImpl()
        let algStr = sdAlgorithm(compact)

        let results = ArrayList<DisclosedClaim>()
        // Split into segments and hash the EXACT received disclosure string. The
        // SD-JWT spec computes each `_sd` digest over the original base64url
        // disclosure string as transmitted — re-encoding the parsed Disclosure (the
        // previous approach) can produce a different string (key order / spacing),
        // yielding a digest that never matches the `_sd` entries, so no claim
        // resolves. Disclosures occupy parts[1 .. size-2]; the last element is the
        // empty trailing-`~` segment or a KB-JWT.
        let parts = compact.split(Keys.disclosureSeparator)
        let discEnd = parts.size - 1
        var i: Int64 = 1
        while (i < discEnd) {
            let seg = parts[i]
            i += 1
            if (seg.isEmpty()) { continue }
            let hashBytes = computeHash(algStr, seg.toArray(), digest)
            let digestStr = b64.encode(hashBytes)
            let disc = Disclosure.decodeWith(seg, b64)
            results.add(DisclosedClaim(
                name: disc.getName(),
                value: disc.getValue(),
                digest: digestStr
            ))
        }
        return results.toArray()
    }

    // -----------------------------------------------------------------------
    // buildClaimMap: name->value map for object-property disclosures
    // -----------------------------------------------------------------------

    /**
     * Build a String->String map of claim name to JSON value for all
     * object-property disclosures in the given compact SD-JWT.
     *
     * Array-element disclosures (name == None) are skipped.
     *
     * Mirrors iOS SdJwtUtils.resolveNestedSdClaims for the flat case.
     */
    public static func buildClaimMap(compact: String): HashMap<String, String> {
        let claims = resolveDisclosures(compact)
        let map = HashMap<String, String>()
        var i: Int64 = 0
        while (i < claims.size) {
            let c = claims[i]
            match (c.name) {
                case Some(n) => map[n] = c.value
                case None => ()
            }
            i += 1
        }
        return map
    }

    // -----------------------------------------------------------------------
    // Internal: digest computation
    // -----------------------------------------------------------------------

    /**
     * Compute the hash of data using the named algorithm.
     *
     * Supported: "sha-256", "sha-384", "sha-512".
     * Throws SdJwtVerifierError for unknown algorithms.
     */
    public static func computeHash(
        algStr: String,
        data: Array<UInt8>,
        digestImpl: CoreDigestImpl
    ): Array<UInt8> {
        if (algStr == "sha-256") {
            return digestImpl.sha256(data)
        } else if (algStr == "sha-384") {
            return digestImpl.sha384(data)
        } else if (algStr == "sha-512") {
            return digestImpl.sha512(data)
        } else {
            throw SdJwtVerifierError("Unsupported _sd_alg: " + algStr)
        }
    }
}
