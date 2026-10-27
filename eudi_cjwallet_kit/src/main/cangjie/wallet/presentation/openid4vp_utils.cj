/*
 * openid4vp_utils.cj
 *
 * EUDI Wallet Kit — OpenID4VP utility functions.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Services/Openid4VpUtils.swift
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.presentation
 *
 * Responsibilities:
 *   - generateMdocGeneratedNonce()    — 16 random bytes → base64url nonce
 *   - generateOpenId4VpHandover()     — OpenID4VP CBOR handover bytes for SessionTranscript
 *   - parseDcqlFormats()              — parse CredentialQuery format + docType per query
 *   - resolveDcql()                   — resolve DCQL against DcqlQueryable map
 *   - getRequestItems()               — convert DCQL ClaimsQuery → RequestItem list
 *   - buildMdocVpToken()              — build CBOR DeviceResponse bytes for mdoc presentation
 *   - buildSdJwtVpToken()             — build SD-JWT presentation string
 *
 * Design decisions:
 *   - All iOS async static methods → synchronous static methods
 *   - iOS SecRandomCopyBytes → eudi_lib_core_crypto.Rng.bytes
 *   - iOS CryptoKit.SHA256 → eudi_lib_core_crypto.Digest.sha256
 *   - iOS Foundation.base64UrlEncoding → eudi_lib_core_crypto.Base64Url.encode
 *   - CBOR handover: CborValue from ohos_app_cangjie_eudi_cjcbor
 *   - Per-credential DcqlQueryable: caller passes HashMap<queryId, DcqlQueryable>
 *
 * R-103: HashMap uses subscript [k] = v for insert.
 * R-104: HashMap reads use .contains() guard.
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.presentation

import kit.PerformanceAnalysisKit.Hilog

import eudi_lib_core_crypto.{Base64Url, Digest, Rng}

import ohos_app_cangjie_eudi_cjcbor.cbor.CborValue

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.DCQL
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.CredentialQuery
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.ClaimsQuery
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.ClaimPath
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.ClaimPathElement
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.ClaimName
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.VerifiablePresentation
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.GenericPresentation
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.Format

import ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.DcqlQueryable
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.pathKey
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.WalletError

import ohos_app_cangjie_eudi_cjmdoc_transfer.transfer.framing.RequestItem

import std.collection.ArrayList
import std.collection.HashMap
import stdx.encoding.json.JsonValue
import stdx.encoding.json.JsonObject
import stdx.encoding.json.JsonArray
import stdx.encoding.json.JsonString

// ===========================================================================
// DcqlFormatEntry — per-credential-query format + docType
// Mirrors iOS parseDcqlFormats return type
// ===========================================================================

/**
 * Format descriptor for a DCQL credential query.
 * Mirrors iOS OpenId4VpUtils.DcqlFormatEntry used in parseDcqlFormats.
 */
public class DcqlFormatEntry {
    /** The credential query ID (from DCQL). */
    public let queryId: String
    /** The credential format string ("mso_mdoc" / "vc+sd-jwt" / etc.). */
    public let format: String
    /** The docType (for mso_mdoc) or vct (for sd-jwt-vc); None for other formats. */
    public let docType: ?String

    public init(queryId: String, format: String, docType: ?String) {
        this.queryId = queryId
        this.format = format
        this.docType = docType
    }
}

// ===========================================================================
// Openid4VpUtils — static utility methods
// Mirrors iOS enum Openid4VpUtils (used as namespace)
// ===========================================================================

/**
 * Static utility methods for OpenID4VP flows.
 * Mirrors iOS class Openid4VpUtils (namespace pattern — no instances).
 */
public class Openid4VpUtils {

    // -----------------------------------------------------------------------
    // Nonce generation
    // -----------------------------------------------------------------------

    /**
     * Generate a 16-byte random nonce and return it base64url-encoded.
     * Used as the "mdocGeneratedNonce" in OpenID4VP handover structures.
     *
     * Mirrors iOS Openid4VpUtils.generateMdocGeneratedNonce()
     *   → SecRandomCopyBytes(kSecRandomDefault, 16) + base64UrlEncodedString
     *
     * Uses eudi_lib_core_crypto.Rng.bytes + Base64Url.encode.
     */
    public static func generateMdocGeneratedNonce(): String {
        let randomBytes = Rng.bytes(16)
        return Base64Url.encode(randomBytes)
    }

    // -----------------------------------------------------------------------
    // OpenID4VP Handover generation
    // -----------------------------------------------------------------------

    /**
     * Generate the OpenID4VP handover bytes for inclusion in SessionTranscript.
     *
     * The handover is a CBOR array:
     *   ["OpenID4VPHandover", SHA256(clientId || responseUri || nonce || mdocGeneratedNonce)]
     *
     * Where the hash input is the CBOR-encoded array of these four tText strings.
     *
     * Mirrors iOS Openid4VpUtils.generateOpenId4VpHandover(clientId:responseUri:nonce:mdocGeneratedNonce:)
     *
     * @param clientId            — verifier client_id from the authorization request
     * @param responseUri         — response_uri (directPost endpoint)
     * @param nonce               — nonce from the authorization request
     * @param mdocGeneratedNonce  — locally generated nonce (from generateMdocGeneratedNonce())
     * @return raw CBOR bytes of the OID4VP handover array
     */
    public static func generateOpenId4VpHandover(
        clientId: String,
        responseUri: String,
        nonce: String,
        mdocGeneratedNonce: String
    ): Array<UInt8> {
        // Step 1: CBOR-encode the [clientId, responseUri, nonce, mdocGeneratedNonce] array
        let innerItems = ArrayList<CborValue>()
        innerItems.add(CborValue.TextStringVal(clientId))
        innerItems.add(CborValue.TextStringVal(responseUri))
        innerItems.add(CborValue.TextStringVal(nonce))
        innerItems.add(CborValue.TextStringVal(mdocGeneratedNonce))
        let innerCbor = CborValue.ArrayVal(innerItems).encode()

        // Step 2: SHA256 hash of the inner CBOR array bytes
        let hashBytes = Digest.sha256(innerCbor)

        // Step 3: Wrap in the OID4VP handover CBOR structure:
        //   ["OID4VPHandover", <hash bytes>]
        //   (per ISO 18013-7 Annex B / EUDI wallet spec)
        let outerItems = ArrayList<CborValue>()
        outerItems.add(CborValue.TextStringVal("OID4VPHandover"))
        outerItems.add(CborValue.ByteStringVal(hashBytes))
        return CborValue.ArrayVal(outerItems).encode()
    }

    // -----------------------------------------------------------------------
    // DCQL format parsing
    // -----------------------------------------------------------------------

    /**
     * Parse the format and docType from each DCQL CredentialQuery.
     *
     * For mso_mdoc format: extracts docType from the "meta.doctype_value" JSON
     *   in the query's metaJson field, or falls back to the queryId.
     * For vc+sd-jwt and dc+sd-jwt: extracts vct from meta.vct_values[0], or queryId.
     *
     * Mirrors iOS Openid4VpUtils.parseDcqlFormats(_:idsToDocTypes:)
     *
     * @param dcql            — the DCQL query from the resolved request
     * @return list of DcqlFormatEntry per credential query
     */
    public static func parseDcqlFormats(dcql: DCQL): ArrayList<DcqlFormatEntry> {
        let result = ArrayList<DcqlFormatEntry>()
        var i: Int64 = 0
        while (i < dcql.credentials.size) {
            let cq = dcql.credentials[i]
            let queryId = cq.queryId.value
            let fmt = cq.format.format
            var docType: ?String = None

            if (fmt == "mso_mdoc") {
                // Extract doctype_value from meta JSON
                docType = extractMetaStringField(cq.metaJson, "doctype_value")
                if (docType.isNone()) {
                    docType = Some(queryId)
                }
            } else if (fmt == "vc+sd-jwt" || fmt == "dc+sd-jwt") {
                // Extract first vct_values entry from meta JSON
                docType = extractMetaFirstArrayEntry(cq.metaJson, "vct_values")
                if (docType.isNone()) {
                    docType = Some(queryId)
                }
            } else {
                // Generic: use queryId as identifier
                docType = Some(queryId)
            }

            result.add(DcqlFormatEntry(queryId, fmt, docType))
            i += 1
        }
        return result
    }

    // -----------------------------------------------------------------------
    // DCQL resolution
    // -----------------------------------------------------------------------

    /**
     * Resolve a DCQL query against a map of per-credential DcqlQueryable instances.
     *
     * Returns a map from queryId → Array<ClaimPath> of matched claims.
     * Throws WalletError if no credential can satisfy any required credential query.
     *
     * Mirrors iOS Openid4VpUtils.resolveDcql(dcql:credentialQueryables:allowPartialClaims:)
     *
     * @param dcql                — the DCQL to resolve
     * @param queryables          — map from queryId → DcqlQueryable (one per query)
     * @param allowPartialClaims  — if true, skip missing claims instead of failing
     * @return map from queryId → matched ClaimPath list
     */
    public static func resolveDcql(
        dcql: DCQL,
        queryables: HashMap<String, DcqlQueryable>,
        allowPartialClaims: Bool
    ): HashMap<String, ArrayList<ClaimPath>> {
        let result = HashMap<String, ArrayList<ClaimPath>>()
        var i: Int64 = 0
        while (i < dcql.credentials.size) {
            let cq = dcql.credentials[i]
            let queryId = cq.queryId.value

            if (!queryables.contains(queryId)) {
                Hilog.warn(0, "Openid4VpUtils",
                    "No queryable found for queryId=" + queryId)
                i += 1
                continue
            }
            let queryable = queryables[queryId]

            // Resolve claims for this credential query
            let matchedPaths = resolveCredentialQuery(cq, queryable, allowPartialClaims)
            result[queryId] = matchedPaths
            i += 1
        }
        return result
    }

    /**
     * Convert DCQL ClaimsQuery list to RequestItem list for mdoc request building.
     *
     * For mso_mdoc: ClaimPath = [namespace, elementId] → RequestItem([elementId], intentToRetain)
     * For sd-jwt: ClaimPath = [claimName, ...] → RequestItem([...], false)
     *
     * Mirrors iOS Openid4VpUtils.getRequestItems(claims:intentToRetain:)
     *
     * @param claims           — ClaimsQuery list from the CredentialQuery
     * @param defaultIntentToRetain — default if not specified in query
     * @return list of RequestItem for this credential
     */
    public static func getRequestItems(
        claims: Array<ClaimsQuery>,
        defaultIntentToRetain: Bool
    ): ArrayList<RequestItem> {
        let result = ArrayList<RequestItem>()
        var i: Int64 = 0
        while (i < claims.size) {
            let cq = claims[i]
            let pathElements = cq.path.value
            let retain = match (cq.intentToRetain) {
                case Some(b) => b
                case None => defaultIntentToRetain
            }
            // Convert ClaimPath elements to string path
            let pathStrs = ArrayList<String>()
            var j: Int64 = 0
            while (j < pathElements.size) {
                let elem = pathElements[j]
                pathStrs.add(elem.description())
                j += 1
            }
            result.add(RequestItem(pathStrs.toArray(), Some(retain), Some(false)))
            i += 1
        }
        return result
    }

    // -----------------------------------------------------------------------
    // VP token building helpers
    // -----------------------------------------------------------------------

    /**
     * Build a base64url-encoded CBOR presentation token string for inclusion in
     * a DCQL VP token map.
     *
     * For mso_mdoc: the deviceResponseBytes (already CBOR-encoded DeviceResponse)
     * are base64url-encoded and wrapped in the "GenericPresentation" format.
     *
     * Mirrors iOS Openid4VpUtils.makeCredentialMap / makeCborClaimData.
     *
     * @param deviceResponseBytes — raw CBOR DeviceResponse bytes
     * @return base64url-encoded presentation string
     */
    public static func buildMdocVpToken(deviceResponseBytes: Array<UInt8>): String {
        return Base64Url.encode(deviceResponseBytes)
    }

    /**
     * Build an SD-JWT presentation string for inclusion in a DCQL VP token map.
     *
     * @param sdJwtString — the SD-JWT string from the credential store
     * @param keyBinding  — optional key-binding JWT appended with "~"
     * @return SD-JWT~KB-JWT or SD-JWT string
     */
    public static func buildSdJwtVpToken(sdJwtString: String, keyBinding: ?String): String {
        match (keyBinding) {
            case Some(kb) => return sdJwtString + "~" + kb
            case None => return sdJwtString
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /** Resolve claims for a single CredentialQuery against a DcqlQueryable. */
    private static func resolveCredentialQuery(
        cq: CredentialQuery,
        queryable: DcqlQueryable,
        allowPartialClaims: Bool
    ): ArrayList<ClaimPath> {
        let matched = ArrayList<ClaimPath>()
        match (cq.claims) {
            case None =>
                // No claims filter: include all available paths
                let allPaths = queryable.getAllClaimPaths()
                var k: Int64 = 0
                while (k < allPaths.size) {
                    matched.add(allPaths[k])
                    k += 1
                }
            case Some(claimQueries) =>
                var j: Int64 = 0
                while (j < claimQueries.size) {
                    let cqItem = claimQueries[j]
                    if (queryable.hasClaim(cqItem.path)) {
                        matched.add(cqItem.path)
                    } else if (!allowPartialClaims) {
                        Hilog.warn(0, "Openid4VpUtils",
                            "Claim path not found: " + pathKey(cqItem.path))
                    }
                    j += 1
                }
        }
        return matched
    }

    /**
     * Extract a string field from a JSON meta string.
     * Example: metaJson = `{"doctype_value": "org.iso.18013.5.1.mDL"}`
     *          field = "doctype_value" → "org.iso.18013.5.1.mDL"
     */
    private static func extractMetaStringField(metaJson: ?String, field: String): ?String {
        match (metaJson) {
            case None => return None
            case Some(js) =>
                try {
                    let parsed = JsonValue.fromStr(js)
                    match (parsed) {
                        case obj: JsonObject =>
                            match (obj.get(field)) {
                                case Some(s: JsonString) => return Some(s.getValue())
                                case _ => return None
                            }
                        case _ => return None
                    }
                } catch (_: Exception) {
                    return None
                }
        }
    }

    /**
     * Extract the first element of a JSON array field from a meta string.
     * Example: metaJson = `{"vct_values": ["urn:credential:pid"]}`
     *          field = "vct_values" → "urn:credential:pid"
     */
    private static func extractMetaFirstArrayEntry(metaJson: ?String, field: String): ?String {
        match (metaJson) {
            case None => return None
            case Some(js) =>
                try {
                    let parsed = JsonValue.fromStr(js)
                    match (parsed) {
                        case obj: JsonObject =>
                            match (obj.get(field)) {
                                case Some(arr: JsonArray) =>
                                    let items = arr.getItems()
                                    if (items.isEmpty()) { return None }
                                    match (items[0]) {
                                        case s: JsonString => return Some(s.getValue())
                                        case _ => return None
                                    }
                                case _ => return None
                            }
                        case _ => return None
                    }
                } catch (_: Exception) {
                    return None
                }
        }
    }
}
