/*
 * dcql_queryable.cj
 *
 * EUDI Wallet Kit — DcqlQueryable interface and DefaultDcqlQueryable implementation.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Services/DcqlQueryable.swift
 *   Sources/EudiWalletKit/Models/Enumerations.swift  (FlowType / DocTypedData / PopUsage)
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.support  (S-002)
 *
 * iOS DcqlQueryable is a protocol that credential types implement to support
 * DCQL (Digital Credentials Query Language) queries.  DefaultDcqlQueryable is
 * a class-based default implementation.
 *
 * Cangjie mapping:
 *   - DcqlQueryable → interface
 *   - DefaultDcqlQueryable → class implementing DcqlQueryable
 *   - ClaimPath from ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql
 *   - No iOS Sequence/SwiftUI dependencies
 *   - R-104 safe: all HashMap accesses guarded with contains()
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.support

import kit.PerformanceAnalysisKit.Hilog

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.ClaimPath
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.ClaimPathElement
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.ClaimName

import std.collection.HashMap
import std.collection.ArrayList

// ===========================================================================
// FlowType — transport / protocol used for presentation
// ===========================================================================

/**
 * Transport protocol used for a credential exchange flow.
 *
 * Mirrors iOS enum FlowType in Enumerations.swift.
 */
public enum FlowType {
    /** Bluetooth Low Energy proximity presentation (ISO 18013-5). */
    | Ble
    /** Remote presentation via OpenID4VP. Carries the authorization-request
     *  URI bytes (iOS `case openid4vp(qrCode: Data)`) — the service resolves
     *  the verifier request from this URI. */
    | OpenId4Vp(Array<UInt8>)
    /** Other / unspecified transport. */
    | Other

    public func rawValue(): String {
        match (this) {
            case Ble          => return "ble"
            case OpenId4Vp(_) => return "openid4vp"
            case Other        => return "other"
        }
    }

    public static func fromRaw(raw: String): ?FlowType {
        match (raw) {
            case "ble"       => return Some(FlowType.Ble)
            case "openid4vp" => return Some(FlowType.OpenId4Vp(Array<UInt8>()))
            case "other"     => return Some(FlowType.Other)
            case _ => return None
        }
    }
}

// ===========================================================================
// DocTypedData — credential format
// ===========================================================================

/**
 * Discriminates between mdoc and SD-JWT credential formats.
 *
 * Mirrors iOS enum DocTypedData in Enumerations.swift.
 */
public enum DocTypedData {
    /** ISO/IEC 18013-5 mobile document (CBOR/COSE). */
    | MsoMdoc(String)
    /** SD-JWT-VC (RFC 7519 + SD-JWT). */
    | SdJwt(String)

    /** The document type string (docType for mDL; vct for SD-JWT-VC). */
    public func docType(): String {
        match (this) {
            case MsoMdoc(dt) => return dt
            case SdJwt(dt)   => return dt
        }
    }

    /** Whether this is an SD-JWT credential. */
    public func isSdJwt(): Bool {
        match (this) {
            case SdJwt(_) => return true
            case _        => return false
        }
    }

    /** Whether this is an MSO mDoc credential. */
    public func isMsoMdoc(): Bool {
        match (this) {
            case MsoMdoc(_) => return true
            case _          => return false
        }
    }
}

// ===========================================================================
// PopUsage — DPoP / key-binding proof purpose
// ===========================================================================

/**
 * Intended usage of a Proof of Possession (PoP).
 *
 * Mirrors iOS enum PopUsage in Enumerations.swift.
 */
public enum PopUsage {
    /** DPoP binding key for token requests. */
    | DPop
    /** Client attestation JWT signing key. */
    | ClientAttestation

    public func rawValue(): String {
        match (this) {
            case DPop              => return "dpop"
            case ClientAttestation => return "client_attestation"
        }
    }

    public static func fromRaw(raw: String): ?PopUsage {
        match (raw) {
            case "dpop"              => return Some(PopUsage.DPop)
            case "client_attestation" => return Some(PopUsage.ClientAttestation)
            case _ => return None
        }
    }
}

// ===========================================================================
// DcqlQueryable — interface
// ===========================================================================

/**
 * Protocol for credential objects that can be queried via DCQL.
 *
 * Mirrors iOS protocol DcqlQueryable.
 *
 * Credential types implementing this interface allow the DCQL engine to
 * select and filter credentials without knowledge of the internal format.
 */
public interface DcqlQueryable {

    /**
     * Return all claim paths available in this credential.
     *
     * Mirrors iOS DcqlQueryable.getAllClaimPaths() -> [ClaimPath].
     */
    func getAllClaimPaths(): Array<ClaimPath>

    /**
     * Return whether the credential has a claim at the given path.
     *
     * Mirrors iOS DcqlQueryable.hasClaim(_ path: ClaimPath) -> Bool.
     */
    func hasClaim(path: ClaimPath): Bool

    /**
     * Return whether the credential has a claim at the given path with the
     * expected JSON value.
     *
     * Mirrors iOS DcqlQueryable.hasClaimWithValue(_ path: ClaimPath, value: JSON) -> Bool.
     *
     * @param path          The claim path to check.
     * @param expectedValue JSON-serialized expected value (e.g. `"\"Alice\""`, `"42"`).
     */
    func hasClaimWithValue(path: ClaimPath, expectedValue: String): Bool
}

// ===========================================================================
// DefaultDcqlQueryable — flat claim-map based implementation
// ===========================================================================

/**
 * Default DCQL queryable backed by flat claim-path → value maps.
 *
 * Mirrors iOS class DefaultDcqlQueryable.
 *
 * Callers build this from a credential's disclosed claim set (e.g. from
 * SdJwtUtils.buildClaimMap or from mDoc namespace flattening).
 *
 * Design:
 *   - claimPaths: Array<ClaimPath> — all paths present in the credential.
 *   - claimValues: HashMap<String, String> — path hash key → JSON value string.
 *     Path key is produced by pathKey(claimPath).
 *
 *   pathKey() serialises ClaimPath to a dotted string ("given_name",
 *   "address.country", etc.) for use as a HashMap key.
 */
public class DefaultDcqlQueryable <: DcqlQueryable {

    /** All claim paths in this credential. */
    private let claimPaths: Array<ClaimPath>

    /**
     * Map from pathKey(ClaimPath) -> JSON value string.
     * R-104: never subscript directly; always use contains() guard.
     */
    private let claimValues: HashMap<String, String>

    /**
     * Construct a DefaultDcqlQueryable from a flat path→value map.
     *
     * @param claimPaths  All ClaimPath objects present in the credential.
     * @param claimValues Map from ClaimPath.pathKey() to JSON value string.
     */
    public init(claimPaths!: Array<ClaimPath>, claimValues!: HashMap<String, String>) {
        this.claimPaths = claimPaths
        this.claimValues = claimValues
    }

    /**
     * Build a DefaultDcqlQueryable from a simple name→value map (flat credentials).
     *
     * Each key becomes a single-element ClaimPath (ClaimName).
     * Values are JSON strings (quoted or unquoted depending on type).
     *
     * @param flatClaims  Map of claim name → JSON value string.
     */
    public static func fromFlatClaims(flatClaims: HashMap<String, String>): DefaultDcqlQueryable {
        let paths = ArrayList<ClaimPath>()
        let values = HashMap<String, String>()
        let iter = flatClaims.keys()
        for (k in iter) {
            let pathElems: Array<ClaimPathElement> = [ClaimName(k)]
            let path = ClaimPath(pathElems)
            paths.add(path)
            let pk = pathKey(path)
            if (flatClaims.contains(k)) {
                values[pk] = flatClaims[k]
            }
        }
        return DefaultDcqlQueryable(
            claimPaths: paths.toArray(),
            claimValues: values
        )
    }

    // -----------------------------------------------------------------------
    // DcqlQueryable implementation
    // -----------------------------------------------------------------------

    public func getAllClaimPaths(): Array<ClaimPath> {
        return claimPaths
    }

    /**
     * Return true if any stored ClaimPath contains (or equals) the query path.
     *
     * iOS: claimPaths.contains { $0.contains(path) }
     * where ClaimPath.contains() checks prefix containment.
     */
    public func hasClaim(path: ClaimPath): Bool {
        var i: Int64 = 0
        while (i < claimPaths.size) {
            if (claimPaths[i].contains(path)) {
                return true
            }
            i += 1
        }
        return false
    }

    /**
     * Return true if the claim at the given path exists and has the expected value.
     *
     * Mirrors iOS DefaultDcqlQueryable.hasClaimWithValue.
     * R-104: uses contains() before subscripting claimValues.
     */
    public func hasClaimWithValue(path: ClaimPath, expectedValue: String): Bool {
        if (!hasClaim(path)) {
            return false
        }
        let pk = pathKey(path)
        if (!claimValues.contains(pk)) {
            return false
        }
        return claimValues[pk] == expectedValue
    }
}

// ===========================================================================
// pathKey — serialize ClaimPath to a string key for HashMap use
// ===========================================================================

/**
 * Produce a stable string key for a ClaimPath suitable for use as a HashMap key.
 *
 * Format: dot-separated element descriptions.
 * Examples:
 *   ClaimPath(["given_name"])          -> "given_name"
 *   ClaimPath(["address", "country"])  -> "address.country"
 *   ClaimPath(["certs", null, "type"]) -> "certs.[*].type"
 *   ClaimPath(["arr", 0])              -> "arr.[0]"
 *
 * This is an internal serialization convention; callers must use pathKey()
 * consistently when building and querying claimValues maps.
 */
public func pathKey(path: ClaimPath): String {
    var result = ""
    var i: Int64 = 0
    while (i < path.value.size) {
        if (i > 0) {
            result = result + "."
        }
        let elem = path.value[i]
        result = result + elem.description()
        i += 1
    }
    return result
}
