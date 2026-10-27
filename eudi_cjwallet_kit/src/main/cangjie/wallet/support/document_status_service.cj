/*
 * document_status_service.cj
 *
 * EUDI Wallet Kit — DocumentStatusService.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Services/DocumentStatusService.swift
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.support  (S-002)
 *
 * iOS DocumentStatusService is an actor wrapping statium's GetStatus +
 * StatusListTokenFetcher to determine the revocation status of a credential.
 *
 * Cangjie mapping:
 *   - iOS actor -> Cangjie class (HarmonyOS has no built-in actor isolation for
 *     library-level classes; concurrency is handled at the application layer).
 *   - GetStatus.getStatus() is called with the fetcher's getStatusClaims as the
 *     FetchClaimsHandler closure, matching the iOS pattern.
 *   - StatusListTokenFormat defaults to Jwt (as iOS defaults).
 *   - VerifyStatusListTokenSignature must be supplied by the caller; a no-op
 *     implementation (IgnoreVerifier) is provided for testing/non-production use.
 *   - StatusIdentifier comes from ohos_app_cangjie_eudi_cjmdoc_data_model.
 *   - StatusReference comes from ohos_app_cangjie_eudi_cjstatium.statium.model.
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.support

import kit.PerformanceAnalysisKit.Hilog

import std.time.DateTime

import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.issuerauth.StatusIdentifier

import ohos_app_cangjie_eudi_cjstatium.statium.crypto.VerifyStatusListTokenSignature
import ohos_app_cangjie_eudi_cjstatium.statium.model.CredentialStatus
import ohos_app_cangjie_eudi_cjstatium.statium.model.StatusError
import ohos_app_cangjie_eudi_cjstatium.statium.model.StatusListTokenFormat
import ohos_app_cangjie_eudi_cjstatium.statium.model.StatusReference
import ohos_app_cangjie_eudi_cjstatium.statium.status.GetStatus
import ohos_app_cangjie_eudi_cjstatium.statium.status.StatusListTokenFetcher

// ===========================================================================
// IgnoreVerifier — no-op signature verifier for development / testing
// ===========================================================================

/**
 * No-operation verifier that accepts any status list token signature.
 *
 * Mirrors iOS `struct VerifyStatusListTokenSignatureIgnore` — which is INTERNAL,
 * not public, and only used as the fallback when no verifier is injected. This
 * class is package-internal for the same reason: it performs NO signature check
 * and must never be a publicly-selectable production verifier. The default
 * fallback happens inside DocumentStatusService (mirroring iOS
 * `verifier ?? VerifyStatusListTokenSignatureIgnore()`); production callers
 * inject a real verifier.
 */
class VerifyStatusListTokenSignatureIgnore <: VerifyStatusListTokenSignature {
    init() {}

    public func verify(
        tokenBytes: Array<UInt8>,
        format: StatusListTokenFormat,
        atSecs: Float64
    ): Unit {
        Hilog.warn(0, "DocumentStatusService",
            "VerifyStatusListTokenSignatureIgnore: signature check bypassed (no verifier injected)")
    }
}

// ===========================================================================
// DocumentStatusService
// ===========================================================================

/**
 * Retrieves the revocation status of a credential document.
 *
 * Mirrors iOS `actor DocumentStatusService`.
 *
 * Typical usage:
 *   let verifier: VerifyStatusListTokenSignature = ...
 *   let service = DocumentStatusService(verifier: verifier)
 *   let status = service.getStatus(statusIdentifier: identifier)
 */
public class DocumentStatusService {

    /**
     * Signature verifier passed to StatusListTokenFetcher.
     * Mirrors iOS DocumentStatusService.verifier.
     */
    public let verifier: VerifyStatusListTokenSignature

    /**
     * Clock skew tolerance in seconds for token validation.
     * iOS default is 5 minutes (300 seconds).
     */
    public let clockSkew: Float64

    /**
     * Status list token format preference.
     * iOS defaults to Jwt.
     */
    public let preferredFormat: StatusListTokenFormat

    /**
     * Construct a DocumentStatusService.
     *
     * @param verifier        Signature verifier for status list tokens.
     * @param clockSkew       Clock skew tolerance in seconds (default 300.0).
     * @param preferredFormat Token format (default Jwt).
     */
    public init(
        verifier!: ?VerifyStatusListTokenSignature = None,
        clockSkew!: Float64 = 300.0,
        preferredFormat!: StatusListTokenFormat = StatusListTokenFormat.Jwt
    ) {
        // iOS: `verifier ?? VerifyStatusListTokenSignatureIgnore()` — an injected
        // verifier is used when present; otherwise fall back to the internal
        // no-op ignore (NO signature verification). Production must inject a real
        // verifier; the default is dev/test only.
        this.verifier = match (verifier) {
            case Some(v) => v
            case None => VerifyStatusListTokenSignatureIgnore()
        }
        this.clockSkew = clockSkew
        this.preferredFormat = preferredFormat
    }

    /**
     * Get the credential status for a StatusIdentifier (from an mdoc MSO).
     *
     * Converts StatusIdentifier (idx + uriString) to a StatusReference and
     * delegates to getStatus(reference:).
     *
     * Mirrors iOS DocumentStatusService.getStatus(statusIdentifier:).
     *
     * @param statusIdentifier  The MSO's status pointer.
     * @return CredentialStatus (Valid / Invalid / Suspended / ...).
     * @throws StatusError if the status cannot be determined.
     */
    public func getStatus(statusIdentifier: StatusIdentifier): CredentialStatus {
        let ref = StatusReference(idx: statusIdentifier.idx, uri: statusIdentifier.uriString)
        return getStatusForReference(ref)
    }

    /**
     * Get the credential status for a StatusReference.
     *
     * Creates a StatusListTokenFetcher backed by `verifier` and calls
     * GetStatus.getStatus(reference, format, fetchClaims, nowSecs, clockSkew).
     *
     * Mirrors iOS DocumentStatusService.getStatus(session:reference:).
     *
     * @param reference  Status list index + URL.
     * @return CredentialStatus.
     * @throws StatusError on network, signature, or decode failure.
     */
    public func getStatusForReference(reference: StatusReference): CredentialStatus {
        Hilog.info(0, "DocumentStatusService",
            "getStatus idx=" + reference.idx.toString()
            + " uri=" + reference.uri)

        let fetcher = StatusListTokenFetcher.create(verifier)

        // Build the FetchClaimsHandler closure that wraps the fetcher
        let skew = clockSkew
        let fmt = preferredFormat
        let getStatusImpl = GetStatus()

        // All positional calls (third_party methods have no ! params)
        return getStatusImpl.getStatus(
            reference,
            fmt,
            { fmt2, url, nowSecs, cs =>
                fetcher.getStatusClaims(url, fmt2, nowSecs, cs)
            },
            currentTimeSecs(),
            skew
        )
    }

    /**
     * Get the credential status given an explicit index and URL.
     *
     * Mirrors iOS DocumentStatusService.getStatus(session:index:uri:).
     *
     * @param index  Zero-based status list index.
     * @param uri    Status list token URL.
     * @return CredentialStatus.
     * @throws StatusError on failure.
     */
    public func getStatusForIndexUri(index: Int64, uri: String): CredentialStatus {
        let ref = StatusReference(idx: index, uri: uri)
        return getStatusForReference(ref)
    }
}

// ===========================================================================
// Internal: current time helper
// ===========================================================================

/**
 * Return the current time as seconds since Unix epoch (Float64).
 *
 * Uses std.time.DateTime.now() to obtain current time.
 * Mirrors iOS `Date().timeIntervalSince1970`.
 */
func currentTimeSecs(): Float64 {
    // DateTime.nowUTC().toUnixTimeStamp() returns a Duration since Unix epoch.
    // .toSeconds() returns Int64 seconds.
    let secs = DateTime.nowUTC().toUnixTimeStamp().toSeconds()
    return Float64(secs)
}
