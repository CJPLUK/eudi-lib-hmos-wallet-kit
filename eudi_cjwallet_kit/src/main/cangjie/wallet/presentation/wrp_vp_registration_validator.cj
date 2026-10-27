/*
 * wrp_vp_registration_validator.cj
 *
 * EUDI Wallet Kit — WRPRC validator for OpenID4VP / proximity presentation.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Services/WrpVpRegistrationValidator.swift  (v0.40.9)
 *   Sources/EudiWalletKit/Services/Openid4VpUtils.swift (validateDcqlPolicy, makeDcql)
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.presentation  (S-002)
 *
 * Validates the WRP registration certificate (WRPRC) of a verifier (relying
 * party) during presentation and checks the requested scope (DCQL) against
 * the registration policy. Over-asking violations are keyed by docType/vct;
 * the empty key holds request-wide violations (registration itself failed) —
 * matching the wrpVerifierWarnings convention consumed by the app layer.
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.presentation

import kit.PerformanceAnalysisKit.Hilog

import std.collection.ArrayList
import std.collection.HashMap

import ohos_app_cangjie_eudi_cjcbor.cbor.CborValue
import ohos_app_cangjie_eudi_cjx509.x509.core.Cert
import ohos_app_cangjie_eudi_cjetsi_1196x2.etsi_trust.{TrustConfiguration, TrustPolicy}
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.request.DeviceRequest
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.{
    DCQL, CredentialQuery, ClaimsQuery, ClaimPath
}

import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.{
    WrpRegistrationPolicy, PolicyCredential,
    RegistrationPolicyViolation,
    PresentationPolicyViolation, PresentationFailureReason
}
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.{
    WrpRegistrationCore, RegistrationCertificateAuthorization
}

// ===========================================================================
// WrpVpRegistrationValidator
// iOS: public actor WrpVpRegistrationValidator
// ===========================================================================

/**
 * Validates the WRP registration certificate (WRPRC) of a verifier
 * (relying party) during presentation.
 */
public class WrpVpRegistrationValidator {

    /** Label of the ItemsRequest.requestInfo member carrying the WRPRC in
     *  ISO/IEC 18013-5 requests (ETSI TS 119 472-2). */
    public static let REG_CERT_REQUEST_INFO_KEY: String = "euWrprc"
    /** ETSI TS 119 475 entitlement URI expected of presenting relying parties. */
    public static let SERVICE_PROVIDER_ENTITLEMENT: String = "https://uri.etsi.org/19475/Entitlement/Service_Provider"

    /** Trust configuration used to validate the relying-party registration certificate. */
    public let trustConfig: ?TrustConfiguration

    /** The registration policy decoded from the WRPRC by the last validateCertificate call, if any. */
    public var wrpVpRegistrationPolicy: ?WrpRegistrationPolicy

    /**
     * Typed violations collected during validation. The empty key holds
     * request-wide violations; per-docType keys hold over-asking violations.
     */
    public var wrpVpWarnings: HashMap<String, Array<PresentationPolicyViolation>>

    public init(trustConfig!: ?TrustConfiguration) {
        this.trustConfig = trustConfig
        this.wrpVpRegistrationPolicy = None
        this.wrpVpWarnings = HashMap<String, Array<PresentationPolicyViolation>>()
    }

    /** The trust policy applied to VP WRPRC validation (app default: warning). */
    public func vpTrustPolicy(): TrustPolicy {
        match (this.trustConfig) {
            case Some(cfg) => return cfg.wrprcVpTrustPolicy
            case None => return TrustPolicy.Warning
        }
    }

    /** Resets state from the previous request so it does not leak into the next one. */
    public func resetValidations(): Unit {
        this.wrpVpRegistrationPolicy = None
        this.wrpVpWarnings = HashMap<String, Array<PresentationPolicyViolation>>()
    }

    /**
     * Validate the relying party registration certificate (raw string value,
     * e.g. from the OpenID4VP `verifier_info`) and check the requested items
     * against the registration policy.
     *
     * Mirrors iOS validateCertificate(wrpac:wrprc:dcql:).
     */
    public func validateCertificate(
        wrpac: ?Cert,
        wrprc: String,
        dcql: ?DCQL
    ): RegistrationCertificateAuthorization {
        resetValidations()
        return validateCertificateData(wrpac, wrprc.toArray(), dcql)
    }

    /**
     * Validate the relying party registration certificate (WRPRC) carried in
     * an ISO/IEC 18013-5 device request.
     *
     * According to ETSI TS 119 472-2 (proximity profile), the WRPRC is
     * repeated in the `requestInfo` member of each ItemsRequest, under the
     * "euWrprc" label, as a CBOR byte string containing the serialization of
     * the registration certificate.
     *
     * Mirrors iOS validateDeviceRequestCertificate(wrpac:deviceRequest:dcql:).
     *
     * @return The authorization result, or None when the request carries no
     *         registration certificate (not evaluated).
     */
    public func validateDeviceRequestCertificate(
        wrpac: ?Cert,
        deviceRequest: DeviceRequest,
        dcql: ?DCQL
    ): ?RegistrationCertificateAuthorization {
        resetValidations()
        let wrprcValues = ArrayList<Array<UInt8>>()
        for (docReq in deviceRequest.docRequests) {
            match (docReq.itemsRequest.requestInfo) {
                case Some(info) =>
                    match (info.field(CborValue.TextStringVal(WrpVpRegistrationValidator.REG_CERT_REQUEST_INFO_KEY))) {
                        case Some(CborValue.ByteStringVal(bs)) => wrprcValues.add(bs)
                        case _ => ()
                    }
                case None => ()
            }
        }
        if (wrprcValues.size == 0) {
            return None
        }
        let wrprcData = wrprcValues[0]
        if (wrprcValues.size < deviceRequest.docRequests.size) {
            appendVpWarning("", PresentationPolicyViolation(
                PresentationFailureReason.WrprcNotRepeated,
                "WRPRC not repeated in every ItemsRequest.requestInfo"))
        }
        var i: Int64 = 1
        while (i < wrprcValues.size) {
            if (!bytesEqual(wrprcValues[i], wrprcData)) {
                appendVpWarning("", PresentationPolicyViolation(
                    PresentationFailureReason.WrprcMismatch,
                    "Different WRPRC values found in ItemsRequest.requestInfo"))
                break
            }
            i += 1
        }
        return Some(validateCertificateData(wrpac, wrprcData, dcql))
    }

    /**
     * Validate the relying party registration certificate and check the
     * requested items against the registration policy.
     *
     * Mirrors iOS validateCertificate(wrpac:wrprcData:dcql:). Warnings are
     * exposed via `wrpVpWarnings`: the empty key for request-wide violations,
     * docType/vct keys for over-asking.
     */
    public func validateCertificateData(
        wrpac: ?Cert,
        wrprcData: Array<UInt8>,
        dcql: ?DCQL
    ): RegistrationCertificateAuthorization {
        try {
            let (policy, coreWarnings) =
                WrpRegistrationCore.validateWrprcCore(this.trustConfig, wrpac, wrprcData)
            this.wrpVpRegistrationPolicy = Some(policy)
            for (w in coreWarnings) {
                appendVpWarning("", PresentationPolicyViolation.fromRegistration(w))
            }
            // Under Enforce, hard failures block presentation.
            match (this.vpTrustPolicy()) {
                case TrustPolicy.Enforce =>
                    match (firstEnforceableRequestWide()) {
                        case Some(v) =>
                            return RegistrationCertificateAuthorization.NotGranted(v.message)
                        case None => ()
                    }
                case TrustPolicy.Warning => ()
            }
            validateEntitlements(policy)
            match (dcql) {
                case Some(query) => validateDcqlPolicy(query, policy)
                case None => ()
            }
            return RegistrationCertificateAuthorization.Granted
        } catch (e: Exception) {
            appendVpWarning("", PresentationPolicyViolation(
                PresentationFailureReason.Other,
                "WRP policy could not be created: " + e.message))
            Hilog.error(0, "WrpRegistrationValidator",
                "Error in validate registration certificate: " + e.message)
            match (this.vpTrustPolicy()) {
                case TrustPolicy.Enforce =>
                    return RegistrationCertificateAuthorization.NotGranted(e.message)
                case TrustPolicy.Warning =>
                    return RegistrationCertificateAuthorization.Granted
            }
        }
    }

    /**
     * Record a request-wide violation for a request that carries no WRPRC
     * while validation is enabled. Returns NotGranted under Enforce.
     */
    public func recordMissingCertificate(context: String): RegistrationCertificateAuthorization {
        resetValidations()
        let message = "Request carries no WRP registration certificate (" + context + ")"
        appendVpWarning("", PresentationPolicyViolation(
            PresentationFailureReason.InvalidCertificate, message))
        match (this.vpTrustPolicy()) {
            case TrustPolicy.Enforce =>
                return RegistrationCertificateAuthorization.NotGranted(message)
            case TrustPolicy.Warning =>
                return RegistrationCertificateAuthorization.Granted
        }
    }

    // -----------------------------------------------------------------------
    // Entitlements
    // -----------------------------------------------------------------------

    /**
     * Warn when the WRPRC `entitlements` claim is present but does not
     * include the Service_Provider operation. Mirrors iOS validateEntitlements.
     */
    func validateEntitlements(policy: WrpRegistrationPolicy): Unit {
        let entitlements: Array<String> = match (policy.entitlements) {
            case Some(list) => list
            case None => return
        }
        let expected = WrpVpRegistrationValidator.SERVICE_PROVIDER_ENTITLEMENT
        for (e in entitlements) {
            if (e == expected) {
                return
            }
        }
        appendVpWarning("", PresentationPolicyViolation(
            PresentationFailureReason.EntitlementMissing(expected),
            "Registration certificate entitlements do not include '" + expected + "'"))
    }

    // -----------------------------------------------------------------------
    // DCQL policy validation (over-asking)
    // -----------------------------------------------------------------------

    /**
     * Validates that the request DCQL does not exceed the scope declared in
     * the registration policy. Issues over-asking warnings for any credential
     * or claim requested beyond what the policy permits, keyed by docType/vct.
     *
     * Mirrors iOS OpenId4VpUtils.validateDcqlPolicy applied to the request
     * credential queries (this port validates the request scope directly
     * instead of resolving the query against stored credentials first).
     */
    func validateDcqlPolicy(dcql: DCQL, policy: WrpRegistrationPolicy): Unit {
        for (credQuery in dcql.credentials) {
            let docType: String = match (queryDocTypeOrVct(credQuery)) {
                case Some(dt) => dt
                case None => continue
            }
            let policyCredential: ?PolicyCredential = findPolicyCredential(policy, docType)
            match (policyCredential) {
                case None =>
                    appendVpWarning(docType, PresentationPolicyViolation(
                        PresentationFailureReason.OverAskedClaims(docType, None),
                        "Credential '" + docType + "' (query: " + credQuery.queryId.value +
                            ") is not declared in the registration certificate policy"))
                case Some(pc) =>
                    let requestClaims: Array<ClaimsQuery> = match (credQuery.claims) {
                        case Some(cs) => cs
                        case None => continue
                    }
                    if (requestClaims.size == 0) { continue }
                    let policyClaims = match (pc.claims) {
                        case Some(pcs) => pcs
                        case None => continue
                    }
                    let extraPaths = ArrayList<ClaimPath>()
                    for (rc in requestClaims) {
                        var covered = false
                        for (policyClaim in policyClaims) {
                            if (policyClaim.path.contains2(rc.path)) {
                                covered = true
                                break
                            }
                        }
                        if (!covered) {
                            extraPaths.add(rc.path)
                        }
                    }
                    if (extraPaths.size > 0) {
                        appendVpWarning(docType, PresentationPolicyViolation(
                            PresentationFailureReason.OverAskedClaims(docType, Some(extraPaths.toArray())),
                            "Credential '" + docType + "' requests claims beyond policy scope. Extra fields: [" +
                                joinPathList(extraPaths) + "]"))
                    }
            }
        }
    }

    static func queryDocTypeOrVct(credQuery: CredentialQuery): ?String {
        let entries = Openid4VpUtils.parseDcqlFormats(DCQL([credQuery]))
        if (entries.size == 0) {
            return None
        }
        return entries[0].docType
    }

    static func findPolicyCredential(policy: WrpRegistrationPolicy, docType: String): ?PolicyCredential {
        let credentials: Array<PolicyCredential> = match (policy.credentials) {
            case Some(cs) => cs
            case None => return None
        }
        for (pc in credentials) {
            match (pc.meta.doctypeValue) {
                case Some(dt) =>
                    if (dt == docType) {
                        return Some(pc)
                    }
                    continue
                case None => ()
            }
            match (pc.meta.vctValues) {
                case Some(vcts) =>
                    for (v in vcts) {
                        if (v == docType) {
                            return Some(pc)
                        }
                    }
                case None => ()
            }
        }
        return None
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    func appendVpWarning(key: String, violation: PresentationPolicyViolation): Unit {
        let existing: Array<PresentationPolicyViolation> = match (this.wrpVpWarnings.get(key)) {
            case Some(list) => list
            case None => Array<PresentationPolicyViolation>()
        }
        let merged = ArrayList<PresentationPolicyViolation>()
        for (v in existing) {
            merged.add(v)
        }
        merged.add(violation)
        this.wrpVpWarnings[key] = merged.toArray()
    }

    func firstEnforceableRequestWide(): ?PresentationPolicyViolation {
        match (this.wrpVpWarnings.get("")) {
            case Some(list) =>
                for (v in list) {
                    if (v.reason.isEnforceable()) {
                        return Some(v)
                    }
                }
                return None
            case None => return None
        }
    }

    static func bytesEqual(a: Array<UInt8>, b: Array<UInt8>): Bool {
        if (a.size != b.size) {
            return false
        }
        var i: Int64 = 0
        while (i < a.size) {
            if (a[i] != b[i]) {
                return false
            }
            i += 1
        }
        return true
    }

    static func joinPathList(paths: ArrayList<ClaimPath>): String {
        var out = ""
        var first = true
        for (p in paths) {
            var pathStr = ""
            var firstElem = true
            for (e in p.value) {
                if (!firstElem) {
                    pathStr = pathStr + "/"
                }
                pathStr = pathStr + e.description()
                firstElem = false
            }
            if (!first) {
                out = out + ", "
            }
            out = out + pathStr
            first = false
        }
        return out
    }
}
