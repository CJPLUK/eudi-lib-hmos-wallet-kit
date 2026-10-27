/*
 * wrp_vci_registration_validator.cj
 *
 * EUDI Wallet Kit — WRPRC validator for OpenID4VCI issuance.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Services/WrpVciRegistrationValidator.swift  (v0.40.9)
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.issuance  (S-002)
 *
 * Validates the WRP registration certificate (WRPRC) of a credential issuer
 * delivered in the issuer metadata `issuer_info` during OpenID4VCI issuance.
 * The token-level checks (JWT parse, type, expiry, binding, status, trust)
 * are shared with the presentation flow via WrpRegistrationCore.
 *
 * Offered configurations are passed as the raw credential-configuration JSON
 * objects from CredentialIssuerMetadata.credentialConfigurationsRaw, keyed by
 * credential configuration identifier (the iOS CredentialSupported enum is
 * represented as raw JSON in this port).
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.issuance

import kit.PerformanceAnalysisKit.Hilog

import std.collection.ArrayList
import std.collection.HashMap
import stdx.encoding.json.{JsonObject, JsonString}
import stdx.encoding.base64.*

import ohos_app_cangjie_eudi_cjx509.x509.core.Cert
import ohos_app_cangjie_eudi_cjetsi_1196x2.etsi_trust.{TrustConfiguration, TrustPolicy}

import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.{
    WrpRegistrationPolicy, PolicyCredential,
    RegistrationPolicyViolation, RegistrationFailureReason
}
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.{
    WrpRegistrationCore, RegistrationCertificateAuthorization
}

// ===========================================================================
// WrpVciRegistrationValidator
// iOS: public actor WrpVciRegistrationValidator
// ===========================================================================

/**
 * Validates the WRP registration certificate (WRPRC) of a credential issuer
 * during OpenID4VCI issuance.
 */
public class WrpVciRegistrationValidator {

    /** ETSI TS 119 475 entitlement URI required to issue PID credentials. */
    public static let PID_ENTITLEMENT: String = "https://uri.etsi.org/19475/Entitlement/PID_Provider"
    /** ETSI TS 119 475 entitlement URI required to issue PUB EAA credentials. */
    public static let PUB_EAA_ENTITLEMENT: String = "https://uri.etsi.org/19475/Entitlement/PUB_EAA_Provider"

    static let PID_MDOC_DOCTYPE: String = "eu.europa.ec.eudi.pid.1"
    static let PID_SDJWT_VCT: String = "urn:eudi:pid:1"

    /** Trust configuration used to validate the issuer registration certificate. */
    public let trustConfig: ?TrustConfiguration

    /**
     * The registration policy decoded from the WRPRC by the last
     * validateCertificate call, if any. Preserved even when validation fails
     * (expiry, revocation, trust error) so the decoded identity can be inspected.
     */
    public var wrpVciRegistrationPolicy: ?WrpRegistrationPolicy

    /**
     * Typed violations collected during validation, keyed by credential
     * configuration identifier; the empty key holds request-wide violations.
     */
    public var wrpVciWarnings: HashMap<String, Array<RegistrationPolicyViolation>>

    public init(trustConfig!: ?TrustConfiguration) {
        this.trustConfig = trustConfig
        this.wrpVciRegistrationPolicy = None
        this.wrpVciWarnings = HashMap<String, Array<RegistrationPolicyViolation>>()
    }

    /** The trust policy applied to VCI WRPRC validation (iOS default: enforce). */
    public func vciTrustPolicy(): TrustPolicy {
        match (this.trustConfig) {
            case Some(cfg) => return cfg.wrprcVciTrustPolicy
            case None => return TrustPolicy.Enforce
        }
    }

    /** Resets state from the previous validation. */
    public func resetValidations(): Unit {
        this.wrpVciRegistrationPolicy = None
        this.wrpVciWarnings = HashMap<String, Array<RegistrationPolicyViolation>>()
    }

    /**
     * Validate the WRP registration certificate (WRPRC) delivered in the
     * issuer metadata `issuer_info` during OpenID4VCI issuance.
     *
     * Mirrors iOS validateCertificate(wrpac:wrprc:offeredConfigurations:).
     *
     * @param wrpac  The WRP access certificate that signed the issuer metadata
     *               (base64 DER, single X.509 leaf); None when unavailable.
     * @param wrprc  The raw WRPRC value as delivered in `issuer_info`
     *               (typically a compact-serialized JWT, optionally base64-wrapped).
     * @param offeredConfigurations  The credential configurations referenced
     *               by the resolved offer / request, keyed by configuration id
     *               (raw JSON objects from the issuer metadata).
     * @return The authorization result; warnings are exposed via
     *         `wrpVciWarnings`, keyed by credential configuration identifier
     *         with the empty key used for request-wide warnings.
     */
    public func validateCertificate(
        wrpac: ?String,
        wrprc: String,
        offeredConfigurations: HashMap<String, JsonObject>
    ): RegistrationCertificateAuthorization {
        resetValidations()
        let accumulator = HashMap<String, ArrayList<RegistrationPolicyViolation>>()
        try {
            // Decode the WRPAC (base64 DER leaf certificate).
            let wrpacCert: ?Cert = decodeWrpac(wrpac, accumulator)

            // Normalize the WRPRC value into token bytes.
            let wrprcData = WrpRegistrationCore.wrprcValueToBytes(wrprc)

            // Decode-first so the identity survives a validation throw.
            this.wrpVciRegistrationPolicy = try {
                Some(WrpRegistrationCore.decodeWrprc(wrprcData))
            } catch (_: Exception) {
                None
            }

            // Core token validation (type, expiry, binding, status, trust).
            let (policy, coreWarnings) =
                WrpRegistrationCore.validateWrprcCore(this.trustConfig, wrpacCert, wrprcData)
            this.wrpVciRegistrationPolicy = Some(policy)
            appendAll(accumulator, "", coreWarnings)

            // Coverage of each offered configuration by provides_attestations.
            let notCovered = HashMap<String, ArrayList<RegistrationPolicyViolation>>()
            validateOfferedConfigurations(offeredConfigurations, policy, notCovered)
            for ((key, list) in notCovered) {
                for (v in list) {
                    appendOne(accumulator, key, v)
                }
            }

            // Entitlement required for the offered configurations.
            validateEntitlements(offeredConfigurations, policy, accumulator)

            this.wrpVciWarnings = snapshot(accumulator)
            for ((key, violations) in accumulator) {
                for (violation in violations) {
                    Hilog.warn(0, "WrpRegistrationValidator",
                        "VCI WRPRC warning [" + key + "]: " + violation.message)
                }
            }

            // Under Enforce, hard failures block issuance.
            match (this.vciTrustPolicy()) {
                case TrustPolicy.Enforce =>
                    match (firstEnforceable(accumulator)) {
                        case Some(v) =>
                            return RegistrationCertificateAuthorization.NotGranted(v.message)
                        case None => ()
                    }
                    match (firstViolation(notCovered)) {
                        case Some(v) =>
                            return RegistrationCertificateAuthorization.NotGranted(v.message)
                        case None => ()
                    }
                case TrustPolicy.Warning => ()
            }
            return RegistrationCertificateAuthorization.Granted
        } catch (e: Exception) {
            appendOne(accumulator, "", RegistrationPolicyViolation(
                RegistrationFailureReason.WrpacDecodingFailed, e.message))
            this.wrpVciWarnings = snapshot(accumulator)
            Hilog.error(0, "WrpRegistrationValidator",
                "Error in validate registration certificate: " + e.message)
            match (this.vciTrustPolicy()) {
                case TrustPolicy.Enforce =>
                    return RegistrationCertificateAuthorization.NotGranted(e.message)
                case TrustPolicy.Warning =>
                    return RegistrationCertificateAuthorization.Granted
            }
        }
    }

    // -----------------------------------------------------------------------
    // Coverage / entitlements (mirror the iOS static helpers)
    // -----------------------------------------------------------------------

    /**
     * Check each offered credential configuration against the attestations the
     * issuer is registered to provide (`provides_attestations` claim of the
     * WRPRC). Warnings for uncovered configurations are appended keyed by
     * credential configuration identifier.
     */
    static func validateOfferedConfigurations(
        offeredConfigurations: HashMap<String, JsonObject>,
        policy: WrpRegistrationPolicy,
        warnings: HashMap<String, ArrayList<RegistrationPolicyViolation>>
    ): Unit {
        let provided: Array<PolicyCredential> = match (policy.providesAttestations) {
            case Some(list) => list
            case None => Array<PolicyCredential>()
        }
        for ((identifier, credObj) in offeredConfigurations) {
            let isCovered = configurationIsCovered(credObj, provided)
            if (!isCovered) {
                appendOne(warnings, identifier, RegistrationPolicyViolation(
                    RegistrationFailureReason.CredentialNotCovered(identifier),
                    "Credential configuration " + identifier +
                        " is not covered by the issuer registration certificate"))
            }
        }
    }

    static func configurationIsCovered(credObj: JsonObject, provided: Array<PolicyCredential>): Bool {
        let format = jsonStringField(credObj, "format")
        if (format == "mso_mdoc") {
            let docType = jsonStringField(credObj, "doctype")
            if (docType.isEmpty()) { return false }
            for (attestation in provided) {
                match (attestation.meta.doctypeValue) {
                    case Some(dt) => if (dt == docType) { return true }
                    case None => ()
                }
            }
            return false
        }
        if (format == "vc+sd-jwt" || format == "dc+sd-jwt") {
            let vct = jsonStringField(credObj, "vct")
            if (vct.isEmpty()) { return false }
            for (attestation in provided) {
                match (attestation.meta.vctValues) {
                    case Some(vcts) =>
                        for (v in vcts) {
                            if (v == vct) { return true }
                        }
                    case None => ()
                }
            }
            return false
        }
        return false
    }

    /**
     * Validate that the WRPRC entitlements contain the expected entitlement
     * for the offered configurations: PID configurations require PID_Provider;
     * other configurations require PUB_EAA_Provider.
     */
    static func validateEntitlements(
        offeredConfigurations: HashMap<String, JsonObject>,
        policy: WrpRegistrationPolicy,
        warnings: HashMap<String, ArrayList<RegistrationPolicyViolation>>
    ): Unit {
        let entitlements: Array<String> = match (policy.entitlements) {
            case Some(list) => list
            case None => Array<String>()
        }
        var offeredIncludesPid = false
        for ((_, credObj) in offeredConfigurations) {
            let format = jsonStringField(credObj, "format")
            if (format == "mso_mdoc" && jsonStringField(credObj, "doctype") == WrpVciRegistrationValidator.PID_MDOC_DOCTYPE) {
                offeredIncludesPid = true
                break
            }
            if ((format == "vc+sd-jwt" || format == "dc+sd-jwt") &&
                jsonStringField(credObj, "vct") == WrpVciRegistrationValidator.PID_SDJWT_VCT) {
                offeredIncludesPid = true
                break
            }
        }
        let expected = if (offeredIncludesPid) {
            WrpVciRegistrationValidator.PID_ENTITLEMENT
        } else {
            WrpVciRegistrationValidator.PUB_EAA_ENTITLEMENT
        }
        var found = false
        for (e in entitlements) {
            if (e == expected) {
                found = true
                break
            }
        }
        if (!found) {
            appendOne(warnings, "", RegistrationPolicyViolation(
                RegistrationFailureReason.EntitlementMissing(expected),
                "WRPRC is missing required entitlement: " + expected))
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    func decodeWrpac(
        wrpac: ?String,
        accumulator: HashMap<String, ArrayList<RegistrationPolicyViolation>>
    ): ?Cert {
        let wrpacB64: String = match (wrpac) {
            case Some(b64) => b64
            case None =>
                appendOne(accumulator, "", RegistrationPolicyViolation(
                    RegistrationFailureReason.WrpacDecodingFailed, "WRPAC cannot be decoded"))
                return None
        }
        match (fromBase64String(wrpacB64)) {
            case Some(der) =>
                try {
                    return Some(Cert.fromDer(der))
                } catch (_: Exception) {
                    ()
                }
            case None => ()
        }
        appendOne(accumulator, "", RegistrationPolicyViolation(
            RegistrationFailureReason.WrpacDecodingFailed, "WRPAC cannot be decoded"))
        return None
    }

    static func jsonStringField(obj: JsonObject, key: String): String {
        match (obj.get(key)) {
            case Some(js: JsonString) => return js.getValue()
            case _ => return ""
        }
    }

    static func appendOne(
        map: HashMap<String, ArrayList<RegistrationPolicyViolation>>,
        key: String,
        violation: RegistrationPolicyViolation
    ): Unit {
        if (!map.contains(key)) {
            map[key] = ArrayList<RegistrationPolicyViolation>()
        }
        map[key].add(violation)
    }

    static func appendAll(
        map: HashMap<String, ArrayList<RegistrationPolicyViolation>>,
        key: String,
        violations: ArrayList<RegistrationPolicyViolation>
    ): Unit {
        for (v in violations) {
            appendOne(map, key, v)
        }
    }

    static func snapshot(
        map: HashMap<String, ArrayList<RegistrationPolicyViolation>>
    ): HashMap<String, Array<RegistrationPolicyViolation>> {
        let out = HashMap<String, Array<RegistrationPolicyViolation>>()
        for ((key, list) in map) {
            out[key] = list.toArray()
        }
        return out
    }

    static func firstEnforceable(
        map: HashMap<String, ArrayList<RegistrationPolicyViolation>>
    ): ?RegistrationPolicyViolation {
        if (!map.contains("")) {
            return None
        }
        for (v in map[""]) {
            if (v.reason.isEnforceable()) {
                return Some(v)
            }
        }
        return None
    }

    static func firstViolation(
        map: HashMap<String, ArrayList<RegistrationPolicyViolation>>
    ): ?RegistrationPolicyViolation {
        for ((_, list) in map) {
            if (list.size > 0) {
                return Some(list[0])
            }
        }
        return None
    }
}
