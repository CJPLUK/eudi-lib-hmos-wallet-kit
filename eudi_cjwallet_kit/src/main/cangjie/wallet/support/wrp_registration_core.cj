/*
 * wrp_registration_core.cj
 *
 * EUDI Wallet Kit — shared WRP registration certificate (WRPRC) validation core.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Services/WrpVciRegistrationValidator.swift
 *     (decodeWrprc / validateWrprcCore — the half shared by both flows)
 *   Sources/EudiWalletKit/Services/WrpRegistrationBinding.swift
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.support  (S-002)
 *
 * Both WrpVciRegistrationValidator (wallet.issuance) and
 * WrpVpRegistrationValidator (wallet.presentation) delegate the token-level
 * validation here: JWT parse, type-header check, policy decoding, expiration,
 * access-certificate binding, status-list check, and trust-chain validation
 * against TrustConfiguration.registrationTrustManager (etsi lib).
 *
 * Notes:
 *   - iOS x5cVerifyJwtOrCwt handles JWT and CWT tokens. This port validates
 *     the JWT serialization (the format used by the EUDI reference services);
 *     a token that is not a compact JWS records an invalidType violation and
 *     is still payload-decoded when possible, mirroring the Swift fallback.
 *   - Trust validation = x5c chain via registrationTrustManager PLUS an ES256
 *     JWS signature check against the x5c leaf key (what iOS validateTrust
 *     performs inside MdocSecurity18013).
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.support

import kit.PerformanceAnalysisKit.Hilog

import std.collection.ArrayList
import std.time.DateTime

import stdx.encoding.json.{JsonValue, JsonObject, JsonArray, JsonString}
import stdx.encoding.base64.*
import stdx.crypto.keys.ECDSAPublicKey
import stdx.crypto.common.DerBlob

import eudi_lib_core_crypto.Base64Url
import ohos_app_cangjie_eudi_cjjose.jose.JoseJws
import ohos_app_cangjie_eudi_cjx509.x509.core.{Cert, subjectAttributeValue}
import ohos_app_cangjie_eudi_cjetsi_1196x2.etsi_trust.TrustConfiguration
import ohos_app_cangjie_eudi_cjstatium.statium.model.CredentialStatus

import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.{
    WalletError, WalletErrorCode,
    WrpRegistrationPolicy, RegistrationPolicyViolation, RegistrationFailureReason
}

// ===========================================================================
// Constants (mirror WrpRegistrationBinding.swift file-scope lets)
// ===========================================================================

/** WRPRC CWT header type (ETSI TS 119 475). */
public let WRPRC_CWT_TYPE: String = "rc-wrp+cwt"
/** WRPRC JWT header type (ETSI TS 119 475). */
public let WRPRC_JWT_TYPE: String = "rc-wrp+jwt"

// ===========================================================================
// RegistrationCertificateAuthorization
// iOS: OpenID4VCI/OpenID4VP `Authorization` (granted / notGranted)
// ===========================================================================

/**
 * Outcome of a WRPRC policy evaluation. Granted may still carry warnings —
 * read them from the validator's warnings property. NotGranted carries the
 * blocking violation message.
 */
public enum RegistrationCertificateAuthorization {
    | Granted
    | NotGranted(String)

    public func isGranted(): Bool {
        match (this) {
            case Granted => return true
            case NotGranted(_) => return false
        }
    }
}

// ===========================================================================
// WrpRegistrationBinding
// iOS: extension WrpRegistrationPolicy.isBound(to:) + Certificate.subjectIdentifier()
// ===========================================================================

/**
 * Binding between a WRP registration certificate and the access certificate
 * (WRPAC) of the party that presented it.
 */
public class WrpRegistrationBinding {

    /**
     * Whether the registration policy is bound to the relying party that
     * presents it. Mirrors iOS WrpRegistrationPolicy.isBound(to:):
     * when an intermediary is declared, its identifier must match the
     * presenter; otherwise one of the policy identifiers (from `sub`) must.
     * A missing certificate or missing subject identifier means unbound.
     */
    public static func isBound(policy: WrpRegistrationPolicy, accessCertificate: ?Cert): Bool {
        let cert: Cert = match (accessCertificate) {
            case Some(c) => c
            case None => return false
        }
        let presenterId: String = match (subjectIdentifier(cert)) {
            case Some(id) => id
            case None =>
                Hilog.warn(0, "WrpRegistrationValidator",
                    "WRPAC subject identifier missing; subject=" + cert.subject)
                return false
        }
        Hilog.info(0, "WrpRegistrationValidator",
            "WRPAC binding presenter=" + presenterId + ", policy subject=" + policy.sub)
        match (policy.intermediary) {
            case Some(inter) =>
                match (inter.identifier) {
                    case Some(id) => return id == presenterId
                    case None => return false
                }
            case None => ()
        }
        for (ident in policy.identifiers()) {
            if (ident.value == presenterId) {
                return true
            }
        }
        return false
    }

    /**
     * The subject identifier of a certificate: the organizationIdentifier
     * (OID 2.5.4.97) attribute of the subject DN, falling back to the
     * serialNumber (OID 2.5.4.5) attribute. Mirrors iOS
     * Certificate.subjectIdentifier() in WrpRegistrationBinding.swift.
     *
     * Reads the encoded X.500 Name by OID so attributes omitted by stdx's
     * display string remain available. String parsing is retained only as a
     * compatibility fallback.
     */
    public static func subjectIdentifier(cert: Cert): ?String {
        // Use the encoded X.500 Name first. stdx's subject.toString() is only a
        // display representation and drops the organizationIdentifier used by
        // current EUDI WRP access certificates.
        try {
            match (subjectAttributeValue(cert, "2.5.4.97")) {
                case Some(v) => return Some(v)
                case None => ()
            }
            match (subjectAttributeValue(cert, "2.5.4.5")) {
                case Some(v) => return Some(v)
                case None => ()
            }
        } catch (e: Exception) {
            Hilog.warn(0, "WrpRegistrationValidator",
                "WRPAC encoded subject could not be parsed: " + e.message)
        }

        // Compatibility fallback for certificates whose attributes are
        // faithfully included in the stdx display string.
        let dn = cert.subject
        match (firstDnValue(dn, ["organizationidentifier", "oid.2.5.4.97", "2.5.4.97"])) {
            case Some(v) => return Some(v)
            case None => ()
        }
        return firstDnValue(dn, ["serialnumber"])
    }

    /**
     * First value in a DN string whose attribute key (lowercased) matches one
     * of `keys`. DN components are split on ',' and '/'; each component is
     * split on its first '='.
     */
    static func firstDnValue(dn: String, keys: Array<String>): ?String {
        let components = splitDnComponents(dn)
        for (component in components) {
            let eqIdx = component.indexOf("=")
            match (eqIdx) {
                case Some(idx) =>
                    let key = trimAsciiSpaces(component[0..idx]).toAsciiLower()
                    let value = trimAsciiSpaces(component[(idx + 1)..])
                    for (k in keys) {
                        if (key == k && !value.isEmpty()) {
                            return Some(value)
                        }
                    }
                case None => ()
            }
        }
        return None
    }

    static func splitDnComponents(dn: String): ArrayList<String> {
        let out = ArrayList<String>()
        let bytes = dn.toArray()
        var start: Int64 = 0
        var i: Int64 = 0
        while (i < bytes.size) {
            let b = bytes[i]
            if (b == 0x2Cu8 || b == 0x2Fu8) { // ',' or '/'
                if (i > start) {
                    out.add(String.fromUtf8(bytes[start..i]))
                }
                start = i + 1
            }
            i += 1
        }
        if (start < bytes.size) {
            out.add(String.fromUtf8(bytes[start..bytes.size]))
        }
        return out
    }

    static func trimAsciiSpaces(s: String): String {
        return s.trimAscii()
    }
}

// ===========================================================================
// Parsed WRPRC token (JWT serialization)
// ===========================================================================

/** A parsed compact-JWS WRPRC token. */
class WrprcJwtToken {
    /** Full compact serialization (header.payload.signature). */
    let compact: String
    /** Decoded protected header JSON object. */
    let header: JsonObject
    /** Decoded payload JSON string. */
    let payloadJson: String

    init(compact: String, header: JsonObject, payloadJson: String) {
        this.compact = compact
        this.header = header
        this.payloadJson = payloadJson
    }

    func typ(): ?String {
        match (this.header.get("typ")) {
            case Some(js: JsonString) => Some(js.getValue())
            case _ => None
        }
    }

    /** DER certificates from the x5c header (leaf first); empty when absent. */
    func x5cChainDer(): Array<Array<UInt8>> {
        let acc = ArrayList<Array<UInt8>>()
        match (this.header.get("x5c")) {
            case Some(arr: JsonArray) =>
                for (item in arr.getItems()) {
                    match (item) {
                        case s: JsonString =>
                            match (fromBase64String(s.getValue())) {
                                case Some(der) => acc.add(der)
                                case None => ()
                            }
                        case _ => ()
                    }
                }
            case _ => ()
        }
        return acc.toArray()
    }
}

// ===========================================================================
// WrpRegistrationCore — shared token validation
// ===========================================================================

/**
 * Shared WRPRC token validation used by the issuance (OpenID4VCI) and
 * presentation (OpenID4VP / BLE) flows. Mirrors the static half of iOS
 * WrpVciRegistrationValidator (decodeWrprc / validateWrprcCore).
 */
public class WrpRegistrationCore {

    /**
     * Normalize a WRPRC value into token bytes. Mirrors iOS
     * `Data(base64Encoded: wrprc) ?? wrprc.data(using: .ascii)`:
     * a valid standard-base64 wrapper is unwrapped, otherwise the raw
     * ASCII bytes of the value are used.
     */
    public static func wrprcValueToBytes(wrprc: String): Array<UInt8> {
        match (fromBase64String(wrprc)) {
            case Some(decoded) => return decoded
            case None => return wrprc.toArray()
        }
    }

    /**
     * Decode the WRPRC token payload into a WrpRegistrationPolicy without
     * performing any validation. Used to preserve the decoded identity even
     * when subsequent validation fails.
     * Throws WalletError(InvalidWrprc) when the token cannot be decoded.
     */
    public static func decodeWrprc(wrprcData: Array<UInt8>): WrpRegistrationPolicy {
        let token = parseJwt(wrprcData)
        match (token) {
            case Some(t) => return WrpRegistrationPolicy.fromJsonString(t.payloadJson)
            case None =>
                throw WalletError.withCode(
                    "WRPRC cannot be decoded", WalletErrorCode.InvalidWrprc)
        }
    }

    /**
     * Core WRPRC token validation shared by the presentation (OpenID4VP/BLE)
     * and issuance (OpenID4VCI) flows. Parses the token, checks its type
     * header, decodes the registration policy, and validates expiration,
     * access-certificate binding, status and trust chain.
     *
     * Mirrors iOS WrpVciRegistrationValidator.validateWrprcCore.
     *
     * @param trustConfig  The wallet trust configuration; when None the trust
     *                     chain cannot be validated and a trustError violation
     *                     is recorded.
     * @param wrpac        The requester access certificate, if available.
     * @param wrprcData    The raw WRPRC token bytes (JWT serialization).
     * @return (decoded policy, typed violations for all issues found).
     * @throws WalletError(InvalidWrprc) when the token cannot be decoded at all.
     */
    public static func validateWrprcCore(
        trustConfig: ?TrustConfiguration,
        wrpac: ?Cert,
        wrprcData: Array<UInt8>
    ): (WrpRegistrationPolicy, ArrayList<RegistrationPolicyViolation>) {
        let warnings = ArrayList<RegistrationPolicyViolation>()
        let token: WrprcJwtToken = match (parseJwt(wrprcData)) {
            case Some(t) => t
            case None =>
                throw WalletError.withCode(
                    "WRPRC cannot be decoded", WalletErrorCode.InvalidWrprc)
        }

        // 1. Type header check. On mismatch, record invalidType and return the
        //    payload-decoded policy without further validation (Swift early
        //    return path).
        let typValue: ?String = token.typ()
        let typOk: Bool = match (typValue) {
            case Some(t) => t == WRPRC_JWT_TYPE
            case None => false
        }
        if (!typOk) {
            let got: String = match (typValue) {
                case Some(t) => t
                case None => "nil"
            }
            warnings.add(RegistrationPolicyViolation(
                RegistrationFailureReason.InvalidType,
                "WRPRC header type must be " + WRPRC_JWT_TYPE + ", got: " + got))
            let policy = WrpRegistrationPolicy.fromJsonString(token.payloadJson)
            return (policy, warnings)
        }

        // 2. Payload → policy (throws InvalidWrprc when undecodable).
        let policy = WrpRegistrationPolicy.fromJsonString(token.payloadJson)

        // 3. Expiration.
        match (policy.exp) {
            case Some(exp) =>
                if (nowEpochSeconds() > exp) {
                    warnings.add(RegistrationPolicyViolation(
                        RegistrationFailureReason.Expired, "WRPRC is expired"))
                }
            case None => ()
        }

        // 4. Binding to the requester access certificate.
        match (wrpac) {
            case Some(cert) =>
                if (!WrpRegistrationBinding.isBound(policy, Some(cert))) {
                    warnings.add(RegistrationPolicyViolation(
                        RegistrationFailureReason.NotBoundToAccessCertificate,
                        "WRPRC not bound to requester access certificate"))
                }
            case None =>
                warnings.add(RegistrationPolicyViolation(
                    RegistrationFailureReason.AccessCertificateUnavailable,
                    "Requester access certificate not available to check WRPRC binding"))
        }

        // 5. Status list.
        match (policy.status) {
            case Some(statusRef) =>
                checkStatus(statusRef.idx, statusRef.uri, warnings)
            case None =>
                warnings.add(RegistrationPolicyViolation(
                    RegistrationFailureReason.StatusMissing,
                    "WRPRC does not have status list"))
        }

        // 6. Trust chain + signature (registrationTrustManager, WRPRC context).
        let (isTrusted, trustReason) = validateTokenTrust(trustConfig, token)
        if (!isTrusted) {
            let message = "jwt trust error: " + trustReason
            Hilog.warn(0, "WrpRegistrationValidator", message)
            warnings.add(RegistrationPolicyViolation(
                RegistrationFailureReason.TrustError, message))
        }

        return (policy, warnings)
    }

    // -----------------------------------------------------------------------
    // Trust: x5c chain via registrationTrustManager + ES256 JWS signature
    // -----------------------------------------------------------------------

    static func validateTokenTrust(
        trustConfig: ?TrustConfiguration,
        token: WrprcJwtToken
    ): (Bool, String) {
        let cfg: TrustConfiguration = match (trustConfig) {
            case Some(c) => c
            case None => return (false, "no trust configuration for WRPRC validation")
        }
        let chain = token.x5cChainDer()
        if (chain.size == 0) {
            return (false, "WRPRC carries no x5c certificate chain")
        }
        // Chain trust: WRPRC verification context (etsi registrationTrustManager).
        let (trusted, reason) = cfg.registrationTrustManager.validateCertTrustPath(chain)
        if (!trusted) {
            let msg: String = match (reason) {
                case Some(r) => r
                case None => "certificate chain not trusted"
            }
            return (false, msg)
        }
        // Signature: verify the compact JWS ES256 signature with the leaf key.
        let leafPub: ECDSAPublicKey = try {
            let leaf = Cert.fromDer(chain[0])
            ECDSAPublicKey.decodeDer(DerBlob(leaf.publicKeyDer))
        } catch (e: Exception) {
            return (false, "WRPRC leaf public key cannot be decoded: " + e.message)
        }
        let sigOk: Bool = try {
            JoseJws.verifyEs256(token.compact, leafPub)
        } catch (e: Exception) {
            return (false, "WRPRC signature verification error: " + e.message)
        }
        if (!sigOk) {
            return (false, "WRPRC signature does not verify against x5c leaf key")
        }
        return (true, "")
    }

    // -----------------------------------------------------------------------
    // Status-list check (mirrors the DocumentStatusService branch of iOS core)
    // -----------------------------------------------------------------------

    static func checkStatus(idx: Int64, uri: String, warnings: ArrayList<RegistrationPolicyViolation>): Unit {
        let credStatus: ?CredentialStatus = try {
            let statusService = DocumentStatusService()
            Some(statusService.getStatusForIndexUri(idx, uri))
        } catch (e: Exception) {
            Hilog.warn(0, "WrpRegistrationValidator",
                "WRPRC status list could not be retrieved: " + e.message)
            None
        }
        match (credStatus) {
            case Some(CredentialStatus.Valid) => ()
            case Some(CredentialStatus.Invalid) =>
                warnings.add(RegistrationPolicyViolation(
                    RegistrationFailureReason.StatusRevoked, "WRPRC status: revoked"))
            case Some(CredentialStatus.Suspended) =>
                warnings.add(RegistrationPolicyViolation(
                    RegistrationFailureReason.StatusSuspended, "WRPRC status: suspended"))
            case Some(CredentialStatus.ApplicationSpecific(code)) =>
                warnings.add(RegistrationPolicyViolation(
                    RegistrationFailureReason.StatusApplicationSpecific,
                    "WRPRC status: application-specific (" + code.toString() + ")"))
            case Some(CredentialStatus.Reserved(code)) =>
                warnings.add(RegistrationPolicyViolation(
                    RegistrationFailureReason.StatusApplicationSpecific,
                    "WRPRC status: reserved (" + code.toString() + ")"))
            case None =>
                warnings.add(RegistrationPolicyViolation(
                    RegistrationFailureReason.StatusRetrievalFailed,
                    "WRPRC status list could not be retrieved"))
        }
    }

    // -----------------------------------------------------------------------
    // Compact JWS parsing
    // -----------------------------------------------------------------------

    static func parseJwt(wrprcData: Array<UInt8>): ?WrprcJwtToken {
        let compact: String = try {
            String.fromUtf8(wrprcData).trimAscii()
        } catch (_: Exception) {
            return None
        }
        let parts = compact.split(".")
        if (parts.size < 3) {
            return None
        }
        let headerJson: String = try {
            String.fromUtf8(Base64Url.decode(parts[0]))
        } catch (_: Exception) {
            return None
        }
        let headerObj: JsonObject = try {
            match (JsonValue.fromStr(headerJson)) {
                case obj: JsonObject => obj
                case _ => return None
            }
        } catch (_: Exception) {
            return None
        }
        let payloadJson: String = try {
            String.fromUtf8(Base64Url.decode(parts[1]))
        } catch (_: Exception) {
            return None
        }
        return Some(WrprcJwtToken(compact, headerObj, payloadJson))
    }

    static func nowEpochSeconds(): Int64 {
        return DateTime.nowUTC().toUnixTimeStamp().toSeconds()
    }
}
