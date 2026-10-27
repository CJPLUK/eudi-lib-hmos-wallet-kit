/*
 * registration_policy_violation.cj
 *
 * EUDI Wallet Kit — typed WRP registration certificate violations (issuance).
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Models/RegistrationPolicyViolation.swift  (v0.40.9)
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.models  (S-002)
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.models

// ===========================================================================
// RegistrationFailureReason
// iOS: public enum RegistrationFailureReason: Sendable, Hashable
// ===========================================================================

/** Typed reason for a WRP registration certificate validation failure or warning. */
public enum RegistrationFailureReason {
    /** The WRPRC `exp` claim has passed. */
    | Expired
    /** The WRPRC status is revoked (invalid). */
    | StatusRevoked
    /** The WRPRC status is suspended. */
    | StatusSuspended
    /** The WRPRC status is an application-specific or reserved non-valid value. */
    | StatusApplicationSpecific
    /** The WRPRC does not contain a status list reference. */
    | StatusMissing
    /** The WRPRC status list could not be retrieved. */
    | StatusRetrievalFailed
    /** The WRPRC trust chain could not be validated. */
    | TrustError
    /** The WRPRC header type is not a registration certificate type. */
    | InvalidType
    /** The WRPRC payload could not be decoded. */
    | PayloadDecodingFailed
    /** The WRPRC data could not be decoded at all. */
    | InvalidCertificate
    /** The WRPAC (access certificate) could not be decoded. */
    | WrpacDecodingFailed
    /** The WRPRC is not bound to the requester access certificate. */
    | NotBoundToAccessCertificate
    /** The requester access certificate was not available to check WRPRC binding. */
    | AccessCertificateUnavailable
    /** A credential configuration is not covered by the issuer's `provides_attestations` claim. */
    | CredentialNotCovered(String)
    /** The required entitlement is missing from the WRPRC (payload: expected entitlement). */
    | EntitlementMissing(String)
    /** An unclassified failure. */
    | Other

    /** True when this reason blocks issuance under TrustPolicy.Enforce. */
    public func isEnforceable(): Bool {
        // Mirrors iOS WrpVciRegistrationValidator.enforceableReasons:
        // expired, statusRevoked, statusSuspended, statusApplicationSpecific,
        // statusMissing, trustError, invalidType.
        match (this) {
            case Expired => return true
            case StatusRevoked => return true
            case StatusSuspended => return true
            case StatusApplicationSpecific => return true
            case StatusMissing => return true
            case TrustError => return true
            case InvalidType => return true
            case _ => return false
        }
    }

    /** True for CredentialNotCovered(_) (the only case the app layer branches on). */
    public func isCredentialNotCovered(): Bool {
        match (this) {
            case CredentialNotCovered(_) => return true
            case _ => return false
        }
    }

    /** Stable raw label for logging / diagnostics. */
    public func rawValue(): String {
        match (this) {
            case Expired => return "expired"
            case StatusRevoked => return "statusRevoked"
            case StatusSuspended => return "statusSuspended"
            case StatusApplicationSpecific => return "statusApplicationSpecific"
            case StatusMissing => return "statusMissing"
            case StatusRetrievalFailed => return "statusRetrievalFailed"
            case TrustError => return "trustError"
            case InvalidType => return "invalidType"
            case PayloadDecodingFailed => return "payloadDecodingFailed"
            case InvalidCertificate => return "invalidCertificate"
            case WrpacDecodingFailed => return "wrpacDecodingFailed"
            case NotBoundToAccessCertificate => return "notBoundToAccessCertificate"
            case AccessCertificateUnavailable => return "accessCertificateUnavailable"
            case CredentialNotCovered(id) => return "credentialNotCovered(" + id + ")"
            case EntitlementMissing(e) => return "entitlementMissing(" + e + ")"
            case Other => return "other"
        }
    }
}

// ===========================================================================
// RegistrationPolicyViolation
// iOS: public struct RegistrationPolicyViolation: Sendable, Hashable
// ===========================================================================

/** A WRP registration certificate violation with a typed reason and message. */
public class RegistrationPolicyViolation {
    /** The typed failure reason. */
    public let reason: RegistrationFailureReason
    /** A human-readable description of the violation. */
    public let message: String

    public init(reason: RegistrationFailureReason, message: String) {
        this.reason = reason
        this.message = message
    }
}
