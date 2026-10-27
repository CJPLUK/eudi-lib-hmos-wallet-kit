/*
 * presentation_policy_violation.cj
 *
 * EUDI Wallet Kit — typed WRP registration certificate violations (presentation).
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Models/PresentationPolicyViolation.swift  (v0.40.9)
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.models  (S-002)
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.models

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.ClaimPath

// ===========================================================================
// PresentationFailureReason
// iOS: public enum PresentationFailureReason: Sendable, Hashable
// ===========================================================================

/**
 * Typed reason for a WRP registration certificate validation failure or
 * warning during presentation.
 */
public enum PresentationFailureReason {
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
    /**
     * The verifier requests claims beyond the registration policy scope.
     * Payload: (docType or vct, extra claim paths — None means the whole
     * attestation is outside the policy scope).
     */
    | OverAskedClaims(String, ?Array<ClaimPath>)
    /** The WRPRC is not repeated in every ItemsRequest.requestInfo. */
    | WrprcNotRepeated
    /** Different WRPRC values found across ItemsRequest.requestInfo entries. */
    | WrprcMismatch
    /** The WRPRC entitlements do not include the expected operation. */
    | EntitlementMissing(String)
    /** An unclassified failure. */
    | Other

    /**
     * Map a RegistrationFailureReason to the corresponding presentation
     * failure reason. Mirrors iOS
     * PresentationFailureReason.init(registrationReason:).
     */
    public static func fromRegistrationReason(reason: RegistrationFailureReason): PresentationFailureReason {
        match (reason) {
            case RegistrationFailureReason.Expired => return PresentationFailureReason.Expired
            case RegistrationFailureReason.StatusRevoked => return PresentationFailureReason.StatusRevoked
            case RegistrationFailureReason.StatusSuspended => return PresentationFailureReason.StatusSuspended
            case RegistrationFailureReason.StatusApplicationSpecific =>
                return PresentationFailureReason.StatusApplicationSpecific
            case RegistrationFailureReason.StatusMissing => return PresentationFailureReason.StatusMissing
            case RegistrationFailureReason.StatusRetrievalFailed =>
                return PresentationFailureReason.StatusRetrievalFailed
            case RegistrationFailureReason.TrustError => return PresentationFailureReason.TrustError
            case RegistrationFailureReason.InvalidType => return PresentationFailureReason.InvalidType
            case RegistrationFailureReason.PayloadDecodingFailed =>
                return PresentationFailureReason.PayloadDecodingFailed
            case RegistrationFailureReason.InvalidCertificate =>
                return PresentationFailureReason.InvalidCertificate
            case RegistrationFailureReason.WrpacDecodingFailed =>
                return PresentationFailureReason.WrpacDecodingFailed
            case RegistrationFailureReason.NotBoundToAccessCertificate =>
                return PresentationFailureReason.NotBoundToAccessCertificate
            case RegistrationFailureReason.AccessCertificateUnavailable =>
                return PresentationFailureReason.AccessCertificateUnavailable
            case _ => return PresentationFailureReason.Other
        }
    }

    /** True when this reason blocks presentation under TrustPolicy.Enforce. */
    public func isEnforceable(): Bool {
        // Mirrors iOS WrpVpRegistrationValidator enforceableReasons:
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

    /** True for OverAskedClaims(_, _) (the only case the app layer branches on). */
    public func isOverAskedClaims(): Bool {
        match (this) {
            case OverAskedClaims(_, _) => return true
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
            case OverAskedClaims(docType, _) => return "overAskedClaims(" + docType + ")"
            case WrprcNotRepeated => return "wrprcNotRepeated"
            case WrprcMismatch => return "wrprcMismatch"
            case EntitlementMissing(e) => return "entitlementMissing(" + e + ")"
            case Other => return "other"
        }
    }
}

// ===========================================================================
// PresentationPolicyViolation
// iOS: public struct PresentationPolicyViolation: Sendable, Hashable
// ===========================================================================

/** A WRP registration certificate violation with a typed reason during presentation. */
public class PresentationPolicyViolation {
    /** The typed failure reason. */
    public let reason: PresentationFailureReason
    /** A human-readable description of the violation. */
    public let message: String

    public init(reason: PresentationFailureReason, message: String) {
        this.reason = reason
        this.message = message
    }

    /**
     * Convert from a RegistrationPolicyViolation produced by the shared core
     * validator. Mirrors iOS PresentationPolicyViolation.init(from:).
     */
    public static func fromRegistration(violation: RegistrationPolicyViolation): PresentationPolicyViolation {
        return PresentationPolicyViolation(
            PresentationFailureReason.fromRegistrationReason(violation.reason),
            violation.message
        )
    }
}
