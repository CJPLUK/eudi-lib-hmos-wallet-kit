/*
 * wallet_error.cj
 *
 * EUDI Wallet Kit — error types.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Models/WalletError.swift
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.models  (S-002)
 *
 * Notes:
 *   - R-100 / R-105: enum cannot extend Exception; implemented as class<:Exception
 *     with a companion enum WalletErrorCode for the structured code.
 *   - R-105: Exception subclass must NOT re-declare `message`; message is passed
 *     via super(msg) and accessed via the inherited property.
 *   - iOS WalletError is a struct conforming to LocalizedError; Cangjie uses class<:Exception.
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.models

// ===========================================================================
// WalletErrorCode
// iOS: public enum WalletError.Code: String, Sendable
// Cangjie: plain enum (R-100: enums cannot extend Exception)
// R-102: no static constants in enum body.
// ===========================================================================

/**
 * Structured error code for programmatic handling of WalletError.
 * Mirrors iOS WalletError.Code enum.
 */
public enum WalletErrorCode {
    /** The verifier requested a claim that is not present in the credential. */
    | ClaimNotFound
    /** The verifier requested a credential/document type not in the wallet. */
    | CredentialNotFound
    /** The verifier requested a claim whose value does not match. */
    | ClaimValueMismatch
    /** No claim_set option could be satisfied. */
    | ClaimSetNotSatisfied
    /** A required credential_set cannot be satisfied. */
    | CredentialSetNotSatisfied
    /** The DCQL query could not be satisfied (general). */
    | DcqlQueryNotSatisfied
    /** Bluetooth is not authorized by the user. */
    | BleNotAuthorized
    /** Bluetooth is not supported on this device. */
    | BleNotSupported
    /** No documents available for presentation. */
    | NoDocumentsAvailable
    /** The issuer is not registered. */
    | IssuerNotRegistered
    /**
     * A trust decision failed: the issuer (or verifier) certificate chain did
     * not validate against the configured trust anchors, or the signing key of
     * an issued credential could not be resolved to a trusted source.
     * Mirrors iOS `WalletError.Code.trustError`.
     */
    | TrustError
    /**
     * The WRP registration certificate (WRPRC) is missing, undecodable, or its
     * policy blocked the operation. Mirrors iOS `WalletError.Code.invalidWrprc`.
     */
    | InvalidWrprc

    /** Raw string value matching iOS enum rawValue. */
    public func rawValue(): String {
        match (this) {
            case ClaimNotFound           => return "claimNotFound"
            case CredentialNotFound      => return "credentialNotFound"
            case ClaimValueMismatch      => return "claimValueMismatch"
            case ClaimSetNotSatisfied    => return "claimSetNotSatisfied"
            case CredentialSetNotSatisfied => return "credentialSetNotSatisfied"
            case DcqlQueryNotSatisfied   => return "dcqlQueryNotSatisfied"
            case BleNotAuthorized        => return "bleNotAuthorized"
            case BleNotSupported         => return "bleNotSupported"
            case NoDocumentsAvailable    => return "noDocumentsAvailable"
            case IssuerNotRegistered     => return "issuerNotRegistered"
            case TrustError              => return "trustError"
            case InvalidWrprc            => return "invalidWrprc"
        }
    }

    /** Parse from raw string. Returns None if unrecognised. */
    public static func fromRaw(raw: String): ?WalletErrorCode {
        match (raw) {
            case "claimNotFound"           => return Some(WalletErrorCode.ClaimNotFound)
            case "credentialNotFound"      => return Some(WalletErrorCode.CredentialNotFound)
            case "claimValueMismatch"      => return Some(WalletErrorCode.ClaimValueMismatch)
            case "claimSetNotSatisfied"    => return Some(WalletErrorCode.ClaimSetNotSatisfied)
            case "credentialSetNotSatisfied" => return Some(WalletErrorCode.CredentialSetNotSatisfied)
            case "dcqlQueryNotSatisfied"   => return Some(WalletErrorCode.DcqlQueryNotSatisfied)
            case "bleNotAuthorized"        => return Some(WalletErrorCode.BleNotAuthorized)
            case "bleNotSupported"         => return Some(WalletErrorCode.BleNotSupported)
            case "noDocumentsAvailable"    => return Some(WalletErrorCode.NoDocumentsAvailable)
            case "issuerNotRegistered"     => return Some(WalletErrorCode.IssuerNotRegistered)
            case "trustError"              => return Some(WalletErrorCode.TrustError)
            case "invalidWrprc"            => return Some(WalletErrorCode.InvalidWrprc)
            case _                         => return None
        }
    }
}

// ===========================================================================
// WalletError
// iOS: public struct WalletError: LocalizedError
// Cangjie: class <: Exception (R-100: cannot use enum here; R-105: no re-declare message)
// ===========================================================================

/**
 * EUDI wallet error.
 *
 * Wraps a human-readable description, an optional localization key,
 * an optional structured code, and optional context key-value pairs.
 *
 * Downstream code catches `WalletError` exceptions and can inspect
 * `code` for programmatic handling.
 */
public class WalletError <: Exception {
    /**
     * Deprecated localization key (kept for iOS API parity).
     * Prefer `code` for programmatic error handling.
     */
    public let localizationKey: ?String
    /** Structured error code; None for legacy errors. */
    public let code: ?WalletErrorCode
    /** Additional context (e.g. claim path, docType). */
    public let context: Array<(String, String)>
    /**
     * The wrapped underlying error, if any (mirrors iOS `WalletError.innerError`).
     * Downstream code can inspect it, e.g. to detect an OpenID4VP
     * `authorizationPolicyNotMet` or an OpenID4VCI `WRPRCError`.
     */
    public let innerError: ?Exception

    /**
     * Primary constructor.
     *
     * R-101: init parameter names need `!` prefix for named-parameter call style.
     * Using positional style here to avoid call-site breakage; `innerError` is
     * a named optional so existing 4-argument call sites stay valid.
     */
    public init(description: String, localizationKey: ?String, code: ?WalletErrorCode,
                context: Array<(String, String)>, innerError!: ?Exception = None) {
        // R-105: pass message to super; do NOT redeclare `message` field.
        super(description)
        this.localizationKey = localizationKey
        this.code = code
        this.context = context
        this.innerError = innerError
    }

    /** Convenience: create with description only. */
    public static func withDescription(description: String): WalletError {
        return WalletError(description, None, None, [])
    }

    /** Convenience: create with description and structured code. */
    public static func withCode(description: String, code: WalletErrorCode): WalletError {
        return WalletError(description, None, Some(code), [])
    }

    /** Convenience: create with description, code and context pairs. */
    public static func withContext(description: String, code: WalletErrorCode,
                                   context: Array<(String, String)>): WalletError {
        return WalletError(description, None, Some(code), context)
    }

    /** Convenience: create with description, code and a wrapped inner error. */
    public static func withInner(description: String, code: WalletErrorCode,
                                 innerError: Exception): WalletError {
        return WalletError(description, None, Some(code), [], innerError: Some(innerError))
    }

    /**
     * Human-readable description (mirrors iOS errorDescription).
     * Uses the message inherited from Exception.
     */
    public func errorDescription(): String {
        match (this.localizationKey) {
            case Some(key) => return key + ": " + this.message
            case None      => return this.message
        }
    }
}
