/*
 * enums.cj
 *
 * EUDI Wallet Kit — public enumerations.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Models/Enums.swift (DocTypeIdentifier + internal enums)
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.models  (S-002)
 *
 * Notes:
 *   - R-102: no static let inside enum body; constants extracted to companion classes.
 *   - Internal-only enums (AsWebOutcome, AuthorizeRequestOutcome) are kept package-private.
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.models

// ===========================================================================
// DocTypeIdentifier
// Public enum: identifies a credential/document by its type discriminator.
// iOS: public enum DocTypeIdentifier: Sendable, Hashable, Codable
// ===========================================================================

/**
 * Discriminated union for credential/document type identifiers.
 *
 * msoMdoc   — ISO 18013-5 mDoc identified by docType string
 * sdJwt     — SD-JWT VC identified by vct (Verifiable Credential Type) string
 * identifier — credential configuration identifier (VCI offer)
 */
public enum DocTypeIdentifier {
    | MsoMdoc(String)     // iOS: .msoMdoc(docType: String)
    | SdJwt(String)       // iOS: .sdJwt(vct: String)
    | Identifier(String)  // iOS: .identifier(String)

    /** Extract docType for msoMdoc credentials; None for other variants. */
    public func docType(): ?String {
        match (this) {
            case MsoMdoc(dt) => return Some(dt)
            case _ => return None
        }
    }

    /** Extract vct for SD-JWT credentials; None for other variants. */
    public func vct(): ?String {
        match (this) {
            case SdJwt(v) => return Some(v)
            case _ => return None
        }
    }

    /** Extract configuration identifier; None for other variants. */
    public func configurationIdentifier(): ?String {
        match (this) {
            case Identifier(id) => return Some(id)
            case _ => return None
        }
    }

    /** Return docType if msoMdoc, vct if sdJwt, nil for identifier variant. */
    public func docTypeOrVct(): ?String {
        match (this) {
            case MsoMdoc(dt) => return Some(dt)
            case SdJwt(v)    => return Some(v)
            case Identifier(_) => return None
        }
    }

    /**
     * Primary string value regardless of variant.
     * iOS: var value: String { ... }
     */
    public func value(): String {
        match (this) {
            case MsoMdoc(dt)   => return dt
            case SdJwt(v)      => return v
            case Identifier(id) => return id
        }
    }

    /**
     * Equality check (mirrors Hashable/Equatable).
     * Cangjie does not support operator == on enum with associated values automatically.
     */
    public func equals(other: DocTypeIdentifier): Bool {
        match ((this, other)) {
            case (MsoMdoc(a), MsoMdoc(b))     => return a == b
            case (SdJwt(a), SdJwt(b))         => return a == b
            case (Identifier(a), Identifier(b)) => return a == b
            case _ => return false
        }
    }

    /** Human-readable string for logging. */
    public func describe(): String {
        match (this) {
            case MsoMdoc(dt)   => return "msoMdoc(" + dt + ")"
            case SdJwt(v)      => return "sdJwt(" + v + ")"
            case Identifier(id) => return "identifier(" + id + ")"
        }
    }
}

// ===========================================================================
// AsWebOutcome (package-private)
// iOS: internal enum AsWebOutcome (not exported to consumers)
// ===========================================================================

enum AsWebOutcome {
    | Code(String, ?String)      // code, state
    | PresentationRequest(String) // URL as string
}

// ===========================================================================
// AuthorizeRequestOutcome (package-private)
// iOS: internal enum AuthorizeRequestOutcome
// ===========================================================================

enum AuthorizeRequestOutcome {
    | Authorized(String)         // AuthorizedRequest token string
    | PresentationRequest(String) // URL as string
}
