/*
 * issuance_models.cj
 *
 * EUDI Wallet Kit — credential issuance data models.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Models/InternalssuanceModels.swift
 *   Sources/EudiWalletKit/Models/OfferedIssuanceModel.swift
 *   Sources/EudiWalletKit/Models/BatchCreateKeyResult.swift
 *   Sources/EudiWalletKit/Models/WalletAttestationsProvider.swift (interface: in config.cj)
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.models  (S-002)
 *
 * Upstream dependencies consumed (read-only):
 *   ohos_app_cangjie_eudi_cjopenid4vp_vci  → CredentialConfigurationIdentifier,
 *                                             TransactionId, Claim, AuthorizedRequest,
 *                                             CredentialIssuerEndpoint, AuthorizeIssuanceConfig,
 *                                             DisplayMetadata (via claims module)
 *   ohos_app_cangjie_eudi_cjmdoc_data_model → DocDataFormat, CoseKey, KeyOptions, CredentialOptions
 *   ohos_app_cangjie_eudi_cjwallet_storage  → DocumentStatus
 *
 * Notes:
 *   - R-100 / R-105: IssuanceOutcome as plain enum (not Exception).
 *   - R-102: no static let in enum body; companion class used where needed.
 *   - ConfigurationCredentialMetadata does not exist in third_party; defined locally
 *     as an opaque data carrier (JSON string wrapper) since the iOS type is
 *     used only to transport raw credential metadata JSON.
 *   - iOS CredentialIssuerEndpoint → represented as String (URL) in Cangjie.
 *   - iOS AuthorizedRequest → opaque token string (its full graph depends on
 *     OAuthClient which is not available; stored as token string only).
 *   - BatchCreateKeyResult uses CoseKey from mdoc-data-model.
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.models

import std.collection.ArrayList
import std.collection.HashMap
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.claims.DocDataFormat
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.engagement.CoseKey
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.KeyOptions
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.CredentialOptions
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.types.{CredentialConfigurationIdentifier, TransactionId, TxCode, Display}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.credential.Claim
import ohos_app_cangjie_eudi_cjwallet_storage.storage.types.DocumentStatus

// ===========================================================================
// ConfigurationCredentialMetadata
// iOS: ConfigurationCredentialMetadata (from OpenID4VCI library)
// Not present in current third_party; defined locally as opaque JSON carrier.
// ===========================================================================

/**
 * Opaque container for raw credential configuration metadata JSON.
 * Mirrors iOS ConfigurationCredentialMetadata from the OpenID4VCI library.
 * Stored as a raw JSON string; consumers can parse it for display data.
 */
public class ConfigurationCredentialMetadata {
    /** Raw JSON string of the credential configuration metadata. */
    public let rawJson: String

    public init(rawJson: String) {
        this.rawJson = rawJson
    }
}

// ===========================================================================
// BatchCreateKeyResult
// iOS: public struct BatchCreateKeyResult: Sendable
// ===========================================================================

/**
 * Result of creating a batch of wallet keys together with their batch attestation JWT.
 *
 * keys         — the generated public COSE keys
 * keyAttestation — key attestation JWT covering the generated key batch
 */
public class BatchCreateKeyResult {
    public let keys: ArrayList<CoseKey>
    public let keyAttestation: String

    public init(keys: ArrayList<CoseKey>, keyAttestation: String) {
        this.keys = keys
        this.keyAttestation = keyAttestation
    }
}

// ===========================================================================
// CredentialConfiguration (internal)
// iOS: internal struct CredentialConfiguration: Codable, Sendable
// Used by the issuance service for per-credential type state tracking.
// ===========================================================================

/**
 * Internal per-credential-type configuration snapshot captured at offer resolution.
 * Mirrors iOS CredentialConfiguration (package-private in iOS source).
 *
 * This is stored in issuance state and passed through the deferred/pending flows.
 */
public class CredentialConfiguration {
    public let configurationIdentifier: CredentialConfigurationIdentifier
    public let credentialIssuerIdentifier: String
    public let docType: ?String
    public let vct: ?String
    public let scope: ?String
    public let supportsAttestationProofType: Bool
    public let supportsJwtProofTypeWithAttestation: Bool
    public let supportsJwtProofTypeWithoutAttestation: Bool
    public let credentialSigningAlgValuesSupported: Array<String>
    public let dpopSigningAlgValuesSupported: ?Array<String>
    public let clientAttestationPopSigningAlgValuesSupported: ?Array<String>
    public let issuerDisplay: ArrayList<Display>
    public let display: ArrayList<Display>
    public let claims: ArrayList<Claim>
    public let credentialMetadata: ?ConfigurationCredentialMetadata
    public let format: DocDataFormat
    public let defaultCredentialOptions: CredentialOptions

    public init(configurationIdentifier: CredentialConfigurationIdentifier,
                credentialIssuerIdentifier: String,
                docType: ?String,
                vct: ?String,
                scope: ?String,
                supportsAttestationProofType: Bool,
                supportsJwtProofTypeWithAttestation: Bool,
                supportsJwtProofTypeWithoutAttestation: Bool,
                credentialSigningAlgValuesSupported: Array<String>,
                dpopSigningAlgValuesSupported: ?Array<String>,
                clientAttestationPopSigningAlgValuesSupported: ?Array<String>,
                issuerDisplay: ArrayList<Display>,
                display: ArrayList<Display>,
                claims: ArrayList<Claim>,
                credentialMetadata: ?ConfigurationCredentialMetadata,
                format: DocDataFormat,
                defaultCredentialOptions: CredentialOptions) {
        this.configurationIdentifier = configurationIdentifier
        this.credentialIssuerIdentifier = credentialIssuerIdentifier
        this.docType = docType
        this.vct = vct
        this.scope = scope
        this.supportsAttestationProofType = supportsAttestationProofType
        this.supportsJwtProofTypeWithAttestation = supportsJwtProofTypeWithAttestation
        this.supportsJwtProofTypeWithoutAttestation = supportsJwtProofTypeWithoutAttestation
        this.credentialSigningAlgValuesSupported = credentialSigningAlgValuesSupported
        this.dpopSigningAlgValuesSupported = dpopSigningAlgValuesSupported
        this.clientAttestationPopSigningAlgValuesSupported = clientAttestationPopSigningAlgValuesSupported
        this.issuerDisplay = issuerDisplay
        this.display = display
        this.claims = claims
        this.credentialMetadata = credentialMetadata
        this.format = format
        this.defaultCredentialOptions = defaultCredentialOptions
    }
}

// ===========================================================================
// DeferredIssuanceModel (internal)
// iOS: internal struct DeferredIssuanceModel: Codable, Sendable
// ===========================================================================

/**
 * State model for a deferred issuance flow.
 * Stored until the credential is ready at the deferred endpoint.
 *
 * deferredEndpointUrl — URL of the deferred credential endpoint
 * transactionId       — opaque transaction id from the issuer
 * publicKeysData      — serialized public key bytes (one per batch entry)
 * derKeyData          — optional DER-encoded private key (software area only)
 * timeStamp           — Unix epoch seconds when this was created
 */
public class DeferredIssuanceModel {
    public let deferredEndpointUrl: String
    public let transactionId: TransactionId
    public let publicKeysData: ArrayList<Array<UInt8>>
    public let derKeyData: ?Array<UInt8>
    public let timeStamp: Float64
    /**
     * Authorization state persisted for the later deferred poll (iOS keeps the
     * equivalent AuthorizedRequestData in DocMetadata.authorizedRequestData and
     * the DPoP key alias in DocMetadata.dpopKeyId). Without these the deferred
     * endpoint call cannot be authorized after the original session ends.
     */
    public let accessToken: String
    public let tokenType: String
    public let refreshToken: String
    /** Access-token lifetime in seconds (0 = unknown). */
    public let expiresIn: Float64
    /**
     * HUKS / SecureArea key id for the session DPoP key (iOS DocMetadata.dpopKeyId).
     * Empty when this deferred blob predates HUKS DPoP or the session used no DPoP.
     */
    public let dpopKeyId: String
    /**
     * Legacy DER-encoded DPoP private key. New saves leave this empty; kept so
     * a deferred poll that started before HUKS DPoP can still complete.
     */
    public let dpopKeyDer: Array<UInt8>

    public init(deferredEndpointUrl: String, transactionId: TransactionId,
                publicKeysData: ArrayList<Array<UInt8>>, derKeyData: ?Array<UInt8>,
                timeStamp: Float64,
                accessToken!: String = "",
                tokenType!: String = "",
                refreshToken!: String = "",
                expiresIn!: Float64 = 0.0,
                dpopKeyId!: String = "",
                dpopKeyDer!: Array<UInt8> = Array<UInt8>()) {
        this.deferredEndpointUrl = deferredEndpointUrl
        this.transactionId = transactionId
        this.publicKeysData = publicKeysData
        this.derKeyData = derKeyData
        this.timeStamp = timeStamp
        this.accessToken = accessToken
        this.tokenType = tokenType
        this.refreshToken = refreshToken
        this.expiresIn = expiresIn
        this.dpopKeyId = dpopKeyId
        this.dpopKeyDer = dpopKeyDer
    }
}

// ===========================================================================
// PendingIssuanceModel (internal)
// iOS: internal struct PendingIssuanceModel: Codable
// ===========================================================================

/**
 * Reason for a pending issuance (e.g. OAuth presentation_request redirect).
 * Mirrors iOS PendingIssuanceModel.PendingReason.
 */
public enum PendingReason {
    /** A presentation_request URL was returned instead of a credential. */
    | PresentationRequestUrl(String)
}

/**
 * State model for a pending issuance flow (OAuth redirect in progress).
 *
 * pendingReason     — why issuance is pending
 * configuration     — credential configuration snapshot
 * metadataKey       — storage key for this pending issuance
 * pkceCodeVerifier  — PKCE code verifier
 * pkceCodeVerifierMethod — PKCE method ("S256")
 * state             — OAuth state parameter
 * dpopKeyId         — SecureArea id of the DPoP key the PAR bound via dpop_jkt
 */
public class PendingIssuanceModel {
    public let pendingReason: PendingReason
    public let configuration: CredentialConfiguration
    public let metadataKey: String
    public let pkceCodeVerifier: String
    public let pkceCodeVerifierMethod: String
    public let state: String
    // All credential_configuration_ids authorized together in one request
    // (iOS "PID Combined" issues every PID format from a single authorization).
    // Empty ⇒ single-config (falls back to `configuration`); see allConfigIds().
    public let configIds: Array<String>
    // The authorization server binds the browser session to the DPoP public key
    // thumbprint (dpop_jkt) sent with the PAR; the token request after the
    // redirect must be proven with that SAME key. iOS derives a deterministic
    // key id per issuer (generatePopKeyId); this port persists the random id.
    // Empty ⇒ DPoP disabled, or a document stored before this field existed.
    public let dpopKeyId: String

    public init(pendingReason: PendingReason, configuration: CredentialConfiguration,
                metadataKey: String, pkceCodeVerifier: String,
                pkceCodeVerifierMethod: String, state: String,
                configIds!: Array<String> = Array<String>(),
                dpopKeyId!: String = "") {
        this.pendingReason = pendingReason
        this.configuration = configuration
        this.metadataKey = metadataKey
        this.pkceCodeVerifier = pkceCodeVerifier
        this.pkceCodeVerifierMethod = pkceCodeVerifierMethod
        this.state = state
        this.configIds = configIds
        this.dpopKeyId = dpopKeyId
    }

    /** The full config-id set for this authorization; falls back to the primary
     *  configuration's id when no combined list was recorded (single-config). */
    public func allConfigIds(): Array<String> {
        if (configIds.size > 0) {
            return configIds
        }
        return [configuration.configurationIdentifier.value]
    }
}

// ===========================================================================
// IssuanceOutcome (internal)
// iOS: internal enum IssuanceOutcome
// ===========================================================================

/**
 * Outcome of an issuance request.
 *
 * Issued   — one or more credentials were returned (data+publicKey pairs)
 * Deferred — issuer accepted but deferred; model for polling later
 * Pending  — OAuth redirect required before issuance can continue
 *
 * authorizedRequestToken: opaque OAuth authorized-request token string
 * (the full AuthorizedRequest object graph is handled in the issuance service).
 */
public enum IssuanceOutcome {
    | Issued(ArrayList<(Array<UInt8>, Array<UInt8>)>, CredentialConfiguration, String)
    | Deferred(DeferredIssuanceModel, CredentialConfiguration, String)
    | Pending(PendingIssuanceModel)
}

/** Helper functions for IssuanceOutcome (R-102: no static let in enum). */
public class IssuanceOutcomeHelper {
    public static func isDeferred(outcome: IssuanceOutcome): Bool {
        match (outcome) {
            case IssuanceOutcome.Deferred(_, _, _) => return true
            case _ => return false
        }
    }

    public static func isPending(outcome: IssuanceOutcome): Bool {
        match (outcome) {
            case IssuanceOutcome.Pending(_) => return true
            case _ => return false
        }
    }

    public static func pendingOrDeferredStatus(outcome: IssuanceOutcome): ?DocumentStatus {
        match (outcome) {
            case IssuanceOutcome.Deferred(_, _, _) => return Some(DocumentStatus.Deferred)
            case IssuanceOutcome.Pending(_) => return Some(DocumentStatus.Pending)
            case _ => return None
        }
    }

    /**
     * Extract credential data bytes for a given index from an Issued outcome.
     * Returns empty array if out of range or not Issued.
     */
    public static func getDataToSave(outcome: IssuanceOutcome, index: Int64): Array<UInt8> {
        match (outcome) {
            case IssuanceOutcome.Issued(dataPairs, _, _) =>
                if (index >= 0 && index < dataPairs.size) {
                    let (data, _) = dataPairs[index]
                    return data
                }
                return []
            case _ => return []
        }
    }

    /**
     * Extract public key bytes for a given index from an Issued outcome.
     * Returns empty array if out of range or not Issued.
     */
    public static func getPublicKey(outcome: IssuanceOutcome, index: Int64): Array<UInt8> {
        match (outcome) {
            case IssuanceOutcome.Issued(dataPairs, _, _) =>
                if (index >= 0 && index < dataPairs.size) {
                    let (_, pk) = dataPairs[index]
                    return pk
                }
                return []
            case _ => return []
        }
    }
}

// ===========================================================================
// OfferedDocModel
// iOS: @Copyable public struct OfferedDocModel: Sendable
// ===========================================================================

/**
 * Information about an offered document to be issued.
 *
 * Returned as part of OfferedIssuanceModel when resolving an issuance offer URL.
 */
public class OfferedDocModel {
    public let credentialConfigurationIdentifier: String
    public let docType: ?String
    public let vct: ?String
    public let scope: ?String
    public let identifier: ?String
    public let displayName: String
    public let algValuesSupported: Array<String>
    public let claims: ArrayList<Claim>
    public let credentialMetadata: ?ConfigurationCredentialMetadata
    public let credentialOptions: CredentialOptions
    public let keyOptions: ?KeyOptions

    public init(credentialConfigurationIdentifier: String,
                docType: ?String,
                vct: ?String,
                scope: ?String,
                identifier: ?String,
                displayName: String,
                algValuesSupported: Array<String>,
                claims: ArrayList<Claim>,
                credentialMetadata: ?ConfigurationCredentialMetadata,
                credentialOptions: CredentialOptions,
                keyOptions: ?KeyOptions) {
        this.credentialConfigurationIdentifier = credentialConfigurationIdentifier
        this.docType = docType
        this.vct = vct
        this.scope = scope
        this.identifier = identifier
        this.displayName = displayName
        this.algValuesSupported = algValuesSupported
        this.claims = claims
        this.credentialMetadata = credentialMetadata
        this.credentialOptions = credentialOptions
        this.keyOptions = keyOptions
    }

    /** docType if msoMdoc, vct if SD-JWT, else None. */
    public func docTypeOrVct(): ?String {
        match (this.docType) {
            case Some(dt) => return Some(dt)
            case None => return this.vct
        }
    }

    /**
     * Convert to DocTypeIdentifier.
     * Mirrors iOS OfferedDocModel.docTypeIdentifier computed property.
     */
    public func docTypeIdentifier(): ?DocTypeIdentifier {
        match (this.identifier) {
            case Some(id) => return Some(DocTypeIdentifier.Identifier(id))
            case None =>
                match (this.docType) {
                    case Some(dt) => return Some(DocTypeIdentifier.MsoMdoc(dt))
                    case None =>
                        match (this.vct) {
                            case Some(v) => return Some(DocTypeIdentifier.SdJwt(v))
                            case None => return None
                        }
                }
        }
    }
}

// ===========================================================================
// OfferedIssuanceModel
// iOS: public struct OfferedIssuanceModel: Sendable
// ===========================================================================

/**
 * Information gathered by resolving an issuance offer URL.
 * Returned from EudiWallet.resolveOfferUrlDocTypes(uriOffer:).
 *
 * issuerName     — display name of the issuer
 * issuerLogoUrl  — optional URL to the issuer logo
 * docModels      — one entry per credential type included in the offer
 * txCodeSpec     — transaction code spec (pre-authorized flow only)
 */
public class OfferedIssuanceModel {
    public let issuerName: String
    public let issuerLogoUrl: ?String
    public let docModels: ArrayList<OfferedDocModel>
    public let txCodeSpec: ?TxCode
    /**
     * The WRP registration policy decoded from the issuer's WRPRC while the
     * offer was resolved, when validateRegistrationCertificate is enabled.
     * Preserved even when validation failed so the issuer identity can be
     * inspected. Mirrors iOS OfferedIssuanceModel.wrpVciRegistrationPolicy.
     */
    public let wrpVciRegistrationPolicy: ?WrpRegistrationPolicy
    /**
     * WRPRC violations collected while the offer was resolved, keyed by
     * credential configuration identifier; the empty key holds request-wide
     * violations. None when validation is not enabled.
     * Mirrors iOS OfferedIssuanceModel.wrpVciWarnings.
     */
    public let wrpVciWarnings: ?HashMap<String, Array<RegistrationPolicyViolation>>

    public init(issuerName: String, issuerLogoUrl: ?String,
                docModels: ArrayList<OfferedDocModel>, txCodeSpec: ?TxCode,
                wrpVciRegistrationPolicy!: ?WrpRegistrationPolicy = None,
                wrpVciWarnings!: ?HashMap<String, Array<RegistrationPolicyViolation>> = None) {
        this.issuerName = issuerName
        this.issuerLogoUrl = issuerLogoUrl
        this.docModels = docModels
        this.txCodeSpec = txCodeSpec
        this.wrpVciRegistrationPolicy = wrpVciRegistrationPolicy
        this.wrpVciWarnings = wrpVciWarnings
    }

    /** True when a transaction code is required (pre-authorized flow). */
    public func isTxCodeRequired(): Bool {
        match (this.txCodeSpec) {
            case Some(_) => return true
            case None => return false
        }
    }
}
