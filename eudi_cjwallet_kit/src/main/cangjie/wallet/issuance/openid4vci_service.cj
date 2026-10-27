/*
 * openid4vci_service.cj
 *
 * EUDI Wallet Kit — OpenID4VCI credential issuance service.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Services/OpenId4VciService.swift
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.issuance  (S-002)
 *
 * Responsibilities:
 *   - Resolve credential offer URLs → OfferedIssuanceModel (issuer display + offered docs)
 *   - Orchestrate OpenID4VCI authorization code flow and pre-authorized code flow
 *   - Issue, defer, and resume pending credentials
 *   - Save issued credentials to DataStorageService via StorageManager
 *
 * iOS actor → Cangjie class (synchronous).
 * iOS async/await → synchronous throws.
 * iOS static nonisolated(unsafe) var caches → instance-level HashMap fields.
 *
 * Key design decisions (fallbacks documented in wk_issuance.json unresolved_api_decisions):
 *   - IssueRequest defined locally (not in third_party).
 *   - BindingKey.JwtCallback signs OpenID4VCI proofs via SecureAreaSigner
 *     (HUKS batch keys). Software JwtKey is only kept for protocol-library tests.
 *   - UUID-like id: randomBase64UrlString(16) from dpop package helper.
 *   - No browser/ASWebAuthentication equivalent; auth URL exposed to caller.
 *   - Metadata and offer caches are instance-level HashMaps.
 *
 * Syntax rules observed:
 *   R-101: no named params in positional-only function calls.
 *   R-102: no static let in enum body.
 *   R-103: HashMap uses subscript assignment [k]=v and .add(); no .put().
 *   R-104: HashMap[k] subscript throws if absent; use .get() / .contains() guard.
 *   R-105: Exception subclass passes msg to super(); no redeclaration of message.
 *   R-106: Use Int64, not Int.
 *   R-107: type alias uses `type` keyword, not `typealias`.
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.issuance

import kit.PerformanceAnalysisKit.Hilog

import std.collection.ArrayList
import std.collection.HashMap
import std.time.*

import stdx.encoding.json.{JsonObject, JsonString, JsonArray, JsonFloat, JsonInt, JsonBool, JsonValue}

import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.{
    SecureAreaRegistry, SecureArea, KeyOptions, CredentialOptions, CredentialPolicy,
    DocKeyInfo, SigningAlgorithm, CoseEcCurve
}
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.engagement.CoseKey
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.claims.DocDataFormat
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.response.IssuerSigned
import ohos_app_cangjie_eudi_cjcbor.cbor.{CborValue, decodeCbor}
import ohos_app_cangjie_eudi_cjmdoc_security.security.issuer_auth.{MsoValidation, MsoValidationError}

import ohos_app_cangjie_eudi_cjwallet_storage.storage.types.{Document, DocumentStatus}
import ohos_app_cangjie_eudi_cjwallet_storage.storage.types.DocDataFormat as StorageDocDataFormat

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.config.{
    OpenId4VCIConfig, AuthorizeIssuanceConfig, Client, ClientKind, ParUsage, IssuerMetadataPolicy
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuer.{
    CredentialIssuerId, CredentialIssuerMetadata
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.offer.CredentialOffer
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuance.{
    AuthorizationRequested, AuthorizedRequest, IssuanceRequestPayload,
    BindingKey, SubmittedRequest, DeferredCredentialIssuanceResponse,
    CredentialIssuanceResponse, IssuedCredential, AuthorizationDetailsInTokenRequest,
    Credential
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.types.{
    CredentialConfigurationIdentifier, CredentialIdentifier, TransactionId, Nonce, Grants, TxCode, Display,
    AuthorizationCode, PreAuthorizedCode
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.access_mgmt.IdentityAndAccessManagementMetadata
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.credential.Claim
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.credential.{
    CredentialReusePolicy, CredentialReusePolicyValidator, ReuseMethod, ReusePolicy,
    SupportedCredentialReusePolicies
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.dpop.{
    DPoPConstructor, DPoPConstructorCallback, DPoPConstructorType,
    ClientAttestationCallback, ClientAttestationType
}
import ohos_app_cangjie_eudi_cjjose.jose.EcPublicKey
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.pkce.{PKCEVerifier, PKCEGenerator}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.access.{IssuanceAccessToken, IssuanceRefreshToken, TokenType}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuance.{
    AuthorizationDetailsIdentifiers, AuthorizationCodeURL, GrantType
}
import eudi_lib_core_crypto.{Base64Url, Rng, EcdsaP256}
import stdx.crypto.keys.ECDSAPrivateKey
import stdx.crypto.common.DerBlob
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.issuance.Issuer
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.resolver.{
    CredentialOfferRequestResolver, CredentialIssuerMetadataResolver, AuthorizationServerMetadataResolver
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.error.{ValidationError, CredentialIssuanceError, WRPRCError}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuer.IssuerInfo

import ohos_app_cangjie_eudi_cjetsi_1196x2.etsi_trust.TrustConfiguration
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.{
    OpenId4VciConfiguration, KeyAttestationConfiguration, WalletAttestationsProvider,
    OfferedIssuanceModel, OfferedDocModel, CredentialConfiguration,
    DeferredIssuanceModel, PendingIssuanceModel, PendingReason,
    IssuanceOutcome, IssuanceOutcomeHelper, ConfigurationCredentialMetadata,
    DocTypeIdentifier, WalletError, WalletErrorCode,
    WrpRegistrationPolicy, RegistrationPolicyViolation, RegistrationFailureReason,
    IssuerResponse
}
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.RegistrationCertificateAuthorization
import ohos_app_cangjie_eudi_cjetsi_1196x2.etsi_trust.TrustPolicy
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.storage.StorageManager
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.SecureAreaSigner

// ===========================================================================
// IssueRequest
// iOS: public struct IssueRequest (not in third_party; defined locally)
// Carries per-document state through the beginIssueDocument/endIssueDocument
// handshake.
// ===========================================================================

/**
 * State bundle for a single credential being issued.
 *
 * Mirrors iOS OpenId4VciService.IssueRequest struct.
 *
 * id                — unique document id (used as SecureArea key)
 * secureAreaName    — name of the SecureArea to use (None = default)
 * credentialOptions — batch policy + batch size
 * keyOptions        — curve + access control options
 * dpopKeyId         — key id used for DPoP proof (if DPoP enabled)
 */
public class IssueRequest {
    public let id: String
    public let secureAreaName: ?String
    public let credentialOptions: CredentialOptions
    public let keyOptions: ?KeyOptions
    public var dpopKeyId: ?String

    public init(
        id: String,
        secureAreaName: ?String,
        credentialOptions: CredentialOptions,
        keyOptions: ?KeyOptions,
        dpopKeyId: ?String
    ) {
        this.id = id
        this.secureAreaName = secureAreaName
        this.credentialOptions = credentialOptions
        this.keyOptions = keyOptions
        this.dpopKeyId = dpopKeyId
    }
}

// ===========================================================================
// OpenId4VciService
// iOS: internal class OpenId4VciService
// ===========================================================================

/**
 * Orchestrates the full OpenID4VCI credential issuance lifecycle:
 *   1. Resolve credential offer → display metadata + offered credential list
 *   2. Create key pairs in SecureArea (beginIssueDocument)
 *   3. Authorize with pre-authorized code or authorization code flow
 *   4. Send credential request with PoP proofs (BindingKey)
 *   5. Process response: Issued / Deferred / InvalidProof
 *   6. Persist documents to storage (endIssueDocument)
 *   7. Handle deferred polling and pending OAuth redirect resume
 *
 * Mirrors iOS internal class OpenId4VciService.
 *
 * Thread-safety: sequential access expected (iOS @MainActor).
 */
public class OpenId4VciService {

    // -----------------------------------------------------------------------
    // Dependencies
    // -----------------------------------------------------------------------

    /** OpenID4VCI configuration (client_id, redirect_uri, PAR/DPoP flags, …). */
    public let openId4VciConfiguration: OpenId4VciConfiguration

    /** Storage orchestration layer. */
    public let storageManager: StorageManager

    /** iOS `OpenId4VciService.trustConfig` — issuer chain checks at persist time. */
    private let trustConfiguration: ?TrustConfiguration

    // -----------------------------------------------------------------------
    // Instance-level caches (iOS: static nonisolated(unsafe) var)
    // -----------------------------------------------------------------------

    /** Cache of resolved CredentialOffer objects, keyed by offer URI. */
    private var offerCache: HashMap<String, CredentialOffer>

    /** Cache of resolved CredentialIssuerMetadata, keyed by issuer URL. */
    private var metadataCache: HashMap<String, CredentialIssuerMetadata>

    /**
     * SecureArea key id for the current session DPoP key (see
     * buildDPoPConstructor). Persisted into the DeferredIssuanceModel when the
     * issuer defers, because the deferred-endpoint poll must present DPoP proofs
     * with the SAME key the access token was bound to (iOS: dpopKeyId).
     */
    private var activeDPoPKeyId: ?String = None

    /**
     * The WRP registration policy decoded from the issuer WRPRC during the
     * last registration-validating call, if any. Mirrors iOS
     * OpenId4VciService.wrpIssuerPolicy.
     */
    public var wrpIssuerPolicy: ?WrpRegistrationPolicy = None

    /**
     * Warnings produced by the WRP registration certificate policy during the
     * last registration-validating call, keyed by credential configuration
     * identifier (empty key = request-wide). None when validation is not
     * enabled. Mirrors iOS OpenId4VciService.wrpIssuerWarnings.
     */
    public var wrpIssuerWarnings: ?HashMap<String, Array<RegistrationPolicyViolation>> = None

    // -----------------------------------------------------------------------
    // Initialiser
    // -----------------------------------------------------------------------

    /**
     * Create an OpenId4VciService.
     *
     * @param openId4VciConfiguration  VCI-specific configuration.
     * @param storageManager           Backing storage manager.
     */
    public init(
        openId4VciConfiguration: OpenId4VciConfiguration,
        storageManager: StorageManager,
        trustConfiguration!: ?TrustConfiguration = None
    ) {
        this.openId4VciConfiguration = openId4VciConfiguration
        this.storageManager = storageManager
        this.trustConfiguration = trustConfiguration
        this.offerCache = HashMap<String, CredentialOffer>()
        this.metadataCache = HashMap<String, CredentialIssuerMetadata>()
    }

    // -----------------------------------------------------------------------
    // hasIssuerUrl
    // iOS: func hasIssuerUrl(_ issuerURL: URL) -> Bool
    // -----------------------------------------------------------------------

    /**
     * Return true if the service is configured with the given issuer URL.
     *
     * Mirrors iOS OpenId4VciService.hasIssuerUrl(_:).
     *
     * @param issuerURL  URL string to compare against credentialIssuerURL.
     * @return true if the configuration's credentialIssuerURL equals issuerURL.
     */
    public func hasIssuerUrl(issuerURL: String): Bool {
        match (openId4VciConfiguration.credentialIssuerURL) {
            case Some(url) => return url == issuerURL
            case None => return false
        }
    }

    // -----------------------------------------------------------------------
    // getIssuerMetadata
    // iOS: func getIssuerMetadata() async throws -> CredentialIssuerMetadata
    // -----------------------------------------------------------------------

    /**
     * Resolve and return CredentialIssuerMetadata for the configured issuer URL.
     * Results are cached per issuer URL.
     *
     * Mirrors iOS OpenId4VciService.getIssuerMetadata().
     *
     * @return CredentialIssuerMetadata for the configured issuer.
     * @throws WalletError if credentialIssuerURL is not configured or resolution fails.
     */
    public func getIssuerMetadata(): CredentialIssuerMetadata {
        let issuerUrl = match (openId4VciConfiguration.credentialIssuerURL) {
            case Some(u) => u
            case None =>
                throw WalletError.withDescription("credentialIssuerURL is not configured")
        }

        // Honour cacheIssuerMetadata=false: skip the cache in both directions
        // so registration certificates / trust anchors are re-fetched fresh.
        if (openId4VciConfiguration.cacheIssuerMetadata && metadataCache.contains(issuerUrl)) {
            return metadataCache[issuerUrl]
        }

        let resolver = CredentialIssuerMetadataResolver()
        let policy = toIssuerMetadataPolicy(openId4VciConfiguration.issuerMetadataPolicy)
        let issuerId = CredentialIssuerId(issuerUrl)
        let metadata = resolver.resolve(issuerId, policy)
        if (openId4VciConfiguration.cacheIssuerMetadata) {
            metadataCache[issuerUrl] = metadata
        }
        return metadata
    }

    // -----------------------------------------------------------------------
    // WRP registration certificate (WRPRC) validation
    // iOS: makeRegistrationCertificatePolicy / IssuanceAuthorizer /
    //      resolveIssuerRegistration
    // -----------------------------------------------------------------------

    /**
     * Resolve the issuer's WRP registration certificate for a set of
     * credential configuration identifiers without starting an issuance flow.
     *
     * Mirrors iOS OpenId4VciService.resolveIssuerRegistration: validation
     * errors are recorded as policy / warnings rather than thrown, so the
     * caller can inspect the issuer registration verdict.
     *
     * @return An IssuerResponse with an empty documents array, containing the
     *         decoded registration policy and any violations.
     */
    public func resolveIssuerRegistration(credentialConfigurationIds: Array<String>): IssuerResponse {
        let metadata = getIssuerMetadata()
        validateIssuerRegistrationTolerant(metadata, credentialConfigurationIds)
        return IssuerResponse(Array<Document>(), this.wrpIssuerWarnings,
            wrpIssuerPolicy: this.wrpIssuerPolicy)
    }

    /** The VCI WRPRC trust policy (from TrustConfiguration; default Enforce). */
    private func vciWrprcTrustPolicy(): TrustPolicy {
        match (this.trustConfiguration) {
            case Some(cfg) => return cfg.wrprcVciTrustPolicy
            case None => return TrustPolicy.Enforce
        }
    }

    /**
     * Tolerant WRPRC validation: mirrors the iOS offer-resolution path
     * (`try? authorizer.authorize`) — hard failures are swallowed and the
     * outcome surfaces only through wrpIssuerPolicy / wrpIssuerWarnings.
     * No-op (fields nil) when validation is disabled.
     */
    private func validateIssuerRegistrationTolerant(
        metadata: CredentialIssuerMetadata,
        configIds: Array<String>
    ): Unit {
        if (!openId4VciConfiguration.validateRegistrationCertificate) {
            this.wrpIssuerPolicy = None
            this.wrpIssuerWarnings = None
            return
        }
        try {
            enforceIssuerRegistration(metadata, configIds)
        } catch (e: Exception) {
            Hilog.warn(0, "OpenId4VciService",
                "Issuer registration validation failed (tolerant path): " + e.message)
        }
    }

    /**
     * Enforcing WRPRC validation for the issuance paths. Mirrors the iOS
     * OpenID4VCI-library IssuanceAuthorizer invoked during authorization:
     *   - requireSigned metadata gate → WalletError(InvalidWrprc)
     *   - missing / empty issuer_info → HARD failure (WRPRCError inner)
     *   - no / multiple registration_cert entries → HARD failure
     *   - missing WRPAC → HARD failure
     *   - policy NotGranted (Enforce trust policy) → HARD failure
     * The decoded policy and warnings are recorded on the service either way.
     * No-op (fields nil) when validation is disabled.
     */
    private func enforceIssuerRegistration(
        metadata: CredentialIssuerMetadata,
        configIds: Array<String>
    ): Unit {
        if (!openId4VciConfiguration.validateRegistrationCertificate) {
            this.wrpIssuerPolicy = None
            this.wrpIssuerWarnings = None
            return
        }
        // Registration validation is only meaningful over cryptographically
        // bound (signed) issuer metadata — the metadata signer supplies the
        // WRPAC. Mirrors iOS toOpenId4VCIConfig requireSigned gate.
        match (openId4VciConfiguration.issuerMetadataPolicy) {
            case IssuerMetadataPolicy.RequireSigned(_) => ()
            case _ =>
                throw WalletError.withCode(
                    "Registration certificate validation requires issuerMetadataPolicy to be RequireSigned",
                    WalletErrorCode.InvalidWrprc
                )
        }
        // Reset validator state via a fresh validator per call (iOS creates a
        // new WrpVciRegistrationValidator in makeRegistrationCertificatePolicy).
        let validator = WrpVciRegistrationValidator(trustConfig: this.trustConfiguration)
        this.wrpIssuerPolicy = None
        this.wrpIssuerWarnings = Some(validator.wrpVciWarnings)

        // issuer_info → exactly one registration_cert attestation. Under
        // Enforce these are HARD failures (mirrors WRPRCError in the iOS
        // OpenID4VCI library); under Warning they are recorded and issuance
        // proceeds.
        let attestations = match (metadata.issuerInfo) {
            case Some(info) => info.attestations
            case None =>
                metadataShapeFailure(
                    "Issuer metadata does not carry an `issuer_info` container, or the container is empty",
                    WRPRCError.MissingIssuerInfo())
                return
        }
        if (attestations.size == 0) {
            metadataShapeFailure(
                "Issuer metadata does not carry an `issuer_info` container, or the container is empty",
                WRPRCError.MissingIssuerInfo())
            return
        }
        var wrprc: ?String = None
        var wrprcCount: Int64 = 0
        for (attestation in attestations) {
            if (attestation.format == IssuerInfo.REGISTRATION_CERT_FORMAT) {
                wrprcCount += 1
                wrprc = Some(attestation.data)
            }
        }
        if (wrprcCount > 1) {
            metadataShapeFailure(
                "More than one WRP Registration Certificate found in issuer_info; exactly one is required",
                WRPRCError.MultipleRegistrationCertificates())
            return
        }
        let wrprcValue: String = match (wrprc) {
            case Some(v) => v
            case None =>
                metadataShapeFailure(
                    "No WRP Registration Certificate found in issuer metadata issuer_info",
                    WRPRCError.MissingRequiredRegistrationCertificate())
                return
        }
        // The WRPAC (leaf that signed the metadata JWT) must have been
        // captured during signed-metadata resolution.
        match (metadata.wrpac) {
            case Some(_) => ()
            case None =>
                metadataShapeFailure(
                    "WRPAC is not available on the issuer metadata",
                    WRPRCError.MissingWrpac())
                return
        }
        // Offered configurations referenced by this request.
        let offeredConfigurations = HashMap<String, JsonObject>()
        for (configId in configIds) {
            match (metadata.credentialConfigurationsRaw.get(configId)) {
                case Some(credObj) => offeredConfigurations[configId] = credObj
                case None => ()
            }
        }
        let verdict = validator.validateCertificate(metadata.wrpac, wrprcValue, offeredConfigurations)
        this.wrpIssuerPolicy = validator.wrpVciRegistrationPolicy
        this.wrpIssuerWarnings = Some(validator.wrpVciWarnings)
        match (verdict) {
            case RegistrationCertificateAuthorization.Granted => ()
            case RegistrationCertificateAuthorization.NotGranted(reason) =>
                throw WalletError.withInner(
                    "WRPRC policy not met: " + reason,
                    WalletErrorCode.InvalidWrprc, WRPRCError.PolicyNotMet(reason))
        }
    }

    /**
     * Handle a metadata-shape WRPRC failure (missing issuer_info, missing /
     * multiple registration_cert entries, missing WRPAC): a HARD failure
     * (WalletError InvalidWrprc wrapping the WRPRCError) under the Enforce
     * trust policy; a recorded request-wide violation under Warning.
     */
    private func metadataShapeFailure(
        description: String,
        inner: WRPRCError
    ): Unit {
        match (this.vciWrprcTrustPolicy()) {
            case TrustPolicy.Enforce =>
                throw WalletError.withInner(description, WalletErrorCode.InvalidWrprc, inner)
            case TrustPolicy.Warning =>
                let warnings = HashMap<String, Array<RegistrationPolicyViolation>>()
                warnings[""] = [RegistrationPolicyViolation(
                    RegistrationFailureReason.Other, description)]
                this.wrpIssuerWarnings = Some(warnings)
                Hilog.warn(0, "OpenId4VciService", description)
        }
    }

    // -----------------------------------------------------------------------
    // resolveOfferUrlDocTypes
    // iOS: func resolveOfferUrlDocTypes(uriOffer: String) async throws -> OfferedIssuanceModel
    // -----------------------------------------------------------------------

    /**
     * Resolve a credential offer URI to an OfferedIssuanceModel.
     *
     * Mirrors iOS OpenId4VciService.resolveOfferUrlDocTypes(uriOffer:).
     *
     * @param offerUri  Credential offer URI (openid-credential-offer:// or https://).
     * @return OfferedIssuanceModel listing offered credential types and issuer metadata.
     * @throws WalletError if the offer cannot be resolved.
     */
    public func resolveOfferUrlDocTypes(offerUri: String): OfferedIssuanceModel {
        let policy = toIssuerMetadataPolicy(openId4VciConfiguration.issuerMetadataPolicy)
        let offerResolver = CredentialOfferRequestResolver()
        let offer = offerResolver.resolveUri(offerUri, policy)
        offerCache[offerUri] = offer
        return buildOfferedIssuanceModel(offer)
    }

    // -----------------------------------------------------------------------
    // resolveOfferDocTypes
    // iOS: func resolveOfferDocTypes(uriOffer: String, offer: CredentialOffer)
    //          async throws -> OfferedIssuanceModel
    // -----------------------------------------------------------------------

    /**
     * Build an OfferedIssuanceModel from a pre-resolved CredentialOffer.
     *
     * Mirrors iOS OpenId4VciService.resolveOfferDocTypes(uriOffer:offer:).
     * Used when the caller already holds the resolved CredentialOffer (e.g. after
     * issueDocuments has resolved it internally).
     *
     * @param offerUri  Offer URI (used as cache key).
     * @param offer     Pre-resolved CredentialOffer.
     * @return OfferedIssuanceModel.
     */
    public func resolveOfferDocTypes(offerUri: String, offer: CredentialOffer): OfferedIssuanceModel {
        offerCache[offerUri] = offer
        return buildOfferedIssuanceModel(offer)
    }

    // -----------------------------------------------------------------------
    // beginIssueDocument
    // iOS: func beginIssueDocument(id: String, credentialOptions: CredentialOptions,
    //          keyOptions: KeyOptions?, bDeferred: Bool) async throws -> IssueRequest
    // -----------------------------------------------------------------------

    /**
     * Create key material in the SecureArea for a credential about to be issued.
     *
     * Mirrors iOS OpenId4VciService.beginIssueDocument(id:credentialOptions:keyOptions:bDeferred:).
     *
     * @param id                Document id (opaque string, typically UUID-like).
     * @param credentialOptions Batch policy + size for the credential batch.
     * @param keyOptions        Curve / access-control options; None = SecureArea defaults.
     * @param bDeferred         True if this credential will be deferred.
     * @return IssueRequest bundling id + key configuration.
     * @throws WalletError if key creation fails.
     */
    public func beginIssueDocument(
        id: String,
        credentialOptions: CredentialOptions,
        keyOptions: ?KeyOptions,
        bDeferred: Bool
    ): IssueRequest {
        let secureAreaName: ?String = match (keyOptions) {
            case Some(ko) => ko.secureAreaName
            case None => None
        }

        let secureArea = SecureAreaRegistry.shared.get(secureAreaName)

        // Create the key batch in the SecureArea.
        let batchInfo = secureArea.createKeyBatch(id, credentialOptions, keyOptions)
        Hilog.info(0, "OpenId4VciService",
            "beginIssueDocument id=" + id +
            " batchSize=" + batchInfo.batchSize().toString() +
            " deferred=" + bDeferred.toString())

        return IssueRequest(id, secureAreaName, credentialOptions, keyOptions, None)
    }

    // -----------------------------------------------------------------------
    // endIssueDocument
    // iOS: func endIssueDocument(_ issued: IssueRequest, batch: IssuanceOutcome)
    // -----------------------------------------------------------------------

    /**
     * Persist the outcome of a credential issuance request.
     *
     * For Issued outcomes: saves each credential+publicKey pair as a Document.
     * For Deferred outcomes: saves a single Document with deferred status.
     * For Pending outcomes: saves a Document with pending status.
     *
     * Mirrors iOS OpenId4VciService.endIssueDocument(_:batch:).
     *
     * @param issued   The IssueRequest that was originally started.
     * @param outcome  The issuance outcome (Issued / Deferred / Pending).
     * @throws StorageError if persistence fails.
     */
    /**
     * Validate an issued mdoc credential's MSO before persisting it, mirroring
     * iOS OpenId4VciService.validateIssuedDocuments → IssuerSigned.validate.
     * Same rule order as iOS, plus issuer x5chain trust via issuerTrustManager
     * (Warning logs, Enforce throws WalletError.trustError):
     *   1. docType matches the requested docType
     *   2. digestAlgorithm is supported (SHA-256/384/512)
     *   3. ValueDigests match the actual IssuerSignedItem digests (anti-tamper)
     *   4. ValidityInfo: 'signed' within DS cert validity, validFrom < validUntil,
     *      current time past validFrom (60s skew)
     *   5. IssuerAuth COSE_Sign1 signature verifies against the DS cert key
     *   6. issuerTrustManager.validateCertTrustPath on x5chain (docType-scoped)
     * Device-key binding (iOS validateMsoSignature's holder half) is enforced
     * inline below from the SecureArea public point.
     *
     * The OHOS port previously never wired ANY of these into the runtime flow —
     * validation lived only in demo/unit-test code, so expired / tampered /
     * forged credentials were silently accepted (weaker than iOS).
     *
     * @param credData raw IssuerSigned CBOR (as it will be stored in Document.data)
     * @param expectedDocType the docType the wallet requested for this credential
     * @throws WalletError on any MSO validation failure.
     */

// Detect base64url TEXT bytes: issuers commonly deliver mso_mdoc credentials
// as base64url strings. Feeding that text straight to the CBOR decoder can
// mis-read a byte as a huge length header and hang cbor4cj's reader instead
// of throwing, so the format is sniffed BEFORE decoding (an IssuerSigned map
// always starts with a byte >= 0xA0, never within the base64url alphabet).
func looksLikeBase64UrlTextBytes(bytes: Array<UInt8>): Bool {
    if (bytes.isEmpty()) { return false }
    for (b in bytes) {
        let ok = (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) ||
            (b >= 0x30 && b <= 0x39) || b == 0x2D || b == 0x5F || b == 0x3D
        if (!ok) { return false }
    }
    return true
}

    private func validateIssuedMdocValidity(credData: Array<UInt8>, expectedDocType: String, holderPubX963: Array<UInt8>): Unit {
        // Stored bytes are raw IssuerSigned CBOR or a base64url string of it —
        // sniff the format first (see looksLikeBase64UrlTextBytes).
        let issuerSignedRaw = if (looksLikeBase64UrlTextBytes(credData)) {
            Base64Url.decode(String.fromUtf8(credData))
        } else { credData }
        let issuerSigned = IssuerSigned.fromCbor(decodeCbor(issuerSignedRaw))
        let issuerAuth = issuerSigned.issuerAuth
        let mso = issuerAuth.mso
        let errors = ArrayList<MsoValidationError>()
        match (MsoValidation.validateDocType(mso, expectedDocType)) {
            case Some(e) => errors.add(e)
            case None => ()
        }
        match (MsoValidation.validateDigestAlgorithm(mso)) {
            case Some(e) => errors.add(e)
            case None => ()
        }
        match (issuerSigned.issuerNameSpaces) {
            case Some(ns) =>
                for (e in MsoValidation.validateDigestValues(mso, ns)) {
                    errors.add(e)
                }
            case None => ()
        }
        for (e in MsoValidation.validateValidityInfo(mso, issuerAuth, false)) {
            errors.add(e)
        }
        match (MsoValidation.validateMsoSignature(issuerAuth)) {
            case Some(e) => errors.add(e)
            case None => ()
        }
        // Device-key binding (iOS validateMsoSignature's holder half): the MSO's
        // deviceKeyInfo.deviceKey must equal the SecureArea public point sent
        // in the credential-request proof. Skip when the point is absent.
        if (holderPubX963.size > 0) {
            match (MsoValidation.validateDeviceKeyBinding(issuerAuth, [holderPubX963])) {
                case Some(e) => errors.add(e)
                case None => ()
            }
        }
        match (this.trustConfiguration) {
            case Some(cfg) =>
                applyIssuerChainTrust(
                    cfg,
                    expectedDocType,
                    issuerAuth.x5chain.toArray(),
                    "The issuer certificate chain is not trusted"
                )
            case None => ()
        }
        if (!errors.isEmpty()) {
            throw WalletError.withDescription(errors[0].message)
        }
    }

    public func endIssueDocument(issued: IssueRequest, outcome: IssuanceOutcome): Unit {
        match (outcome) {
            case IssuanceOutcome.Issued(dataPairs, config, _) =>
                let batchSize = dataPairs.size
                Hilog.info(0, "OpenId4VciService",
                    "endIssueDocument(Issued) id=" + issued.id +
                    " count=" + batchSize.toString())

                let docType = resolveDocType(config)
                let storageFormat = docDataFormatToStorage(config.format)

                // Build the key-info bytes for storage
                let keyInfoBytes = buildDocKeyInfoBytes(issued)

                // Persist the credential-config display / issuer display alongside
                // each credential (iOS DocMetadata parity), so the wallet UI shows
                // real names & logos after the RDB round-trip. Shared by all batch
                // credentials (same configuration).
                let issuedMeta = encodeIssuedMetadata(config)

                // Persist each credential in the batch
                var batchDocs: ?Array<Document> = None
                if (batchSize > 0) {
                    let docList = ArrayList<Document>()
                    var bi: Int64 = 0
                    while (bi < batchSize) {
                        let (credData, holderPubX963) = dataPairs[bi]
                        // iOS validateIssuedDocuments parity: reject expired /
                        // not-yet-valid mdoc credentials at issuance rather than
                        // silently storing them.
                        match (config.format) {
                            case DocDataFormat.Cbor =>
                                Hilog.info(0, "VCI-DEBUG", "validate mdoc ${bi}/${batchSize}")
                                validateIssuedMdocValidity(credData, docType, holderPubX963)
                            case DocDataFormat.Sdjwt =>
                                match (this.trustConfiguration) {
                                    case Some(cfg) =>
                                        let issuerUrl = match (openId4VciConfiguration.credentialIssuerURL) {
                                            case Some(u) => u
                                            case None =>
                                                throw WalletError.withDescription(
                                                    "credentialIssuerURL must be a valid URL to verify SD-JWT credentials"
                                                )
                                        }
                                        applySdJwtIssuerTrust(
                                            cfg,
                                            String.fromUtf8(credData),
                                            issuerUrl,
                                            docType
                                        )
                                    case None => ()
                                }
                        }
                        // Persist SecureArea name / batch metadata only. Do not
                        // write proofKeyDers — presentation must sign via HUKS.
                        let perDocKeyInfo: ?Array<UInt8> = keyInfoBytes
                        let doc = Document(
                            docType,
                            storageFormat,
                            credData,
                            perDocKeyInfo,
                            Some(issuedMeta),
                            None,
                            DocumentStatus.Issued
                        )
                        docList.add(doc)
                        bi++
                    }
                    let primaryDoc = docList[0]
                    primaryDoc.id = issued.id
                    if (batchSize > 1) {
                        let batchArr = ArrayList<Document>()
                        var bj: Int64 = 1
                        while (bj < batchSize) {
                            batchArr.add(docList[bj])
                            bj++
                        }
                        batchDocs = Some(batchArr.toArray())
                    }
                    Hilog.info(0, "VCI-DEBUG", "saveDocument begin id=${primaryDoc.id} batch=${batchSize}")
                    storageManager.storageService.saveDocument(primaryDoc, batchDocs, false)
                    Hilog.info(0, "VCI-DEBUG", "saveDocument done id=${primaryDoc.id}")
                }

            case IssuanceOutcome.Deferred(deferredModel, config, _) =>
                Hilog.info(0, "OpenId4VciService",
                    "endIssueDocument(Deferred) id=" + issued.id)
                let docType = resolveDocType(config)
                let storageFormat = docDataFormatToStorage(config.format)
                let keyInfoBytes = buildDocKeyInfoBytes(issued)

                // iOS parity (OpenId4VciService L929-933): the deferred model is
                // saved in Document.data (dataToSave = encode(deferredIssuanceModel))
                // while Document.metadata carries the FULL DocMetadata
                // (cc.convertToDocMetadata) so the Documents list renders the real
                // name / issuer / logo on the pending row. Storing the deferred
                // blob in metadata (previous layout) made the UI show
                // "Unknown" + an empty title.
                let deferredBytes = encodeDeferredMetadata(deferredModel)
                let doc = Document(
                    docType,
                    storageFormat,
                    deferredBytes,
                    keyInfoBytes,
                    Some(encodeIssuedMetadata(config)),
                    None,
                    DocumentStatus.Deferred
                )
                doc.id = issued.id
                storageManager.storageService.saveDocument(doc, None, false)
                storageManager.appendRawDocument(doc)

            case IssuanceOutcome.Pending(pendingModel) =>
                Hilog.info(0, "OpenId4VciService",
                    "endIssueDocument(Pending) id=" + issued.id)
                let config = pendingModel.configuration
                let docType = resolveDocType(config)
                let storageFormat = docDataFormatToStorage(config.format)
                let keyInfoBytes = buildDocKeyInfoBytes(issued)
                // iOS parity (L934-938): pending model → data; metadata carries
                // DocMetadata + pending_reason_url (combined blob, see
                // encodePendingCombinedMetadata).
                let pendingBytes = encodePendingMetadata(pendingModel)
                let doc = Document(
                    docType,
                    storageFormat,
                    pendingBytes,
                    keyInfoBytes,
                    Some(encodePendingCombinedMetadata(pendingModel, config)),
                    None,
                    DocumentStatus.Pending
                )
                doc.id = issued.id
                storageManager.storageService.saveDocument(doc, None, false)
                storageManager.appendRawDocument(doc)
        }
    }

    // -----------------------------------------------------------------------
    // issueDocuments
    // iOS: func issueDocuments(docTypeIdentifiers: [DocTypeIdentifier],
    //          credentialOptions: CredentialOptions, keyOptions: KeyOptions?,
    //          promptMessage: String?) async throws -> [WalletStorage.Document]
    // -----------------------------------------------------------------------

    /**
     * Issue documents for the given docTypeIdentifiers via an authorization code flow
     * or pre-authorized code flow (depending on the credential offer grants).
     *
     * This method:
     *   1. Resolves the configured issuer's credential offer (using credentialIssuerURL).
     *   2. Prepares authorization.
     *   3. Creates key batches for each requested credential type.
     *   4. Sends credential requests with PoP proofs.
     *   5. Saves results via endIssueDocument.
     *   6. Returns the saved Document objects.
     *
     * Mirrors iOS OpenId4VciService.issueDocuments(docTypeIdentifiers:credentialOptions:
     *   keyOptions:promptMessage:).
     *
     * @param docTypeIdentifiers  One or more credential type identifiers to issue.
     * @param credentialOptions   Key batch policy + size.
     * @param keyOptions          Optional curve / access-control overrides.
     * @param promptMessage       User-facing prompt (passed through; not used in Cangjie HAR).
     * @return Array of issued (or deferred/pending) Documents.
     * @throws WalletError if issuance fails at any stage.
     */
    public func issueDocuments(
        docTypeIdentifiers: Array<DocTypeIdentifier>,
        credentialOptions: CredentialOptions,
        keyOptions: ?KeyOptions,
        promptMessage: ?String,
        issuerState!: ?String = None
    ): Array<Document> {
        if (docTypeIdentifiers.isEmpty()) {
            return []
        }

        let issuerUrl = match (openId4VciConfiguration.credentialIssuerURL) {
            case Some(u) => u
            case None =>
                throw WalletError.withDescription("credentialIssuerURL is not configured")
        }

        // Resolve issuer metadata (cached)
        let issuerMetadata = getIssuerMetadata()

        // Collect configuration identifiers for requested docTypes
        let requestedConfigIds = resolveConfigurationIds(docTypeIdentifiers, issuerMetadata)
        if (requestedConfigIds.isEmpty()) {
            throw WalletError.withDescription(
                "None of the requested credential types are available at issuer " + issuerUrl
            )
        }

        // Enforce the issuer WRPRC (registration certificate) policy when
        // enabled — issuance REFUSES on a bad/absent registration (iOS
        // IssuanceAuthorizer during authorization).
        let requestedConfigIdStrings = ArrayList<String>()
        for (cid in requestedConfigIds) {
            requestedConfigIdStrings.add(cid.value)
        }
        enforceIssuerRegistration(issuerMetadata, requestedConfigIdStrings.toArray())

        // issueDocuments() targets the configured issuer URL without a credential
        // offer carrying a pre-authorized code, so the only valid grant is the
        // authorization_code (browser) flow.  Mirrors iOS issueDocuments →
        // buildCredentialOffer(grants: nil) → authorizeRequestWithAuthCodeUseCase,
        // which (lacking a native ASWebAuthenticationSession here) yields a
        // .pending(PendingIssuanceModel) document the caller opens in a browser.
        // The pre-authorized code flow (an offer carrying a pre-auth grant + PIN)
        // is the responsibility of the offer-based path, not issueDocuments.
        return prepareAuthorizationCodeIssuance(
            issuerMetadata,
            requestedConfigIds,
            credentialOptions,
            keyOptions,
            issuerState
        )
    }


    // -----------------------------------------------------------------------
    // issuePreAuthorized — pre-authorized_code grant flow (no browser step)
    // iOS: issueDocumentsByOfferUrl -> authorizeRequestWithPreAuthCodeUseCase
    // -----------------------------------------------------------------------

    /**
     * Issue every requested configuration of a pre-authorized offer in one
     * token exchange (grant_type pre-authorized_code, optional tx_code typed by
     * the user). Mirrors the resume path's per-config loop; returns the saved
     * Issued/Deferred documents.
     */
    public func issuePreAuthorized(
        offer: CredentialOffer,
        docTypes: Array<OfferedDocModel>,
        txCodeValue: ?String
    ): Array<Document> {
        let pac = match (offer.grants) {
            case Some(Grants.PreAuthCode(p)) => p
            case Some(Grants.Both(_, p)) => p
            case _ => throw WalletError.withDescription("Offer carries no pre-authorized grant")
        }
        let preCode = match (pac.preAuthorizedCode) {
            case Some(c) => c
            case None => throw WalletError.withDescription("Pre-authorized grant has no code")
        }

        let issuerMetadata = offer.credentialIssuerMetadata

        // Enforce the issuer WRPRC policy for the configurations actually
        // being issued — pre-authorized flow (iOS IssuanceAuthorizer).
        let preAuthConfigIds = ArrayList<String>()
        for (dt in docTypes) {
            preAuthConfigIds.add(dt.credentialConfigurationIdentifier)
        }
        enforceIssuerRegistration(issuerMetadata, preAuthConfigIds.toArray())

        let asMetadata = resolveAuthServerMetadata(issuerMetadata)
        let issuerUrl = match (openId4VciConfiguration.credentialIssuerURL) {
            case Some(u) => u
            case None => issuerMetadata.credentialIssuerIdentifier.url
        }
        let vciConfig = buildOpenId4VCIConfig()
        let dpopConstructor = buildDPoPConstructor(issuerUrl)
        let issuer = Issuer(asMetadata, issuerMetadata, vciConfig, dpopConstructor, clientAttestation: buildClientAttestation())

        Hilog.info(0, "VCI-DEBUG", "preauth authorize codeLen=${preCode.size} txCode=${(txCodeValue ?? "").size}")
        let authorizedRequest = issuer.authorizeWithPreAuthorizationCode(
            offer,
            preCode,
            txCodeValue,
            AuthorizationDetailsInTokenRequest.DoNotInclude
        )

        // Per-config issue, mirroring resumePendingIssuance's combined loop.
        let createdDocIds = ArrayList<String>()
        for (dt in docTypes) {
            let docId = "doc-" + Base64Url.encode(Rng.bytes(12))
            let resolvedOptions = resolveCredentialOptionsForConfig(
                issuerMetadata, dt.credentialConfigurationIdentifier, dt.credentialOptions
            )
            beginIssueDocument(docId, resolvedOptions, dt.keyOptions, false)
            issueOneConfigFromAuthorized(
                issuer, authorizedRequest, issuerMetadata,
                dt.credentialConfigurationIdentifier, docId,
                resolvedOptions, dt.keyOptions
            )
            createdDocIds.add(docId)
        }

        let results = ArrayList<Document>()
        for (docId in createdDocIds) {
            match (storageManager.storageService.loadDocument(docId, DocumentStatus.Issued)) {
                case Some(doc) => results.add(doc)
                case None =>
                    match (storageManager.storageService.loadDocument(docId, DocumentStatus.Deferred)) {
                        case Some(doc) => results.add(doc)
                        case None =>
                            Hilog.warn(0, "OpenId4VciService",
                                "issuePreAuthorized: missing saved document id=" + docId)
                    }
            }
        }
        if (results.size == 0) {
            throw WalletError.withDescription("issuePreAuthorized: no document was saved")
        }
        return results.toArray()
    }

    // -----------------------------------------------------------------------
    // prepareAuthorizationCodeIssuance
    // iOS: issueDocumentByOfferUrl → .presentation_request(url) branch returning
    //      .pending(PendingIssuanceModel(pendingReason: .presentation_request_url(url), …))
    // -----------------------------------------------------------------------

    /**
     * Prepare authorization-code (browser) issuance for the given credential
     * configurations.
     *
     * For each requested configuration this:
     *   1. Runs the OpenID4VCI authorization request (PAR when required, else a
     *      plain authorization GET URL) via Issuer.prepareAuthorizationRequest,
     *      yielding the https authorizationCodeURL the user must open in a
     *      browser, the PKCE verifier, and the OAuth state.
     *   2. Creates the device key batch in the SecureArea (beginIssueDocument).
     *   3. Persists a Pending Document whose metadata carries the auth URL, PKCE
     *      verifier/method, state and the real configuration identifier.
     *
     * The caller opens the auth URL, lets the user log in, and feeds the redirect
     * URL back to resumePendingIssuance to finish the issuance.
     *
     * @return Array of Pending Documents (one per requested configuration).
     */
    private func prepareAuthorizationCodeIssuance(
        issuerMetadata: CredentialIssuerMetadata,
        requestedConfigIds: Array<CredentialConfigurationIdentifier>,
        credentialOptions: CredentialOptions,
        keyOptions: ?KeyOptions,
        issuerState: ?String
    ): Array<Document> {
        let asMetadata = resolveAuthServerMetadata(issuerMetadata)
        let issuerUrl = match (openId4VciConfiguration.credentialIssuerURL) {
            case Some(u) => u
            case None => issuerMetadata.credentialIssuerIdentifier.url
        }
        let vciConfig = buildOpenId4VCIConfig()
        // iOS configures PAR with authorization-code DPoP binding.  The issuer
        // rejects the browser session after a successful PAR when this proof is
        // absent, so this flow must construct the same DPoP-enabled issuer as
        // the pre-authorized and resume flows.
        let dpopConstructor = buildDPoPConstructor(issuerUrl)
        let issuer = Issuer(asMetadata, issuerMetadata, vciConfig, dpopConstructor, clientAttestation: buildClientAttestation())

        // iOS parity ("PID Combination of all available formats"): request EVERY
        // configuration in ONE authorization (authorization_details carries all
        // credential_configuration_ids), so the issuer only offers providers that
        // can issue all requested formats (e.g. FormEU/nodeEU/Portugal) instead of
        // the full single-config country list. One browser authorization yields one
        // pending document that resumePendingIssuance expands into one credential
        // per requested config.
        // Offer-based flow (issueDocumentsByOfferUrl) threads the offer's
        // issuer_state through so the PAR carries it — the issuer's dynamic
        // authorization ties the browser session back to the offer with it;
        // without it the prod issuer's verify_user step dies with KeyError
        // ('code'). Scoped issueDocuments() passes None (no offer, no state).
        let grants: Option<Grants> = match (issuerState) {
            case Some(s) => Option<Grants>.Some(
                Grants.AuthCode(AuthorizationCode(Option<String>.Some(s), Option<String>.None)))
            case None => Option<Grants>.None
        }
        let offer = CredentialOffer(
            issuerMetadata.credentialIssuerIdentifier,
            issuerMetadata,
            requestedConfigIds,
            grants
        )

        let authRequested = issuer.prepareAuthorizationRequest(offer)
        let authUrl = authRequested.authorizationCodeURL.url
        let pkceVerifier = authRequested.pkceVerifier.codeVerifier
        let pkceMethod = authRequested.pkceVerifier.codeChallengeMethod
        let state = authRequested.state

        let allConfigIdStrs = ArrayList<String>()
        for (c in requestedConfigIds) {
            allConfigIdStrs.add(c.value)
        }
        Hilog.info(0, "OpenId4VciService",
            "prepareAuthorizationCodeIssuance combined configs=" + allConfigIdStrs.size.toString() +
            " state=" + state + " authUrlLen=" + authUrl.size.toString())

        // One device key batch + one pending document; the full config list rides
        // in PendingIssuanceModel.configIds so resume issues each format.
        let newId = "doc-" + Base64Url.encode(Rng.bytes(12))
        let primaryOptions = resolveCredentialOptionsForConfig(
            issuerMetadata, requestedConfigIds[0].value, credentialOptions
        )
        let req = beginIssueDocument(newId, primaryOptions, keyOptions, false)
        let config = buildCredentialConfigForConfigId(requestedConfigIds[0], issuerMetadata)

        // The PAR above sent dpop_jkt for the key buildDPoPConstructor just
        // created; the resume after the browser redirect must prove the token
        // request with that same key, so its id rides in the pending document.
        let pendingDpopKeyId: String = match (this.activeDPoPKeyId) {
            case Some(id) => id
            case None => ""
        }
        let pendingModel = PendingIssuanceModel(
            PendingReason.PresentationRequestUrl(authUrl),
            config,
            req.id,
            pkceVerifier,
            pkceMethod,
            state,
            configIds: allConfigIdStrs.toArray(),
            dpopKeyId: pendingDpopKeyId
        )

        endIssueDocument(req, IssuanceOutcome.Pending(pendingModel))

        let resultDocs = ArrayList<Document>()
        let pendingDoc = storageManager.storageService.loadDocument(req.id, DocumentStatus.Pending)
        match (pendingDoc) {
            case Some(p) => resultDocs.add(p)
            case None =>
                throw WalletError.withDescription(
                    "prepareAuthorizationCodeIssuance: pending document not persisted id=" + req.id
                )
        }

        return resultDocs.toArray()
    }

    // -----------------------------------------------------------------------
    // requestDeferredIssuance
    // iOS: func requestDeferredIssuance(deferredDoc: WalletStorage.Document,
    //          credentialOptions: CredentialOptions, keyOptions: KeyOptions?)
    //          async throws -> WalletStorage.Document
    // -----------------------------------------------------------------------

    /**
     * Poll a deferred credential endpoint to retrieve a previously deferred credential.
     *
     * Mirrors iOS OpenId4VciService.requestDeferredIssuance(deferredDoc:credentialOptions:keyOptions:).
     *
     * @param deferredDoc     The Document with DocumentStatus.Deferred status.
     * @param credentialOptions Key batch policy (used if new keys needed).
     * @param keyOptions      Optional key overrides.
     * @return The updated Document (now Issued, or still Deferred if still pending).
     * @throws WalletError if metadata decoding or credential retrieval fails.
     */
    public func requestDeferredIssuance(
        deferredDoc: Document,
        credentialOptions: CredentialOptions,
        keyOptions: ?KeyOptions
    ): Document {
        // Decode deferred metadata from the document
        let deferredModel = decodeDeferredMetadata(deferredDoc)

        // Resolve issuer metadata (to get the authorization server)
        let issuerUrl = match (openId4VciConfiguration.credentialIssuerURL) {
            case Some(u) => u
            case None =>
                throw WalletError.withDescription("credentialIssuerURL is not configured")
        }

        let issuerMetadata = getIssuerMetadata()
        let asMetadata = resolveAuthServerMetadata(issuerMetadata)
        let vciConfig = buildOpenId4VCIConfig()
        // The deferred poll must present DPoP proofs with the SAME key the
        // access token was bound to — rebuild it from the persisted DER
        // (a fresh key would make the issuer reject the token binding).
        let dpopConstructor = if (!deferredModel.dpopKeyId.isEmpty()) {
            dpopConstructorFromKeyId(deferredModel.dpopKeyId)
        } else {
            dpopConstructorFromDer(deferredModel.dpopKeyDer)
        }
        let issuer = Issuer(asMetadata, issuerMetadata, vciConfig, dpopConstructor, clientAttestation: buildClientAttestation())

        // Rebuild the original session's authorization from the deferred model.
        var authorizedRequest = buildAuthorizedRequestForDeferred(deferredModel)
        let clientId = openId4VciConfiguration.clientId

        // iOS refreshAuthorization: refresh proactively when the access token
        // has expired (30s clock skew), then retry once with a forced refresh
        // on an auth failure (iOS deferredAction(true) on 4xx).
        let now = Float64(DateTime.nowUTC().toUnixTimeStamp().toSeconds())
        let tokenExpired = deferredModel.expiresIn > 0.0 &&
            now >= deferredModel.timeStamp + deferredModel.expiresIn - 30.0
        if (tokenExpired) {
            Hilog.info(0, "OpenId4VciService",
                "requestDeferredIssuance: access token expired, refreshing id=" + deferredDoc.id)
            authorizedRequest = issuer.refresh(clientId, authorizedRequest, Option<Nonce>.None)
        }

        let txId = deferredModel.transactionId
        var response: DeferredCredentialIssuanceResponse
        try {
            response = issuer.requestDeferredCredential(
                authorizedRequest,
                txId,
                Option<Nonce>.None
            )
        } catch (e: Exception) {
            Hilog.info(0, "OpenId4VciService",
                "requestDeferredIssuance: first attempt failed (" + e.message +
                "), retrying with refreshed token id=" + deferredDoc.id)
            authorizedRequest = issuer.refresh(clientId, authorizedRequest, Option<Nonce>.None)
            response = issuer.requestDeferredCredential(
                authorizedRequest,
                txId,
                Option<Nonce>.None
            )
        }

        match (response) {
            case DeferredCredentialIssuanceResponse.Issued(credentials) =>
                // Convert credential bytes and update storage. Carry the
                // DocMetadata blob over so the now-issued document keeps its
                // real display name / issuer / logo (iOS keeps docMetadata).
                // A batch deferred response carries one credential per original
                // proof (iOS handleCredentialResponse fans the array out the
                // same way): first entry becomes the primary document, the rest
                // are stored as CREDENTIALS batch rows — so the usage badge
                // shows the full batch (30/30) instead of 1/30.
                let updatedDoc = Document(
                    deferredDoc.docType,
                    deferredDoc.docDataFormat,
                    credentialToBytes(credentials[0]),
                    deferredDoc.docKeyInfo,
                    deferredDoc.metadata,
                    deferredDoc.displayName,
                    DocumentStatus.Issued
                )
                updatedDoc.id = deferredDoc.id
                var batchDocs: ?Array<Document> = None
                if (credentials.size > 1) {
                    let batchArr = ArrayList<Document>()
                    var bi: Int64 = 1
                    while (bi < credentials.size) {
                        batchArr.add(Document(
                            deferredDoc.docType,
                            deferredDoc.docDataFormat,
                            credentialToBytes(credentials[bi]),
                            deferredDoc.docKeyInfo,
                            deferredDoc.metadata,
                            deferredDoc.displayName,
                            DocumentStatus.Issued
                        ))
                        bi++
                    }
                    batchDocs = Some(batchArr.toArray())
                }
                storageManager.storageService.deleteDocument(deferredDoc.id, DocumentStatus.Deferred)
                storageManager.storageService.saveDocument(updatedDoc, batchDocs, false)
                Hilog.info(0, "OpenId4VciService",
                    "requestDeferredIssuance: credential issued id=" + deferredDoc.id +
                    " count=" + credentials.size.toString())
                return updatedDoc

            case DeferredCredentialIssuanceResponse.IssuancePending(newTxId, _) =>
                // Persist the new transaction id + the (possibly refreshed)
                // authorization back into Document.data; DocMetadata stays in
                // Document.metadata untouched (display name / issuer / logo).
                let pendingUpdated = persistDeferredState(
                    deferredDoc, deferredModel, newTxId, authorizedRequest)
                Hilog.info(0, "OpenId4VciService",
                    "requestDeferredIssuance: still deferred id=" + deferredDoc.id)
                return pendingUpdated

            case DeferredCredentialIssuanceResponse.IssuanceStillPending(_) =>
                // No new transaction id, but the token may have been refreshed —
                // persist it so the next poll round doesn't reuse a stale token.
                let stillUpdated = persistDeferredState(
                    deferredDoc, deferredModel, deferredModel.transactionId, authorizedRequest)
                Hilog.info(0, "OpenId4VciService",
                    "requestDeferredIssuance: still pending id=" + deferredDoc.id)
                return stillUpdated

            case DeferredCredentialIssuanceResponse.Errored(errorOpt, descOpt) =>
                let errStr: String = match (errorOpt) { case Some(s) => s; case None => "unknown" }
                let descStr: String = match (descOpt) { case Some(s) => s; case None => "" }
                let msg = errStr + ": " + descStr
                throw WalletError.withDescription("Deferred issuance failed: " + msg)
        }
    }

    // -----------------------------------------------------------------------
    // resumePendingIssuance
    // iOS: func resumePendingIssuance(pendingDoc: WalletStorage.Document,
    //          webUrl: URL, credentialOptions: CredentialOptions,
    //          keyOptions: KeyOptions?) async throws -> WalletStorage.Document
    // -----------------------------------------------------------------------

    /**
     * Resume a pending issuance after the user completes an OAuth browser redirect.
     *
     * The pending document was saved when the issuer returned a presentation_request
     * redirect URL (AsWebOutcome.PresentationRequest case).  After the user completes
     * the browser flow, the caller provides the redirect URL containing the
     * authorization code.
     *
     * Mirrors iOS OpenId4VciService.resumePendingIssuance(pendingDoc:webUrl:
     *   credentialOptions:keyOptions:).
     *
     * @param pendingDoc      The Document with DocumentStatus.Pending status.
     * @param webUrl          The redirect URL received from the OAuth browser session.
     * @param credentialOptions Key batch policy.
     * @param keyOptions      Optional key overrides.
     * @return All updated Documents (Issued or Deferred), one per authorized
     *         config — combined issuance ("PID Combined") resumes several
     *         credentials from the one authorization; single-config resumes
     *         return a one-element array. The primary (pending-doc-id) document
     *         is always first.
     * @throws WalletError if resume fails.
     */
    public func resumePendingIssuance(
        pendingDoc: Document,
        webUrl: String,
        credentialOptions: CredentialOptions,
        keyOptions: ?KeyOptions
    ): Array<Document> {
        let pendingModel = decodePendingMetadata(pendingDoc)

        let issuerUrl = match (openId4VciConfiguration.credentialIssuerURL) {
            case Some(u) => u
            case None =>
                throw WalletError.withDescription("credentialIssuerURL is not configured")
        }

        let issuerMetadata = getIssuerMetadata()
        let asMetadata = resolveAuthServerMetadata(issuerMetadata)
        let vciConfig = buildOpenId4VCIConfig()
        // The PAR bound this authorization to the DPoP key thumbprint
        // (dpop_jkt); the token request must be proven with that same key or
        // the AS answers "DPoP Proof public key thumbprint does not match
        // dpop_jkt". Rebuild it from the pending document; only documents
        // stored before the key id was persisted fall back to a fresh key.
        let dpopConstructor = if (!pendingModel.dpopKeyId.isEmpty() && openId4VciConfiguration.requireDpop) {
            this.activeDPoPKeyId = Some(pendingModel.dpopKeyId)
            Hilog.info(0, "OpenId4VciService", "resume reuses DPoP key id=" + pendingModel.dpopKeyId)
            dpopConstructorFromKeyId(pendingModel.dpopKeyId)
        } else {
            buildDPoPConstructor(issuerUrl)
        }
        let issuer = Issuer(asMetadata, issuerMetadata, vciConfig, dpopConstructor, clientAttestation: buildClientAttestation())

        // Extract authorization code from the redirect URL
        let authCode = extractAuthCode(webUrl)
        let state = extractState(webUrl)
        Hilog.info(0, "VCI-DEBUG", "resume authCodeLen=${authCode.size} stateMatches=${state == pendingModel.state}")
        if (authCode.isEmpty()) {
            let errParam = extractQueryParam(webUrl, "error")
            let errDesc = extractQueryParam(webUrl, "error_description")
            throw WalletError.withDescription("Authorization did not return a code (error=${errParam}: ${errDesc})")
        }

        // Reconstruct AuthorizationRequested from the pending model.
        // The AuthorizationCodeURL it carries must be the original https authorization
        // URL (stored in the pending metadata), NOT the redirect webUrl: the redirect
        // uses a custom scheme (e.g. eu.europa.ec.euidi://) which AuthorizationCodeURL
        // rejects (https-only). authorizeWithAuthorizationCode only consumes the PKCE
        // verifier, state, dpopNonce and configurationIds — never the URL itself.
        let authRequested = buildAuthorizationRequestedFromPending(pendingModel)

        // Authorize with the returned code
        let authorizedRequest = issuer.authorizeWithAuthorizationCode(
            state,
            authRequested,
            authCode,
            AuthorizationDetailsInTokenRequest.DoNotInclude,
            Option<Grants>.None
        )

        // Combined issuance (iOS "PID Combined"): issue EVERY authorized config
        // from this single authorization. The primary config reuses the pending
        // document id (whose HUKS key batch was created at prepare time); each extra
        // config gets a fresh document id + key batch. Proof JWTs are signed by
        // that batch via SecureAreaSigner — private keys stay in HUKS.
        let configIds = pendingModel.allConfigIds()
        // Delete the pending document first (its id is reused for the primary config).
        storageManager.storageService.deleteDocument(pendingDoc.id, DocumentStatus.Pending)
        let createdDocIds = ArrayList<String>()
        var idx: Int64 = 0
        for (cidStr in configIds) {
            let resolvedOptions = resolveCredentialOptionsForConfig(issuerMetadata, cidStr, credentialOptions)
            let docId: String = if (idx == 0) {
                pendingDoc.id
            } else {
                let nid = "doc-" + Base64Url.encode(Rng.bytes(12))
                beginIssueDocument(nid, resolvedOptions, keyOptions, false)
                nid
            }
            issueOneConfigFromAuthorized(
                issuer, authorizedRequest, issuerMetadata,
                cidStr, docId, resolvedOptions, keyOptions
            )
            createdDocIds.add(docId)
            idx++
        }

        // Collect every resulting document (Issued preferred, else Deferred) so
        // callers see the full combined-issuance outcome, mirroring the array
        // iOS issueDocuments returns. The primary document must exist.
        let results = ArrayList<Document>()
        for (docId in createdDocIds) {
            match (storageManager.storageService.loadDocument(docId, DocumentStatus.Issued)) {
                case Some(doc) => results.add(doc)
                case None =>
                    match (storageManager.storageService.loadDocument(docId, DocumentStatus.Deferred)) {
                        case Some(doc) => results.add(doc)
                        case None =>
                            Hilog.warn(0, "OpenId4VciService",
                                "resumePendingIssuance: missing saved document id=" + docId)
                    }
            }
        }
        if (results.size == 0) {
            throw WalletError.withDescription(
                "resumePendingIssuance: could not find saved document id=" + pendingDoc.id
            )
        }
        return results.toArray()
    }

    // -----------------------------------------------------------------------
    // issueOneConfigFromAuthorized — request + persist one credential config
    // from an already-authorized request. Shared by resumePendingIssuance for
    // each config in a combined (iOS "PID Combined") authorization; the device
    // key batch for `docId` must already exist (prepare/beginIssueDocument).
    // -----------------------------------------------------------------------
    private func issueOneConfigFromAuthorized(
        issuer: Issuer,
        authorizedRequest: AuthorizedRequest,
        issuerMetadata: CredentialIssuerMetadata,
        configIdStr: String,
        docId: String,
        credentialOptions: CredentialOptions,
        keyOptions: ?KeyOptions
    ): Unit {
        let configId = CredentialConfigurationIdentifier(configIdStr)
        let saName: ?String = match (keyOptions) {
            case Some(ko) => ko.secureAreaName
            case None => None
        }
        let secureArea = SecureAreaRegistry.shared.get(saName)
        let batchInfo = secureArea.getKeyBatchInfo(docId)
        // Proof type selection mirrors iOS OpenId4VciService.initSecurityKeys:
        //   1. `attestation` proof type with key_attestations_required → ONE
        //      attestation proof for the whole batch (the key attestation JWT
        //      already attests every key; no per-key proof JWT is signed);
        //   2. else `jwt` proof type with key_attestations_required → per-key
        //      JWT proofs carrying the key attestation in their header;
        //   3. else plain per-key JWT proofs with an inline jwk.
        let supportsAttestationProofType = proofTypeRequiresKeyAttestation(issuerMetadata, configId, "attestation")
        let supportsJwtProofTypeWithAttestation = proofTypeRequiresKeyAttestation(issuerMetadata, configId, "jwt")
        var attProvider: ?WalletAttestationsProvider = None
        match (openId4VciConfiguration.keyAttestationsConfig) {
            case Some(kac) => attProvider = kac.walletAttestationsProvider
            case None => ()
        }

        let batchKeys = ArrayList<BindingKey>()
        let n = batchInfo.batchSize()
        if (supportsAttestationProofType && !attProvider.isNone()) {
            let provider = attProvider.getOrThrow()
            let allPubs = ArrayList<Array<UInt8>>()
            var pi: Int64 = 0
            while (pi < n) {
                allPubs.add(secureArea.getPublicKeyBytes(docId, pi, batchInfo.crv))
                pi++
            }
            let pubs = allPubs.toArray()
            batchKeys.add(BindingKey.Attestation(
                { nonce: Option<String> => provider.getKeysAttestation(pubs, nonce) }
            ))
            Hilog.info(0, "OpenId4VciService",
                "proof type=attestation config=" + configId.value + " keys=" + n.toString())
        } else {
            var ki: Int64 = 0
            while (ki < n) {
                let index = ki
                let pub = secureArea.getPublicKeyBytes(docId, index, batchInfo.crv)
                let signer = SecureAreaSigner(
                    secureArea,
                    docId,
                    index,
                    batchInfo.crv,
                    SigningAlgorithm.ES256,
                    None
                )
                if (supportsJwtProofTypeWithAttestation && !attProvider.isNone()) {
                    let provider = attProvider.getOrThrow()
                    batchKeys.add(BindingKey.JwtCallbackAttestation(
                        pub,
                        "ES256",
                        { data: Array<UInt8> => signer.sign(data) },
                        { nonce: Option<String> => provider.getKeysAttestation([pub], nonce) }
                    ))
                } else {
                    batchKeys.add(BindingKey.JwtCallback(
                        pub,
                        "ES256",
                        { data: Array<UInt8> => signer.sign(data) }
                    ))
                }
                ki++
            }
            Hilog.info(0, "OpenId4VciService",
                "proof type=jwt keyAttestation=" + (supportsJwtProofTypeWithAttestation && !attProvider.isNone()).toString() +
                " config=" + configId.value + " keys=" + n.toString())
        }
        Hilog.info(0, "OpenId4VciService",
            "issueOneConfigFromAuthorized id=" + docId +
            " batchSize=" + n.toString() + " via SecureArea")

        let payload = IssuanceRequestPayload.ConfigurationBased(configId)
        let submitted = issuer.requestCredential(
            authorizedRequest,
            batchKeys.toArray(),
            payload
        )

        let req = IssueRequest(docId, saName, credentialOptions, keyOptions, this.activeDPoPKeyId)
        let outcome = processSubmittedRequestWithProofKeys(
            submitted, req, issuerMetadata, authorizedRequest,
            configId: configId
        )
        endIssueDocument(req, outcome)
    }

    // -----------------------------------------------------------------------
    // Private helpers — authorization
    // -----------------------------------------------------------------------

    /**
     * Build an OpenId4VCIConfig from the wallet's OpenId4VciConfiguration.
     *
     * Mirrors iOS OpenId4VciConfiguration.toOpenId4VCIConfig().
     */
    private func buildOpenId4VCIConfig(): OpenId4VCIConfig {
        let clientId = openId4VciConfiguration.clientId
        let client = Client(ClientKind.Public(clientId))
        let requirePAR: ParUsage = if (openId4VciConfiguration.requirePAR) {
            ParUsage.Required(false)
        } else {
            ParUsage.Never
        }
        return OpenId4VCIConfig(
            client,
            openId4VciConfiguration.authFlowRedirectionURI,
            openId4VciConfiguration.authorizeIssuanceConfig,
            requirePAR,
            openId4VciConfiguration.issuerMetadataPolicy,
            openId4VciConfiguration.requireDpop
        )
    }

    /**
     * Build an optional DPoP constructor if requireDpop is true.
     * Returns None if DPoP is disabled or key material is unavailable.
     *
     * NOTE: In a full implementation, the DPoP key would be created in SecureArea
     * using dpopKeyOptions.  Here we return None (DPoP is handled by the Issuer
     * internally when dpopConstructor is provided).
     */
    /**
     * Build the OAuth attestation-based client authentication material
     * (`attest_jwt_client_auth`), mirroring iOS: a wallet-held key is attested by
     * the wallet-provider, and every PAR / token request carries the attestation
     * plus a PoP signed by that key. When the AS authenticates the client as
     * `public` instead, the access token it mints omits `client_status` and the
     * credential endpoint rejects the later issuance request.
     *
     * The PoP key lives in HUKS (iOS: Secure Enclave via `popKeyOptions`).
     * Returns None when no attestation provider is configured, or when the
     * provider cannot supply an attestation — the flow then degrades to the
     * previous `public` client auth rather than failing outright.
     */
    private func buildClientAttestation(): Option<ClientAttestationType> {
        var attProvider: ?WalletAttestationsProvider = None
        match (openId4VciConfiguration.keyAttestationsConfig) {
            case Some(kac) => attProvider = kac.walletAttestationsProvider
            case None => ()
        }
        if (attProvider.isNone()) {
            return Option<ClientAttestationType>.None
        }
        let clientId = openId4VciConfiguration.clientId
        if (clientId.isEmpty()) {
            return Option<ClientAttestationType>.None
        }
        try {
            // Fresh HUKS key per flow: the attestation binds the public JWK, and
            // each Issuer authenticates independently. Private key never leaves TEE.
            let keyId = "cattest-" + Base64Url.encode(Rng.bytes(12))
            let secureArea = SecureAreaRegistry.shared.get(Some("HUKS"))
            let credOpts = CredentialOptions(CredentialPolicy.RotateUse, 1)
            let keyOpts = KeyOptions.defaults()
            keyOpts.secureAreaName = Some("HUKS")
            secureArea.createKeyBatch(keyId, credOpts, Some(keyOpts))
            let pub = secureArea.getPublicKeyBytes(keyId, 0, CoseEcCurve.P256)
            let ecPub = EcPublicKey.fromHuksUncompressed(pub)
            let jwk = JsonObject()
            jwk.put("kty", JsonString("EC"))
            jwk.put("crv", JsonString(ecPub.crv.rawValue()))
            jwk.put("x", JsonString(ecPub.x))
            jwk.put("y", JsonString(ecPub.y))
            Hilog.info(0, "OpenId4VciService", "buildClientAttestation via SecureArea id=" + keyId)
            // The provider contract passes the public JWK JSON through this
            // parameter (iOS hands over a SigningKeyProxy wrapping the same JWK).
            // The wallet-provider intermittently answers 500; without an
            // attestation the client silently falls back to `public` auth and the
            // authorization server then rejects the PAR with a bare 401, which
            // reads like a wallet bug rather than a provider hiccup. Retry a few
            // times before giving up.
            var attestation = ""
            var attempt = 0
            while (attempt < 3) {
                attempt++
                try {
                    attestation = attProvider.getOrThrow().getWalletAttestation(jwk.toJsonString())
                    if (!attestation.isEmpty()) {
                        break
                    }
                } catch (e: Exception) {
                    Hilog.warn(0, "VCI-DEBUG",
                        "client-attestation attempt ${attempt} failed: ${e.message}")
                    if (attempt >= 3) {
                        throw e
                    }
                    sleep(Duration.millisecond * 400)
                }
            }
            if (attestation.isEmpty()) {
                return Option<ClientAttestationType>.None
            }
            let signer = SecureAreaSigner(
                secureArea,
                keyId,
                0,
                CoseEcCurve.P256,
                SigningAlgorithm.ES256,
                None
            )
            Hilog.info(0, "VCI-DEBUG", "client-attestation acquired len=${attestation.size} keyId=" + keyId)
            return Option<ClientAttestationType>.Some(
                ClientAttestationCallback(
                    attestation,
                    clientId,
                    "ES256",
                    jwk,
                    { data: Array<UInt8> => signer.sign(data) }
                )
            )
        } catch (e: Exception) {
            // Not recoverable here, but say so loudly: the request that follows
            // will be sent as a `public` client and an AS requiring
            // attest_jwt_client_auth answers 401 "Authentication failed.", which
            // otherwise looks like a client bug instead of an upstream outage.
            Hilog.error(0, "VCI-DEBUG",
                "client-attestation unavailable after retries (${e.message}) — " +
                "continuing as a public client; an AS requiring attest_jwt_client_auth will reject this")
            return Option<ClientAttestationType>.None
        }
    }

    /**
     * Mirrors iOS OpenId4VciService.validateCredentialOptions →
     * resolveCredentialOptions(batchCredentialIssuance:credentialReusePolicy:
     * userCredentialOptions:): the issuer's `credential_reuse_policy` for the
     * configuration decides the batch, and the caller's options are only a cap.
     *
     *   issuerBatch = selected policy batch_size ?? batch_credential_issuance ?? 1
     *   limited_time ⇒ 1 (a single instance used for a limited period)
     *   user batch > issuerBatch ⇒ clamped to issuerBatch
     *   issuer defines a policy ⇒ policy + batch taken from the issuer outright
     *
     * Applied before the key batch is created, so the SecureArea holds exactly
     * the keys the issuer will bind credentials to (a 60-key batch against a
     * once_only/7 issuer used to yield 7 credentials, 53 dead keys and a 7/60
     * counter).
     */
    private func resolveCredentialOptionsForConfig(
        issuerMetadata: CredentialIssuerMetadata,
        configId: String,
        userOptions: CredentialOptions
    ): CredentialOptions {
        let issuerPolicy: Option<CredentialReusePolicy> = match (issuerMetadata.credentialConfigurationsRaw.get(configId)) {
            case Some(rawCfg) => parseCredentialReusePolicy(rawCfg)
            case None => Option<CredentialReusePolicy>.None
        }
        let walletSupported = SupportedCredentialReusePolicies.Supported(
            [ReuseMethod.LimitedTime, ReuseMethod.OnceOnly, ReuseMethod.RotatingBatch]
        )
        let selected: Option<ReusePolicy> = try {
            CredentialReusePolicyValidator.selectMatchingPolicy(issuerPolicy, walletSupported)
        } catch (e: Exception) {
            Hilog.warn(0, "OpenId4VciService",
                "credential_reuse_policy for " + configId + " not usable (" + e.message + "); falling back to batch_credential_issuance")
            Option<ReusePolicy>.None
        }
        let metadataBatch: Option<Int64> = match (issuerMetadata.batchCredentialIssuance) {
            case Some(bci) => Option<Int64>.Some(bci.batchSize)
            case None => Option<Int64>.None
        }
        var issuerBatch: Int64 = match (CredentialReusePolicyValidator.determineBatchSize(selected, metadataBatch)) {
            case Some(bs) => bs
            case None => 1
        }
        var resolvedPolicy = CredentialPolicy.RotateUse
        match (selected) {
            case Some(ReusePolicy.LimitedTime(_)) => issuerBatch = 1
            case Some(ReusePolicy.OnceOnly(_, _)) => resolvedPolicy = CredentialPolicy.OneTimeUse
            case _ => ()
        }
        var policy = userOptions.credentialPolicy
        var batch = userOptions.batchSize
        if (batch > issuerBatch) {
            Hilog.info(0, "OpenId4VciService",
                "batch " + batch.toString() + " for " + configId + " exceeds issuer batch " + issuerBatch.toString() + "; using issuer batch")
            batch = issuerBatch
        }
        if (!selected.isNone()) {
            policy = resolvedPolicy
            batch = issuerBatch
        }
        return CredentialOptions(policy, batch)
    }

    /**
     * `credential_reuse_policy` lives at the top level of a credential
     * configuration in older drafts and under `credential_metadata` in
     * OID4VCI 1.0 (both reference issuers are in use); an unparsable policy
     * is treated as absent.
     */
    private func parseCredentialReusePolicy(rawCfg: JsonObject): Option<CredentialReusePolicy> {
        var policyObj: Option<JsonObject> = match (rawCfg.get("credential_reuse_policy")) {
            case Some(o: JsonObject) => Option<JsonObject>.Some(o)
            case _ => Option<JsonObject>.None
        }
        if (policyObj.isNone()) {
            match (rawCfg.get("credential_metadata")) {
                case Some(cm: JsonObject) =>
                    match (cm.get("credential_reuse_policy")) {
                        case Some(o: JsonObject) => policyObj = Option<JsonObject>.Some(o)
                        case _ => ()
                    }
                case _ => ()
            }
        }
        match (policyObj) {
            case Some(o) =>
                try {
                    Option<CredentialReusePolicy>.Some(CredentialReusePolicy.fromJson(o))
                } catch (e: Exception) {
                    Hilog.warn(0, "OpenId4VciService", "credential_reuse_policy decode failed: " + e.message)
                    Option<CredentialReusePolicy>.None
                }
            case None => Option<CredentialReusePolicy>.None
        }
    }

    /**
     * Mirrors iOS `supportsAttestationProofType` / `supportsJwtProofTypeWithAttestation`
     * (Extensions.swift): the proof type is listed under
     * proof_types_supported AND declares key_attestations_required.
     */
    private func proofTypeRequiresKeyAttestation(
        issuerMetadata: CredentialIssuerMetadata,
        configId: CredentialConfigurationIdentifier,
        proofType: String
    ): Bool {
        match (issuerMetadata.credentialConfigurationsRaw.get(configId.value)) {
            case Some(rawCfg) =>
                match (rawCfg.get("proof_types_supported")) {
                    case Some(ptsObj: JsonObject) =>
                        match (ptsObj.get(proofType)) {
                            case Some(ptObj: JsonObject) => !ptObj.get("key_attestations_required").isNone()
                            case _ => false
                        }
                    case _ => false
                }
            case None => false
        }
    }

    private func buildDPoPConstructor(issuerUrl: String): Option<DPoPConstructorType> {
        if (!openId4VciConfiguration.requireDpop) {
            return Option<DPoPConstructorType>.None
        }
        // HUKS-resident DPoP key (iOS Secure Enclave + dpopKeyId). A single Issuer
        // instance reuses this constructor across token + credential requests, so
        // the access token's cnf/jkt binding stays consistent within one flow.
        let keyId = "dpop-" + Base64Url.encode(Rng.bytes(12))
        let secureArea = SecureAreaRegistry.shared.get(Some("HUKS"))
        let credOpts = CredentialOptions(CredentialPolicy.RotateUse, 1)
        let keyOpts = KeyOptions.defaults()
        keyOpts.secureAreaName = Some("HUKS")
        secureArea.createKeyBatch(keyId, credOpts, Some(keyOpts))
        this.activeDPoPKeyId = Some(keyId)
        Hilog.info(0, "OpenId4VciService", "buildDPoPConstructor via SecureArea id=" + keyId)
        return dpopConstructorFromKeyId(keyId)
    }

    /** Rebuild a DPoP constructor from a persisted HUKS / SecureArea key id. */
    private func dpopConstructorFromKeyId(keyId: String): Option<DPoPConstructorType> {
        if (keyId.isEmpty()) {
            return Option<DPoPConstructorType>.None
        }
        let secureArea = SecureAreaRegistry.shared.get(Some("HUKS"))
        let pub = secureArea.getPublicKeyBytes(keyId, 0, CoseEcCurve.P256)
        let signer = SecureAreaSigner(
            secureArea,
            keyId,
            0,
            CoseEcCurve.P256,
            SigningAlgorithm.ES256,
            None
        )
        let ecPub = EcPublicKey.fromHuksUncompressed(pub)
        return Option<DPoPConstructorType>.Some(
            DPoPConstructorCallback("ES256", ecPub, { data: Array<UInt8> => signer.sign(data) })
        )
    }

    /** Rebuild a DPoP constructor from a persisted DER private key (legacy deferred poll). */
    private func dpopConstructorFromDer(der: Array<UInt8>): Option<DPoPConstructorType> {
        if (der.size == 0) {
            return Option<DPoPConstructorType>.None
        }
        let key = ECDSAPrivateKey.decodeDer(DerBlob(der))
        let pubPoint = EcdsaP256.publicKeyUncompressedOf(key)
        let ecPub = EcPublicKey.fromHuksUncompressed(pubPoint)
        return Option<DPoPConstructorType>.Some(DPoPConstructor("ES256", ecPub, key))
    }

    /**
     * Resolve the IdentityAndAccessManagementMetadata for the first
     * authorization server listed in the issuer metadata.
     */
    private func resolveAuthServerMetadata(
        issuerMetadata: CredentialIssuerMetadata
    ): IdentityAndAccessManagementMetadata {
        if (issuerMetadata.authorizationServers.isEmpty()) {
            throw WalletError.withDescription("No authorization servers in issuer metadata")
        }
        let authServerUrl = issuerMetadata.authorizationServers[0]
        let asResolver = AuthorizationServerMetadataResolver()
        return asResolver.resolve(authServerUrl)
    }

    // -----------------------------------------------------------------------
    // Private helpers — credential configuration resolution
    // -----------------------------------------------------------------------

    /**
     * Build an OfferedIssuanceModel from a resolved CredentialOffer.
     * Iterates credential_configurations_supported to build OfferedDocModel entries
     * matching the identifiers in the offer.
     */
    private func buildOfferedIssuanceModel(offer: CredentialOffer): OfferedIssuanceModel {
        let metadata = offer.credentialIssuerMetadata
        let issuerDisplay = metadata.display
        let issuerName: String = if (issuerDisplay.isEmpty()) {
            metadata.credentialIssuerIdentifier.url
        } else {
            match (issuerDisplay[0].name) {
                case Some(n) => n
                case None => metadata.credentialIssuerIdentifier.url
            }
        }
        let issuerLogoUrl: ?String = if (issuerDisplay.isEmpty()) {
            None
        } else {
            match (issuerDisplay[0].logo) {
                case Some(logo) => match (logo.uri) {
                    case Some(u) => Some(u)
                    case None => Option<String>.None
                }
                case None => Option<String>.None
            }
        }

        let docModels = ArrayList<OfferedDocModel>()
        for (configId in offer.credentialConfigurationIdentifiers) {
            let raw = metadata.credentialConfigurationsRaw.get(configId.value)
            match (raw) {
                case Some(credObj) =>
                    let offered = buildOfferedDocModel(configId, credObj, metadata)
                    docModels.add(offered)
                case None => ()
            }
        }

        // Extract txCode from grants
        let txCodeSpec: ?TxCode = extractTxCode(offer.grants)

        // Validate the issuer WRPRC for the offered configurations when
        // enabled, mirroring iOS resolveOfferDocTypes (errors are swallowed
        // there — `try? authorizer.authorize` — so the offer still resolves
        // and the app decides from the recorded policy / warnings).
        let offerConfigIds = ArrayList<String>()
        for (configId in offer.credentialConfigurationIdentifiers) {
            offerConfigIds.add(configId.value)
        }
        validateIssuerRegistrationTolerant(metadata, offerConfigIds.toArray())

        return OfferedIssuanceModel(issuerName, issuerLogoUrl, docModels, txCodeSpec,
            wrpVciRegistrationPolicy: this.wrpIssuerPolicy,
            wrpVciWarnings: this.wrpIssuerWarnings)
    }

    /**
     * Build an OfferedDocModel from a raw credential configuration JSON object.
     */

    private func credObjKeys(o: JsonObject): String {
        var out = ""
        for ((k, _) in o.getFields()) {
            if (!out.isEmpty()) { out = out + "," }
            out = out + k
        }
        return out
    }

    private func buildOfferedDocModel(
        configId: CredentialConfigurationIdentifier,
        credObj: JsonObject,
        metadata: CredentialIssuerMetadata
    ): OfferedDocModel {
        // Extract format
        let formatStr: String = match (credObj.get("format")) {
            case Some(js: JsonString) => js.getValue()
            case _ => "mso_mdoc"
        }
        let (docType, vct, format) = parseFormatFields(formatStr, credObj)
        Hilog.info(0, "VCI-DEBUG", "buildOffered cfg=${configId.value} format=[${formatStr}] docType=${docType ?? "-"} vct=${vct ?? "-"} keys=${credObjKeys(credObj)}")

        // Extract scope
        let scope: ?String = match (credObj.get("scope")) {
            case Some(js: JsonString) => Some(js.getValue())
            case _ => None
        }

        // Extract display name
        let displayName = extractDisplayName(credObj, configId.value)

        // Extract alg values supported
        let algValues = extractStringArray(credObj, "credential_signing_alg_values_supported")

        // Extract claims (simplified: empty for msoMdoc without claim parsing)
        let claims = ArrayList<Claim>()

        let credMetadata = ConfigurationCredentialMetadata(credObj.toJsonString())
        let defaultCredOptions = CredentialOptions(CredentialPolicy.OneTimeUse, 1)

        return OfferedDocModel(
            configId.value,
            docType,
            vct,
            scope,
            None,
            displayName,
            algValues,
            claims,
            Some(credMetadata),
            defaultCredOptions,
            None
        )
    }

    /**
     * Parse format-specific fields from a credential configuration JSON object.
     * Returns (docType, vct, DocDataFormat).
     */
    private func parseFormatFields(
        formatStr: String,
        credObj: JsonObject
    ): (?String, ?String, DocDataFormat) {
        match (formatStr) {
            case "mso_mdoc" =>
                let docType: ?String = match (credObj.get("doctype")) {
                    case Some(js: JsonString) => Some(js.getValue())
                    case _ => None
                }
                return (docType, None, DocDataFormat.Cbor)
            case "vc+sd-jwt" | "dc+sd-jwt" =>
                let vct: ?String = match (credObj.get("vct")) {
                    case Some(js: JsonString) => Some(js.getValue())
                    case _ => None
                }
                return (None, vct, DocDataFormat.Sdjwt)
            case _ =>
                return (None, None, DocDataFormat.Cbor)
        }
    }

    /**
     * Extract a display name from a credential configuration JSON object.
     * OID4VCI v1 (issuer.eudiw.dev) nests it under `credential_metadata.display`;
     * older drafts keep a top-level `display` array. Check both, fall back to
     * the configuration identifier value ("PID (MSO Mdoc)" vs raw config id on
     * the offer screen — iOS resolves the same nested path).
     */
    private func extractDisplayName(credObj: JsonObject, fallback: String): String {
        match (displayNameFromArray(credObj.get("display"))) {
            case Some(n) => return n
            case None => ()
        }
        match (credObj.get("credential_metadata")) {
            case Some(cm: JsonObject) =>
                match (displayNameFromArray(cm.get("display"))) {
                    case Some(n) => return n
                    case None => ()
                }
            case _ => ()
        }
        return fallback
    }

    /** First `name` out of a display JSON array, if any. */
    private func displayNameFromArray(displayOpt: ?JsonValue): ?String {
        match (displayOpt) {
            case Some(ja: JsonArray) =>
                for (item in ja.getItems()) {
                    match (item) {
                        case jobj: JsonObject =>
                            match (jobj.get("name")) {
                                case Some(js: JsonString) => return Some(js.getValue())
                                case _ => ()
                            }
                        case _ => ()
                    }
                }
                return None
            case _ => return None
        }
    }

    /**
     * Extract a string array field from a JSON object.
     */
    private func extractStringArray(obj: JsonObject, key: String): Array<String> {
        match (obj.get(key)) {
            case Some(ja: JsonArray) =>
                let result = ArrayList<String>()
                for (item in ja.getItems()) {
                    match (item) {
                        case js: JsonString => result.add(js.getValue())
                        case _ => ()
                    }
                }
                return result.toArray()
            case _ => return []
        }
    }

    /**
     * Resolve CredentialConfigurationIdentifiers matching the requested DocTypeIdentifiers.
     */
    private func resolveConfigurationIds(
        docTypeIdentifiers: Array<DocTypeIdentifier>,
        issuerMetadata: CredentialIssuerMetadata
    ): Array<CredentialConfigurationIdentifier> {
        let result = ArrayList<CredentialConfigurationIdentifier>()
        for (dti in docTypeIdentifiers) {
            for ((configIdStr, credObj) in issuerMetadata.credentialConfigurationsRaw) {
                if (docTypeMatchesConfig(dti, configIdStr, credObj)) {
                    result.add(CredentialConfigurationIdentifier(configIdStr))
                    break
                }
            }
        }
        return result.toArray()
    }

    /**
     * Return true if the DocTypeIdentifier matches a credential configuration.
     */
    private func docTypeMatchesConfig(
        dti: DocTypeIdentifier,
        configIdStr: String,
        credObj: JsonObject
    ): Bool {
        match (dti) {
            case DocTypeIdentifier.Identifier(id) =>
                return id == configIdStr
            case DocTypeIdentifier.MsoMdoc(docType) =>
                let rawDocType: String = match (credObj.get("doctype")) {
                    case Some(js: JsonString) => js.getValue()
                    case _ => ""
                }
                return docType == rawDocType
            case DocTypeIdentifier.SdJwt(vct) =>
                let rawVct: String = match (credObj.get("vct")) {
                    case Some(js: JsonString) => js.getValue()
                    case _ => ""
                }
                return vct == rawVct
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers — credential submission processing
    // -----------------------------------------------------------------------

    /**
     * Process a SubmittedRequest result into an IssuanceOutcome.
     * Handles Success (Issued/Deferred credential items), Failed, and InvalidProof.
     */
    private func processSubmittedRequest(
        submitted: SubmittedRequest,
        req: IssueRequest,
        issuerMetadata: CredentialIssuerMetadata,
        authorizedRequest: AuthorizedRequest
    ): IssuanceOutcome {
        return processSubmittedRequestWithProofKeys(submitted, req, issuerMetadata, authorizedRequest)
    }

    /**
     * Process a SubmittedRequest into an IssuanceOutcome.
     *
     * Holder binding uses the SecureArea public point created by beginIssueDocument.
     */
    private func processSubmittedRequestWithProofKeys(
        submitted: SubmittedRequest,
        req: IssueRequest,
        issuerMetadata: CredentialIssuerMetadata,
        authorizedRequest: AuthorizedRequest,
        configId!: ?CredentialConfigurationIdentifier = None
    ): IssuanceOutcome {
        match (submitted) {
            case SubmittedRequest.Success(response) =>
                return processCredentialResponse(response, req, issuerMetadata, authorizedRequest, configId: configId)
            case SubmittedRequest.Failed(error) =>
                throw WalletError.withDescription("Credential issuance failed: " + error.message)
            case SubmittedRequest.InvalidProof(descOpt) =>
                let desc: String = match (descOpt) { case Some(s) => s; case None => "Invalid proof of possession" }
                throw WalletError.withDescription("Invalid PoP proof: " + desc)
        }
    }

    /**
     * Convert a CredentialIssuanceResponse into an IssuanceOutcome.
     */
    private func processCredentialResponse(
        response: CredentialIssuanceResponse,
        req: IssueRequest,
        issuerMetadata: CredentialIssuerMetadata,
        authorizedRequest: AuthorizedRequest,
        configId!: ?CredentialConfigurationIdentifier = None
    ): IssuanceOutcome {
        let issuedPairs = ArrayList<(Array<UInt8>, Array<UInt8>)>()
        let deferred: ?DeferredIssuanceModel = None
        var deferredModel: ?DeferredIssuanceModel = None

        for (item in response.credentialResponses) {
            match (item) {
                case IssuedCredential.Issued(_, credential, _) =>
                    let credBytes = credentialToBytes(credential)
                    let idx = Int64(issuedPairs.size)
                    let secureArea = SecureAreaRegistry.shared.get(req.secureAreaName)
                    let batchInfo = secureArea.getKeyBatchInfo(req.id)
                    let holderPubX963: Array<UInt8> = if (idx < batchInfo.batchSize()) {
                        secureArea.getPublicKeyBytes(req.id, idx, batchInfo.crv)
                    } else {
                        Array<UInt8>()
                    }
                    issuedPairs.add((credBytes, holderPubX963))
                case IssuedCredential.Deferred(transactionId, _) =>
                    let deferredEndpointUrl = match (issuerMetadata.deferredCredentialEndpoint) {
                        case Some(ep) => ep.url
                        case None => issuerMetadata.credentialEndpoint.url
                    }
                    let pubKeysData = ArrayList<Array<UInt8>>()
                    let secureArea = SecureAreaRegistry.shared.get(req.secureAreaName)
                    let batchInfo = secureArea.getKeyBatchInfo(req.id)
                    var ki: Int64 = 0
                    while (ki < batchInfo.batchSize()) {
                        let pkBytes = secureArea.getPublicKeyBytes(req.id, ki, batchInfo.crv)
                        pubKeysData.add(pkBytes)
                        ki++
                    }
                    let now = Float64(DateTime.nowUTC().toUnixTimeStamp().toSeconds())
                    // Persist the session's authorization state alongside the
                    // transaction id: the deferred poll (possibly after an app
                    // restart) must authorize with the ORIGINAL access token /
                    // refresh token and the SAME DPoP key the token is bound to
                    // (iOS: DocMetadata.authorizedRequestData + dpopKeyId).
                    let refreshTokenStr: String = match (authorizedRequest.refreshToken) {
                        case Some(rt) => rt.refreshToken ?? ""
                        case None => ""
                    }
                    let tokenTypeStr: String = match (authorizedRequest.accessToken.tokenType) {
                        case Some(tt) => tt.rawValue()
                        case None => ""
                    }
                    let dpopId: String = match (this.activeDPoPKeyId) {
                        case Some(id) => id
                        case None => ""
                    }
                    deferredModel = Some(DeferredIssuanceModel(
                        deferredEndpointUrl,
                        transactionId,
                        pubKeysData,
                        None,
                        now,
                        accessToken: authorizedRequest.accessToken.accessToken,
                        tokenType: tokenTypeStr,
                        refreshToken: refreshTokenStr,
                        expiresIn: authorizedRequest.accessToken.expiresIn,
                        dpopKeyId: dpopId,
                        dpopKeyDer: Array<UInt8>()
                    ))
            }
        }

        if (!issuedPairs.isEmpty()) {
            let config = buildCredentialConfigForReq(req, issuerMetadata, configId: configId)
            return IssuanceOutcome.Issued(issuedPairs, config, "")
        }

        match (deferredModel) {
            case Some(dm) =>
                let config = buildCredentialConfigForReq(req, issuerMetadata, configId: configId)
                return IssuanceOutcome.Deferred(dm, config, "")
            case None =>
                throw WalletError.withDescription(
                    "No credentials issued and no deferred transaction for id=" + req.id
                )
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers — CredentialConfiguration building
    // -----------------------------------------------------------------------

    /**
     * Build a minimal CredentialConfiguration for an IssueRequest.
     * Used when creating IssuanceOutcome instances.
     */
    private func buildCredentialConfigForReq(
        req: IssueRequest,
        issuerMetadata: CredentialIssuerMetadata,
        configId!: ?CredentialConfigurationIdentifier = None
    ): CredentialConfiguration {
        // When the real configuration identifier is known (auth-code resume), build a
        // full config carrying the credential-config display / issuer display so the
        // issued document persists real document & issuer names and logos (iOS
        // DocMetadata parity). Falls back to the request-id placeholder otherwise.
        match (configId) {
            case Some(cid) => return buildCredentialConfigForConfigId(cid, issuerMetadata)
            case None => ()
        }

        let issuerUrl = match (openId4VciConfiguration.credentialIssuerURL) {
            case Some(u) => u
            case None => ""
        }

        // Use a placeholder configId based on the request id
        let placeholderConfigId = CredentialConfigurationIdentifier(req.id)
        let defaultCredOpts = req.credentialOptions

        return CredentialConfiguration(
            placeholderConfigId,
            issuerUrl,
            None,
            None,
            None,
            false,
            true,
            true,
            [],
            None,
            None,
            ArrayList<Display>(),
            ArrayList<Display>(),
            ArrayList<Claim>(),
            None,
            DocDataFormat.Cbor,
            defaultCredOpts
        )
    }

    /**
     * Build a CredentialConfiguration for a concrete configuration identifier by
     * reading the issuer's credential_configurations_supported entry.
     *
     * Used by prepareAuthorizationCodeIssuance so the persisted Pending Document
     * carries the real configuration identifier (e.g. eu.europa.ec.eudi.pid_mdoc),
     * docType / vct, scope and format — these are what resumePendingIssuance
     * replays into the token + credential request.
     */
    private func buildCredentialConfigForConfigId(
        configId: CredentialConfigurationIdentifier,
        issuerMetadata: CredentialIssuerMetadata
    ): CredentialConfiguration {
        let issuerUrl = match (openId4VciConfiguration.credentialIssuerURL) {
            case Some(u) => u
            case None => issuerMetadata.credentialIssuerIdentifier.url
        }

        var docType: ?String = None
        var vct: ?String = None
        var scope: ?String = None
        var format = DocDataFormat.Cbor
        var algValues: Array<String> = []
        // Credential-config display (document name + logo) for DocMetadata persistence.
        let displayList = ArrayList<Display>()
        // Compact per-claim display-name metadata (path → name) for claim labels.
        var claimMeta: ?ConfigurationCredentialMetadata = None

        match (issuerMetadata.credentialConfigurationsRaw.get(configId.value)) {
            case Some(credObj) =>
                let formatStr: String = match (credObj.get("format")) {
                    case Some(js: JsonString) => js.getValue()
                    case _ => "mso_mdoc"
                }
                let (dt, v, fmt) = parseFormatFields(formatStr, credObj)
                docType = dt
                vct = v
                format = fmt
                scope = match (credObj.get("scope")) {
                    case Some(js: JsonString) => Some(js.getValue())
                    case _ => None
                }
                algValues = extractStringArray(credObj, "credential_signing_alg_values_supported")
                // Newer OID4VCI drafts (eudiw.dev) nest per-credential display under
                // credential_metadata.display; older drafts use top-level display.
                var displayVal: ?JsonValue = None
                match (credObj.get("credential_metadata")) {
                    case Some(cm: JsonObject) => displayVal = cm.get("display")
                    case _ => ()
                }
                if (displayVal.isNone()) { displayVal = credObj.get("display") }
                match (displayVal) {
                    case Some(arr: JsonArray) =>
                        for (item in arr.getItems()) {
                            match (item) {
                                case o: JsonObject => displayList.add(Display.fromJson(o))
                                case _ => ()
                            }
                        }
                    case _ => ()
                }
                match (extractClaimMetadataArray(credObj)) {
                    case Some(cmArr) => claimMeta = ConfigurationCredentialMetadata(cmArr.toJsonString())
                    case None => ()
                }
            case None => ()
        }

        // Issuer-level display (issuer name + logo) from the resolved issuer metadata.
        let issuerDisplayList = ArrayList<Display>()
        for (d in issuerMetadata.display) { issuerDisplayList.add(d) }

        return CredentialConfiguration(
            configId,
            issuerUrl,
            docType,
            vct,
            scope,
            false,
            true,
            true,
            algValues,
            None,
            None,
            issuerDisplayList,
            displayList,
            ArrayList<Claim>(),
            claimMeta,
            format,
            credentialOptionsOrDefault()
        )
    }

    /** Default single-use credential options used for prepared configurations. */
    private func credentialOptionsOrDefault(): CredentialOptions {
        return CredentialOptions(CredentialPolicy.OneTimeUse, 1)
    }

    // -----------------------------------------------------------------------
    // Private helpers — key material
    // -----------------------------------------------------------------------

    /**
     * Get public key bytes for a given index from the SecureArea for an IssueRequest.
     */
    private func getPublicKeyBytesForReq(req: IssueRequest, index: Int64): Array<UInt8> {
        let secureArea = SecureAreaRegistry.shared.get(req.secureAreaName)
        let batchInfo = secureArea.getKeyBatchInfo(req.id)
        return secureArea.getPublicKeyBytes(req.id, index, batchInfo.crv)
    }

    // -----------------------------------------------------------------------
    // Private helpers — storage serialization
    // -----------------------------------------------------------------------

    /**
     * Serialize a Credential to raw bytes for storage.
     * StringCredential: UTF-8 bytes of the JWT/SD-JWT string.
     * JsonCredential: UTF-8 bytes of the JSON object string.
     */
    private func credentialToBytes(credential: Credential): Array<UInt8> {
        match (credential) {
            case Credential.StringCredential(s) => return s.toArray()
            case Credential.JsonCredential(obj) => return obj.toJsonString().toArray()
        }
    }

    /**
     * Build DocKeyInfo CBOR bytes from an IssueRequest for storage in Document.docKeyInfo.
     */
    private func buildDocKeyInfoBytes(req: IssueRequest): ?Array<UInt8> {
        let info = DocKeyInfo(
            req.secureAreaName,
            req.credentialOptions.batchSize,
            req.credentialOptions.credentialPolicy
        )
        return Some(info.toBytes())
    }

    /**
     * Convert DocDataFormat from mdoc_data_model to wallet_storage DocDataFormat.
     */
    private func docDataFormatToStorage(fmt: DocDataFormat): StorageDocDataFormat {
        match (fmt) {
            case DocDataFormat.Cbor => return StorageDocDataFormat.Cbor
            case DocDataFormat.Sdjwt => return StorageDocDataFormat.Sdjwt
        }
    }

    /**
     * Extract a human-readable docType string from a CredentialConfiguration.
     * Prefers docType (msoMdoc) over vct (sdJwt); falls back to config identifier.
     */
    private func resolveDocType(config: CredentialConfiguration): String {
        match (config.docType) {
            case Some(dt) => return dt
            case None =>
                match (config.vct) {
                    case Some(v) => return v
                    case None => return config.configurationIdentifier.value
                }
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers — metadata encoding / decoding
    // -----------------------------------------------------------------------

    /**
     * Encode DeferredIssuanceModel to JSON bytes for Document.metadata.
     * Format: {"deferred_endpoint": "...", "transaction_id": "...", "timestamp": ...}
     */
    private func encodeDeferredMetadata(model: DeferredIssuanceModel): Array<UInt8> {
        let obj = JsonObject()
        obj.put("deferred_endpoint", JsonString(model.deferredEndpointUrl))
        obj.put("transaction_id", JsonString(model.transactionId.value))
        obj.put("timestamp", JsonFloat(model.timeStamp))
        // Authorization state for the later poll (iOS authorizedRequestData +
        // dpopKeyId parity). base64url keeps the DER binary JSON-safe.
        obj.put("access_token", JsonString(model.accessToken))
        obj.put("token_type", JsonString(model.tokenType))
        obj.put("refresh_token", JsonString(model.refreshToken))
        obj.put("expires_in", JsonFloat(model.expiresIn))
        if (!model.dpopKeyId.isEmpty()) {
            obj.put("dpop_key_id", JsonString(model.dpopKeyId))
        } else if (model.dpopKeyDer.size > 0) {
            obj.put("dpop_key_der", JsonString(Base64Url.encode(model.dpopKeyDer)))
        }
        return obj.toJsonString().toArray()
    }

    /** Serialize a credential-config Display list to a JSON array (name/locale/logo.uri). */
    private func displayListToJson(displays: ArrayList<Display>): JsonArray {
        let arr = JsonArray()
        for (d in displays) {
            let o = JsonObject()
            match (d.name) { case Some(n) => o.put("name", JsonString(n)); case None => () }
            match (d.locale) { case Some(l) => o.put("locale", JsonString(l)); case None => () }
            match (d.logo) {
                case Some(lg) =>
                    match (lg.uri) {
                        case Some(u) =>
                            let lo = JsonObject()
                            lo.put("uri", JsonString(u))
                            o.put("logo", lo)
                        case None => ()
                    }
                case None => ()
            }
            arr.add(o)
        }
        return arr
    }

    /**
     * Pick a single display name from an OID4VCI `display` array, preferring the
     * `en` locale, else the first entry. Mirrors iOS DisplayMetadata.getName.
     */
    private func pickDisplayName(displayVal: ?JsonValue): ?String {
        let arr = match (displayVal) {
            case Some(ja: JsonArray) => ja
            case _ => return None
        }
        var first: ?String = None
        for (item in arr.getItems()) {
            match (item) {
                case o: JsonObject =>
                    match (o.get("name")) {
                        case Some(js: JsonString) =>
                            let nm = js.getValue()
                            let loc = match (o.get("locale")) {
                                case Some(l: JsonString) => l.getValue()
                                case _ => ""
                            }
                            if (loc == "en") { return nm }
                            if (first.isNone()) { first = nm }
                        case _ => ()
                    }
                case _ => ()
            }
        }
        return first
    }

    /**
     * Extract compact claim display-name metadata from a credential config's
     * `credential_metadata.claims` (newer OID4VCI drafts) or top-level `claims`.
     * Produces `[{"path":[...],"name":"<display>"}]` (path + single en-locale
     * name only) so the issued-document blob can label claims exactly like iOS
     * (DocClaimMetadata). Deliberately compact — never the full credObj, which
     * carries every locale and overflows the heap (the issuance OOM root cause).
     * Returns None when no claim metadata with display names is present.
     */
    private func extractClaimMetadataArray(credObj: JsonObject): ?JsonArray {
        var claimsVal: ?JsonValue = None
        match (credObj.get("credential_metadata")) {
            case Some(cm: JsonObject) => claimsVal = cm.get("claims")
            case _ => ()
        }
        if (claimsVal.isNone()) { claimsVal = credObj.get("claims") }
        let claimsArr = match (claimsVal) {
            case Some(ja: JsonArray) => ja
            case _ => return None
        }
        let out = JsonArray()
        var added = false
        for (item in claimsArr.getItems()) {
            match (item) {
                case o: JsonObject =>
                    match (o.get("path")) {
                        case Some(pa: JsonArray) =>
                            let pathOut = JsonArray()
                            for (seg in pa.getItems()) {
                                match (seg) {
                                    case js: JsonString => pathOut.add(JsonString(js.getValue()))
                                    case _ => ()
                                }
                            }
                            match (pickDisplayName(o.get("display"))) {
                                case Some(nm) =>
                                    let entry = JsonObject()
                                    entry.put("path", pathOut)
                                    entry.put("name", JsonString(nm))
                                    out.add(entry)
                                    added = true
                                case None => ()
                            }
                        case _ => ()
                    }
                case _ => ()
            }
        }
        if (!added) { return None }
        return out
    }

    /**
     * Encode the issued document's DocMetadata to JSON bytes for Document.metadata.
     * Mirrors iOS OpenId4VciService.endIssueDocument storing
     * `cc.convertToDocMetadata(...).toData()` — persists the credential issuer
     * identifier, configuration id, docType, and the credential-config display /
     * issuer display so the wallet UI can show the real document & issuer names and
     * logos after the storage round-trip (instead of reconstructing them from the
     * raw mdoc claims). The matching decoder lives in logic-core decodeMetadataBlob.
     */
    private func encodeIssuedMetadata(config: CredentialConfiguration): Array<UInt8> {
        return issuedMetadataObject(config).toJsonString().toArray()
    }

    /** DocMetadata JSON object for a credential config (shared by the issued /
     *  deferred / pending persistence paths). */
    private func issuedMetadataObject(config: CredentialConfiguration): JsonObject {
        let obj = JsonObject()
        obj.put("credentialIssuerIdentifier", JsonString(config.credentialIssuerIdentifier))
        obj.put("configurationIdentifier", JsonString(config.configurationIdentifier.value))
        obj.put("docType", JsonString(resolveDocType(config)))
        obj.put("display", displayListToJson(config.display))
        obj.put("issuerDisplay", displayListToJson(config.issuerDisplay))
        // Compact per-claim display-name metadata (path → name), so the wallet UI
        // labels claims exactly like iOS instead of prettifying raw keys.
        match (config.credentialMetadata) {
            case Some(m) =>
                match (JsonValue.fromStr(m.rawJson)) {
                    case arr: JsonArray => obj.put("claims", arr)
                    case _ => ()
                }
            case None => ()
        }
        return obj
    }

    /**
     * Metadata blob for a Pending (dynamic-issuance) document: the full
     * DocMetadata (display / issuerDisplay / issuer id — so the Documents list
     * renders name + logo) PLUS `pending_reason_url`, which logic-core's
     * decodeMetadataBlob surfaces as pendingAuthorizationUrl (iOS
     * authorizePresentationUrl parity). The complete pending model itself is
     * persisted in Document.data.
     */
    private func encodePendingCombinedMetadata(
        model: PendingIssuanceModel,
        config: CredentialConfiguration
    ): Array<UInt8> {
        let obj = issuedMetadataObject(config)
        match (model.pendingReason) {
            case PendingReason.PresentationRequestUrl(url) =>
                obj.put("pending_reason_url", JsonString(url))
        }
        return obj.toJsonString().toArray()
    }

    /**
     * Decode DeferredIssuanceModel from Document.data bytes (iOS parity:
     * dataToSave = encode(deferredIssuanceModel)). Falls back to the legacy
     * layout (deferred blob in Document.metadata) for documents stored before
     * the metadata/data split fix.
     */
    private func decodeDeferredMetadata(doc: Document): DeferredIssuanceModel {
        let metaBytes: Array<UInt8> = if (doc.data.size > 0) {
            doc.data
        } else {
            match (doc.metadata) {
                case Some(b) => b
                case None =>
                    throw WalletError.withDescription(
                        "Deferred document " + doc.id + " has no deferred model data"
                    )
            }
        }
        let jsonStr = String.fromUtf8(metaBytes)
        let jv = JsonValue.fromStr(jsonStr)
        let obj = match (jv) {
            case jobj: JsonObject => jobj
            case _ =>
                throw WalletError.withDescription("Invalid deferred metadata for document " + doc.id)
        }
        let endpoint: String = match (obj.get("deferred_endpoint")) {
            case Some(js: JsonString) => js.getValue()
            case _ => ""
        }
        let txIdStr: String = match (obj.get("transaction_id")) {
            case Some(js: JsonString) => js.getValue()
            case _ => throw WalletError.withDescription("Missing transaction_id in deferred metadata")
        }
        let ts: Float64 = match (obj.get("timestamp")) {
            case Some(jf: JsonFloat) => jf.getValue()
            case Some(ji: JsonInt) => Float64(ji.getValue())
            case _ => 0.0
        }
        // Authorization state (absent on legacy blobs → empty defaults).
        let accessTok: String = match (obj.get("access_token")) {
            case Some(js: JsonString) => js.getValue()
            case _ => ""
        }
        let tokType: String = match (obj.get("token_type")) {
            case Some(js: JsonString) => js.getValue()
            case _ => ""
        }
        let refreshTok: String = match (obj.get("refresh_token")) {
            case Some(js: JsonString) => js.getValue()
            case _ => ""
        }
        let expIn: Float64 = match (obj.get("expires_in")) {
            case Some(jf: JsonFloat) => jf.getValue()
            case Some(ji: JsonInt) => Float64(ji.getValue())
            case _ => 0.0
        }
        let dpopId: String = match (obj.get("dpop_key_id")) {
            case Some(js: JsonString) => js.getValue()
            case _ => ""
        }
        let dpopDer: Array<UInt8> = match (obj.get("dpop_key_der")) {
            case Some(js: JsonString) => Base64Url.decode(js.getValue())
            case _ => Array<UInt8>()
        }
        return DeferredIssuanceModel(
            endpoint,
            TransactionId(txIdStr),
            ArrayList<Array<UInt8>>(),
            None,
            ts,
            accessToken: accessTok,
            tokenType: tokType,
            refreshToken: refreshTok,
            expiresIn: expIn,
            dpopKeyId: dpopId,
            dpopKeyDer: dpopDer
        )
    }

    /**
     * Encode PendingIssuanceModel to JSON bytes for Document.metadata.
     */
    private func encodePendingMetadata(model: PendingIssuanceModel): Array<UInt8> {
        let obj = JsonObject()
        let reasonStr: String = match (model.pendingReason) {
            case PendingReason.PresentationRequestUrl(url) => url
        }
        obj.put("pending_reason_url", JsonString(reasonStr))
        obj.put("config_id", JsonString(model.configuration.configurationIdentifier.value))
        // Combined (iOS "PID Combined") config-id list so resume issues each format.
        let cidArr = JsonArray()
        for (cid in model.allConfigIds()) {
            cidArr.add(JsonString(cid))
        }
        obj.put("config_ids", cidArr)
        obj.put("pkce_verifier", JsonString(model.pkceCodeVerifier))
        obj.put("pkce_method", JsonString(model.pkceCodeVerifierMethod))
        obj.put("state", JsonString(model.state))
        obj.put("metadata_key", JsonString(model.metadataKey))
        if (!model.dpopKeyId.isEmpty()) {
            obj.put("dpop_key_id", JsonString(model.dpopKeyId))
        }
        // credentialIssuerIdentifier lets logic-core's metadata decoder expose the
        // issuer (iOS DocMetadata parity) and feeds the authorizePresentationUrl
        // accessor on the pending document.
        obj.put("credentialIssuerIdentifier",
            JsonString(model.configuration.credentialIssuerIdentifier))
        return obj.toJsonString().toArray()
    }

    /**
     * Decode PendingIssuanceModel from Document.metadata bytes.
     * Returns a minimal PendingIssuanceModel sufficient for resumePendingIssuance.
     */
    private func decodePendingMetadata(doc: Document): PendingIssuanceModel {
        // iOS parity: pending model lives in Document.data; legacy fallback to
        // Document.metadata for documents stored before the layout fix.
        let metaBytes: Array<UInt8> = if (doc.data.size > 0) {
            doc.data
        } else {
            match (doc.metadata) {
                case Some(b) => b
                case None =>
                    throw WalletError.withDescription(
                        "Pending document " + doc.id + " has no pending model data"
                    )
            }
        }
        let jsonStr = String.fromUtf8(metaBytes)
        let jv = JsonValue.fromStr(jsonStr)
        let obj = match (jv) {
            case jobj: JsonObject => jobj
            case _ =>
                throw WalletError.withDescription("Invalid pending metadata for document " + doc.id)
        }
        let reasonUrl: String = match (obj.get("pending_reason_url")) {
            case Some(js: JsonString) => js.getValue()
            case _ => ""
        }
        let configIdStr: String = match (obj.get("config_id")) {
            case Some(js: JsonString) => js.getValue()
            case _ => doc.docType
        }
        // Combined config-id list (iOS "PID Combined"); empty for single-config docs.
        let configIdList = ArrayList<String>()
        match (obj.get("config_ids")) {
            case Some(arr: JsonArray) =>
                for (item in arr.getItems()) {
                    match (item) {
                        case js: JsonString => configIdList.add(js.getValue())
                        case _ => ()
                    }
                }
            case _ => ()
        }
        let pkceVerifier: String = match (obj.get("pkce_verifier")) {
            case Some(js: JsonString) => js.getValue()
            case _ => ""
        }
        let pkceMethod: String = match (obj.get("pkce_method")) {
            case Some(js: JsonString) => js.getValue()
            case _ => "S256"
        }
        let state: String = match (obj.get("state")) {
            case Some(js: JsonString) => js.getValue()
            case _ => ""
        }
        let metaKey: String = match (obj.get("metadata_key")) {
            case Some(js: JsonString) => js.getValue()
            case _ => doc.id
        }
        let dpopKeyId: String = match (obj.get("dpop_key_id")) {
            case Some(js: JsonString) => js.getValue()
            case _ => ""
        }

        let config = buildMinimalCredentialConfig(configIdStr, doc)
        return PendingIssuanceModel(
            PendingReason.PresentationRequestUrl(reasonUrl),
            config,
            metaKey,
            pkceVerifier,
            pkceMethod,
            state,
            configIds: configIdList.toArray(),
            dpopKeyId: dpopKeyId
        )
    }

    /**
     * Build a minimal CredentialConfiguration from a configId string and a Document.
     */
    private func buildMinimalCredentialConfig(
        configIdStr: String,
        doc: Document
    ): CredentialConfiguration {
        let issuerUrl = match (openId4VciConfiguration.credentialIssuerURL) {
            case Some(u) => u
            case None => ""
        }
        let configId = CredentialConfigurationIdentifier(configIdStr)
        let storFmt = doc.docDataFormat
        let mdFmt = storageFormatToDocDataFormat(storFmt)
        let defaultCredOpts = CredentialOptions(CredentialPolicy.OneTimeUse, 1)
        return CredentialConfiguration(
            configId,
            issuerUrl,
            Some(doc.docType),
            None,
            None,
            false,
            true,
            true,
            [],
            None,
            None,
            ArrayList<Display>(),
            ArrayList<Display>(),
            ArrayList<Claim>(),
            None,
            mdFmt,
            defaultCredOpts
        )
    }

    /**
     * Convert StorageDocDataFormat to mdoc DocDataFormat.
     */
    private func storageFormatToDocDataFormat(fmt: StorageDocDataFormat): DocDataFormat {
        match (fmt) {
            case StorageDocDataFormat.Cbor => return DocDataFormat.Cbor
            case StorageDocDataFormat.Sdjwt => return DocDataFormat.Sdjwt
        }
    }

    // -----------------------------------------------------------------------
    // Private helpers — authorization flow resume
    // -----------------------------------------------------------------------

    /**
     * Build a minimal AuthorizedRequest for use in the deferred credential endpoint.
     * The access token is embedded as an empty placeholder; the Issuer uses the
     * DPoP nonce and token from the deferred model's timestamp context.
     *
     * In a production implementation, the access token from the original
     * authorization should be stored in the DeferredIssuanceModel and retrieved here.
     */
    /**
     * Re-persist a still-deferred document's data blob with the (possibly new)
     * transaction id and the (possibly refreshed) authorization state, keeping
     * the DocMetadata blob in Document.metadata untouched. Returns the saved
     * Document (Document.data is immutable, so a new instance is built).
     */
    private func persistDeferredState(
        deferredDoc: Document,
        model: DeferredIssuanceModel,
        txId: TransactionId,
        authorizedRequest: AuthorizedRequest
    ): Document {
        let rtStr: String = match (authorizedRequest.refreshToken) {
            case Some(rt) => rt.refreshToken ?? ""
            case None => ""
        }
        let ttStr: String = match (authorizedRequest.accessToken.tokenType) {
            case Some(tt) => tt.rawValue()
            case None => ""
        }
        let newModel = DeferredIssuanceModel(
            model.deferredEndpointUrl,
            txId,
            model.publicKeysData,
            model.derKeyData,
            authorizedRequest.timeStamp,
            accessToken: authorizedRequest.accessToken.accessToken,
            tokenType: ttStr,
            refreshToken: rtStr,
            expiresIn: authorizedRequest.accessToken.expiresIn,
            dpopKeyId: model.dpopKeyId,
            dpopKeyDer: model.dpopKeyDer
        )
        let updated = Document(
            deferredDoc.docType,
            deferredDoc.docDataFormat,
            encodeDeferredMetadata(newModel),
            deferredDoc.docKeyInfo,
            deferredDoc.metadata,
            deferredDoc.displayName,
            DocumentStatus.Deferred
        )
        updated.id = deferredDoc.id
        storageManager.storageService.saveDocument(updated, None, true)
        return updated
    }

    private func buildAuthorizedRequestForDeferred(
        model: DeferredIssuanceModel
    ): AuthorizedRequest {
        // Rebuild the ORIGINAL session's authorization (iOS decodes
        // authorizedRequestData from DocMetadata). Legacy blobs without a
        // persisted token cannot authorize the deferred endpoint — fail fast so
        // the poll marks the document failed instead of looping on 401s.
        if (model.accessToken.isEmpty()) {
            throw WalletError.withDescription(
                "Deferred document has no persisted authorization (legacy blob); re-issue the document"
            )
        }
        let tokenType: Option<TokenType> = if (model.tokenType == "DPoP") {
            Some(TokenType.DPoP)
        } else if (model.tokenType == "Bearer") {
            Some(TokenType.Bearer)
        } else if (model.tokenType.isEmpty()) {
            Option<TokenType>.None
        } else {
            Some(TokenType.Other(model.tokenType))
        }
        let accessToken = IssuanceAccessToken(model.accessToken, tokenType, model.expiresIn)
        let refreshToken: Option<IssuanceRefreshToken> = if (model.refreshToken.isEmpty()) {
            Option<IssuanceRefreshToken>.None
        } else {
            Some(IssuanceRefreshToken(Some(model.refreshToken)))
        }
        return AuthorizedRequest(
            accessToken,
            refreshToken,
            Option<AuthorizationDetailsIdentifiers>.None,
            model.timeStamp,
            Option<Nonce>.None,
            Option<GrantType>.None
        )
    }

    /**
     * Reconstruct an AuthorizationRequested from a PendingIssuanceModel.
     * Used when resuming a pending OAuth redirect flow.
     *
     * @param model   The decoded pending model with PKCE/state fields and the
     *                original https authorization URL (in pendingReason).
     */
    private func buildAuthorizationRequestedFromPending(
        model: PendingIssuanceModel
    ): AuthorizationRequested {
        let pkceChallenge = PKCEGenerator.generateCodeChallenge(model.pkceCodeVerifier)
        let pkceVerifier = PKCEVerifier(model.pkceCodeVerifier, pkceChallenge, model.pkceCodeVerifierMethod)
        let authUrl: String = match (model.pendingReason) {
            case PendingReason.PresentationRequestUrl(url) => url
        }
        let authorizationCodeURL = AuthorizationCodeURL(authUrl)
        let cfgIds = ArrayList<CredentialConfigurationIdentifier>()
        for (cid in model.allConfigIds()) {
            cfgIds.add(CredentialConfigurationIdentifier(cid))
        }
        return AuthorizationRequested(
            [],
            authorizationCodeURL,
            pkceVerifier,
            model.state,
            cfgIds.toArray(),
            Option<Nonce>.None
        )
    }

    /**
     * Extract the authorization code from a redirect URL.
     * Expected format: <redirectUri>?code=<authCode>&state=<state>
     */
    private func extractAuthCode(redirectUrl: String): String {
        return extractQueryParam(redirectUrl, "code")
    }

    /**
     * Extract the state parameter from a redirect URL.
     */
    private func extractState(redirectUrl: String): String {
        return extractQueryParam(redirectUrl, "state")
    }

    /**
     * Extract a single query parameter value from a URL string.
     * Returns empty string if the parameter is not found.
     */
    private func extractQueryParam(url: String, paramName: String): String {
        let urlBytes = url.toArray()
        var qStart: Int64 = -1
        var i: Int64 = 0
        while (i < urlBytes.size) {
            if (urlBytes[i] == 63u8) {  // '?'
                qStart = i + 1
                break
            }
            i++
        }
        if (qStart < 0) {
            return ""
        }
        let query = String.fromUtf8(urlBytes[qStart..urlBytes.size])
        let parts = query.split("&")
        let prefix = paramName + "="
        for (part in parts) {
            if (part.startsWith(prefix)) {
                let partBytes = part.toArray()
                let prefixBytes = prefix.toArray()
                let raw = String.fromUtf8(partBytes[prefixBytes.size..partBytes.size])
                // Query values are percent-encoded: the authorization code is a
                // Fernet token whose '=' padding arrives as %3D. It MUST be URL-
                // decoded before going into the token form body, else double-
                // encoding makes /oidc/token 500 ('NoneType' has no session_id).
                return urlDecodeQuery(raw)
            }
        }
        return ""
    }

    // Percent-decode a query value: %XX -> byte, '+' -> space.
    private func urlDecodeQuery(s: String): String {
        let bytes = s.toArray()
        let out = ArrayList<UInt8>()
        var i: Int64 = 0
        func hx(c: UInt8): Int64 {
            if (c >= 48u8 && c <= 57u8) { return Int64(c - 48u8) }          // 0-9
            if (c >= 65u8 && c <= 70u8) { return Int64(c - 65u8) + 10 }     // A-F
            if (c >= 97u8 && c <= 102u8) { return Int64(c - 97u8) + 10 }    // a-f
            return -1
        }
        while (i < bytes.size) {
            let c = bytes[i]
            if (c == 37u8 && i + 2 < bytes.size) {  // '%'
                let hi = hx(bytes[i + 1]); let lo = hx(bytes[i + 2])
                if (hi >= 0 && lo >= 0) {
                    out.add(UInt8(hi * 16 + lo)); i += 3; continue
                }
            }
            if (c == 43u8) { out.add(32u8) } else { out.add(c) }  // '+' -> space
            i++
        }
        return String.fromUtf8(out.toArray())
    }

    // -----------------------------------------------------------------------
    // Private helpers — misc
    // -----------------------------------------------------------------------

    /**
     * Extract TxCode from offer Grants (pre-authorized code flow only).
     */
    private func extractTxCode(grants: ?Grants): ?TxCode {
        match (grants) {
            case Some(Grants.PreAuthCode(pac)) => return pac.txCode
            case Some(Grants.Both(_, pac)) => return pac.txCode
            case _ => return None
        }
    }

    /**
     * Convert the wallet-kit IssuerMetadataPolicy to the openid4vci IssuerMetadataPolicy.
     * Both are the same enum type from the openid4vci package.
     */
    private func toIssuerMetadataPolicy(
        policy: IssuerMetadataPolicy
    ): IssuerMetadataPolicy {
        return policy
    }
}
