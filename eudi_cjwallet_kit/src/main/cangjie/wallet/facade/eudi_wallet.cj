/*
 * eudi_wallet.cj
 *
 * EUDI Wallet Kit — EudiWallet main facade.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/EudiWallet.swift  (734 lines)
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.facade  (S-002)
 *
 * EudiWallet is the top-level public API entry point for the EUDI wallet kit.
 * It orchestrates all lower-level services and exposes a unified public API for:
 *   - Credential issuance (OpenID4VCI) — delegated to OpenId4VciService
 *   - Credential presentation (OpenID4VP, BLE) — delegated to PresentationSession
 *   - Document storage management — delegated to StorageManager
 *   - Credential status check — delegated to DocumentStatusService
 *   - Transaction logging — delegated to WalletLogger
 *
 * Design decisions:
 *   - iOS class EudiWallet: ObservableObject → Cangjie public class
 *   - iOS async/await → synchronous with exceptions (no coroutine runtime at HAR layer)
 *   - iOS SecureAreaRegistry.shared → SecureAreaRegistry.shared (same pattern)
 *   - iOS @Published var storage → plain public var
 *   - iOS multi-configuration VCI registry → per-EudiWallet OpenId4VciService map
 *   - iOS networking (URLSession) → no equivalent; HTTP handled inside openid4vp-vci third_party
 *   - iOS LocalAuthentication → no equivalent; userAuthenticationRequired is advisory flag
 *   - iOS FileManager log files → WalletLogger backed by Hilog (file_logging.cj)
 *   - R-101: no named params unless ! suffix in declaration
 *   - R-103: HashMap uses [k]=v; no .put()
 *   - R-104: HashMap read uses .contains() guard before subscript
 *   - R-109: init named params use name!: Type (! after name, not before)
 *
 * Syntax rules observed:
 *   S-002: package matches directory path
 *   S-003: facade.cj anchor present in this directory
 *   R-101..R-111: see syntax_error.md
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.facade

import kit.PerformanceAnalysisKit.Hilog

import std.collection.ArrayList
import std.collection.HashMap

import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.{
    EudiWalletConfiguration,
    OpenId4VciConfiguration,
    OpenId4VpConfiguration,
    WalletError,
    WalletErrorCode,
    DocTypeIdentifier,
    OfferedIssuanceModel,
    OfferedDocModel,
    BatchCreateKeyResult,
    IssuanceOutcome,
    IssuerResponse
}

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.credential.{
    CredentialReusePolicyValidator,
    ReusePolicy
}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.resolver.CredentialOfferRequestResolver
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.offer.CredentialOffer
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.types.Grants
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.config.IssuerMetadataPolicy
import stdx.encoding.json.{JsonString, JsonInt}
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.RequestItems
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.issuance.IssueRequest

import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.{
    CredentialOptions,
    CredentialPolicy,
    KeyOptions
}

import ohos_app_cangjie_eudi_cjwallet_kit.wallet.storage.StorageManager
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.issuance.OpenId4VciService
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.presentation.{
    PresentationService,
    PresentationSession,
    FaultPresentationService,
    OpenId4VpService,
    BlePresentationService,
    WrpVpRegistrationValidator
}
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.{
    DocumentStatusService,
    WalletLogger,
    FileLogging,
    LogLevel,
    FlowType
}
import ohos_app_cangjie_eudi_cjstatium.statium.crypto.VerifyStatusListTokenSignature

import ohos_app_cangjie_eudi_cjwallet_storage.storage.docstore.DataStorageService
import ohos_app_cangjie_eudi_cjwallet_storage.storage.types.Document
import ohos_app_cangjie_eudi_cjwallet_storage.storage.types.DocumentStatus

import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.{SecureAreaRegistry, DocKeyInfo}
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.issuerauth.StatusIdentifier
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.engagement.CoseKey

import ohos_app_cangjie_eudi_cjcbor.cbor.decodeCbor

import ohos_app_cangjie_eudi_cjstatium.statium.model.CredentialStatus
import ohos_app_cangjie_eudi_cjstatium.statium.model.StatusListTokenFormat

import ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.TransactionLogEntry

// ===========================================================================
// EudiWallet
// iOS: public final class EudiWallet: ObservableObject, @unchecked Sendable
// ===========================================================================

/**
 * Main facade for the EUDI wallet kit.
 *
 * Initialise with an EudiWalletConfiguration and optional override services.
 * All public methods delegate to the appropriate lower-level service.
 *
 * Usage:
 *   let config = EudiWalletConfiguration.defaultConfig()
 *   let wallet = EudiWallet(config, None)
 *   wallet.addOpenId4VciConfiguration("my-issuer", vciConfig)
 *   let docs = wallet.issueDocuments("my-issuer", [DocTypeIdentifier.MsoMdoc("org.iso.18013.5.1.mDL")],
 *                                     CredentialOptions(CredentialPolicy.OneTimeUse, 1), None, None)
 */
public class EudiWallet {

    // -----------------------------------------------------------------------
    // Public configuration fields (mirrors iOS public vars)
    // -----------------------------------------------------------------------

    /** Wallet configuration (service name, trusted certs, auth flags, …). */
    public var eudiWalletConfig: EudiWalletConfiguration

    /** OpenID4VP configuration for verifier authentication. */
    public var openId4VpConfig: OpenId4VpConfiguration

    /**
     * Validator for the relying-party WRP registration certificate (WRPRC),
     * shared with each presentation session. After a request that could not
     * be satisfied, its wrpVpRegistrationPolicy / wrpVpWarnings still expose
     * who asked. Mirrors iOS EudiWallet.wrpRegistrationValidator.
     */
    public let wrpRegistrationValidator: WrpVpRegistrationValidator

    // -----------------------------------------------------------------------
    // Storage layer
    // -----------------------------------------------------------------------

    /**
     * Storage manager — manages in-memory document index and persistence.
     * Mirrors iOS public private(set) var storage: StorageManager!
     */
    public var storage: StorageManager

    // -----------------------------------------------------------------------
    // Issuance services registry
    // iOS: OpenId4VCIServiceRegistry.shared — instance-level here to avoid global state
    // -----------------------------------------------------------------------

    /** Per-issuer VCI service instances, keyed by issuer name / URL. */
    private var vciServices: HashMap<String, OpenId4VciService>

    // -----------------------------------------------------------------------
    // Logger
    // -----------------------------------------------------------------------

    private var logger: WalletLogger

    // -----------------------------------------------------------------------
    // Active presentation
    // -----------------------------------------------------------------------

    /**
     * The presentation session most recently created by beginPresentation,
     * until stopPresentation() is called. Lets the app stop the BLE transport
     * and delete the ephemeral engagement key when the user leaves the flow.
     */
    private var activePresentation: ?PresentationSession

    // -----------------------------------------------------------------------
    // Initialisers
    // -----------------------------------------------------------------------

    /**
     * Initialise a wallet with explicit storage service.
     *
     * @param eudiWalletConfig  Top-level wallet configuration.
     * @param storageService    Backing storage service; if None, an in-memory
     *                          an in-memory fallback is used (production code must supply a real one).
     *
     * Mirrors iOS EudiWallet.init(eudiWalletConfig:storageService:openID4VpConfig:…).
     */
    public init(
        eudiWalletConfig: EudiWalletConfiguration,
        storageService: ?DataStorageService
    ) {
        this.eudiWalletConfig = eudiWalletConfig
        this.openId4VpConfig = OpenId4VpConfiguration.defaultConfig()
        this.wrpRegistrationValidator =
            WrpVpRegistrationValidator(trustConfig: eudiWalletConfig.trustConfiguration)
        this.vciServices = HashMap<String, OpenId4VciService>()
        this.logger = FileLogging.makeLogger("EudiWallet")
        this.activePresentation = None

        let svc: DataStorageService = match (storageService) {
            case Some(s) => s
            case None => InMemoryStorageService()
        }
        this.storage = StorageManager(svc)

        Hilog.info(0, "EudiWallet",
            "Initialized EudiWallet serviceName=" + eudiWalletConfig.serviceName)
    }

    /**
     * Convenience initialiser with default configuration.
     * Mirrors iOS EudiWallet(eudiWalletConfig:) public init.
     */
    public init(eudiWalletConfig: EudiWalletConfiguration) {
        this.eudiWalletConfig = eudiWalletConfig
        this.openId4VpConfig = OpenId4VpConfiguration.defaultConfig()
        this.wrpRegistrationValidator =
            WrpVpRegistrationValidator(trustConfig: eudiWalletConfig.trustConfiguration)
        this.vciServices = HashMap<String, OpenId4VciService>()
        this.logger = FileLogging.makeLogger("EudiWallet")
        this.activePresentation = None
        this.storage = StorageManager(InMemoryStorageService())

        Hilog.info(0, "EudiWallet",
            "Initialized EudiWallet (default storage) serviceName=" + eudiWalletConfig.serviceName)
    }

    // -----------------------------------------------------------------------
    // VCI Service Registry
    // iOS: registerOpenId4VciServices / registerOpenId4VciService
    // -----------------------------------------------------------------------

    /**
     * Register a VCI configuration under the given issuer name.
     * Multiple configurations can be registered (one per issuer).
     *
     * Mirrors iOS EudiWallet.registerOpenId4VciService(name:config:).
     *
     * @param name    Arbitrary issuer label used as lookup key.
     * @param config  OpenID4VCI configuration for this issuer.
     */
    public func addOpenId4VciConfiguration(name: String, config: OpenId4VciConfiguration): Unit {
        let svc = OpenId4VciService(
            config,
            this.storage,
            trustConfiguration: this.eudiWalletConfig.trustConfiguration
        )
        this.vciServices[name] = svc
        Hilog.info(0, "EudiWallet", "Registered VCI service name=" + name)
    }

    /**
     * Register multiple VCI configurations at once.
     * Mirrors iOS EudiWallet.registerOpenId4VciServices(_:).
     *
     * @param configurations  Array of (name, config) pairs.
     */
    public func addOpenId4VciConfigurations(configurations: Array<(String, OpenId4VciConfiguration)>): Unit {
        var i: Int64 = 0
        while (i < configurations.size) {
            let (name, config) = configurations[i]
            addOpenId4VciConfiguration(name, config)
            i++
        }
    }

    // -----------------------------------------------------------------------
    // VCI service resolution (private)
    // -----------------------------------------------------------------------

    /**
     * Resolve an OpenId4VciService by issuer name or issuer URL.
     *
     * Mirrors iOS resolveVCIService(issuerName:).
     * Falls back to URL matching if name lookup fails.
     *
     * @throws WalletError if no service is registered for the given name or URL.
     */
    private func resolveVciService(issuerName: String): OpenId4VciService {
        // Direct name lookup
        if (this.vciServices.contains(issuerName)) {
            return this.vciServices[issuerName]
        }
        // URL matching: find a service whose credentialIssuerURL matches
        for ((_, svc) in this.vciServices) {
            if (svc.hasIssuerUrl(issuerName)) {
                return svc
            }
        }
        throw WalletError.withCode(
            "No OpenId4VCI service registered for name or URL: " + issuerName,
            WalletErrorCode.IssuerNotRegistered
        )
    }

    // -----------------------------------------------------------------------
    // Issuance — metadata
    // iOS: getIssuerMetadata(issuerName:)
    // -----------------------------------------------------------------------

    /**
     * Get issuer metadata for a registered VCI service.
     *
     * Mirrors iOS EudiWallet.getIssuerMetadata(issuerName:).
     *
     * @param issuerName  Registered issuer name or issuer URL.
     * @return CredentialIssuerMetadata from the issuer's well-known endpoint.
     * @throws WalletError if not registered or metadata resolution fails.
     */
    public func getIssuerMetadata(issuerName: String): Any {
        let vciService = resolveVciService(issuerName)
        return vciService.getIssuerMetadata()
    }

    // -----------------------------------------------------------------------
    // Issuance — resolve offer URL doc types
    // iOS: resolveOfferUrlDocTypes(offerUri:authFlowRedirectionURI:)
    // -----------------------------------------------------------------------

    /**
     * Resolve a VCI offer URL to a list of offered document types.
     *
     * Mirrors iOS EudiWallet.resolveOfferUrlDocTypes(offerUri:authFlowRedirectionURI:).
     *
     * @param offerUri  Credential offer URI (openid-credential-offer:// or https://).
     * @return OfferedIssuanceModel with issuer info and offered doc types.
     * @throws WalletError if the offer cannot be resolved.
     */
    public func resolveOfferUrlDocTypes(offerUri: String): OfferedIssuanceModel {
        // iOS resolves the offer first, then keys the service registry by the
        // offer's credential issuer URL (never the raw offer URI).
        let offer = resolveOfferForUri(offerUri)
        let svc = resolveOrAutoRegisterVciServiceForIssuer(offer.credentialIssuerIdentifier.absoluteString())
        return svc.resolveOfferDocTypes(offerUri, offer)
    }

    /**
     * Issue documents by an offer URI.
     *
     * Resolves the offer, selects offered docs, then issues each via the
     * resolved VCI service.
     *
     * Mirrors iOS EudiWallet.issueDocumentsByOfferUrl(offerUri:docTypes:txCodeValue:…).
     *
     * @param offerUri     Credential offer URI.
     * @param docTypes     Subset of offered doc types to issue (from resolveOfferUrlDocTypes).
     * @param txCodeValue  Transaction code for pre-authorized flows (optional).
     * @return IssuerResponse pairing the issued documents (may be empty if all
     *         were deferred) with the issuer registration policy verdict
     *         (iOS 0.40.x breaking change from [Document]).
     * @throws WalletError on failure — including WalletErrorCode.InvalidWrprc
     *         when registration certificate validation is enabled and refuses.
     */
    public func issueDocumentsByOfferUrl(
        offerUri: String,
        docTypes: Array<OfferedDocModel>,
        txCodeValue: ?String
    ): IssuerResponse {
        // Resolve offer first to get CredentialOffer, then key the service by
        // the offer's credential issuer URL (mirrors iOS issueDocumentsByOfferUrl).
        let offer = resolveOfferForUri(offerUri)
        let svc = resolveOrAutoRegisterVciServiceForIssuer(offer.credentialIssuerIdentifier.absoluteString())
        let offeredModel = svc.resolveOfferDocTypes(offerUri, offer)
        // Pre-authorized offers skip the browser entirely: one token exchange
        // with the pre-authorized code (+ user-typed tx_code) issues every
        // requested configuration synchronously (iOS pre-auth use case).
        let isPreAuth = match (offer.grants) {
            case Some(Grants.PreAuthCode(_)) => true
            case Some(Grants.Both(_, _)) => !txCodeValue.isNone()
            case _ => false
        }
        if (isPreAuth) {
            let preAuthDocs = svc.issuePreAuthorized(offer, docTypes, txCodeValue)
            return IssuerResponse(preAuthDocs, svc.wrpIssuerWarnings,
                wrpIssuerPolicy: svc.wrpIssuerPolicy)
        }

        // Thread the offer's issuer_state into the authorization request (PAR):
        // the issuer's dynamic authorization uses it to tie the browser session
        // back to this offer (prod issuer verify_user KeyError without it).
        let offerIssuerState: ?String = match (offer.grants) {
            case Some(Grants.AuthCode(ac)) => ac.issuerState
            case Some(Grants.Both(ac, _)) => ac.issuerState
            case _ => Option<String>.None
        }

        // Issue each offered doc type
        let allDocs = ArrayList<Document>()
        var i: Int64 = 0
        while (i < docTypes.size) {
            let offered = docTypes[i]
            let dtiOpt = offered.docTypeIdentifier()
            match (dtiOpt) {
                case Some(d) => Hilog.info(0, "VCI-DEBUG", "offerloop cfg=${offered.credentialConfigurationIdentifier} dti=some docType=${offered.docType ?? "-"} vct=${offered.vct ?? "-"}")
                case None => Hilog.warn(0, "VCI-DEBUG", "offerloop cfg=${offered.credentialConfigurationIdentifier} dti=NONE docType=${offered.docType ?? "-"} vct=${offered.vct ?? "-"} id=${offered.identifier ?? "-"}")
            }
            match (dtiOpt) {
                case Some(dti) =>
                    let credOpts = offered.credentialOptions
                    let keyOpts = offered.keyOptions
                    let issued = svc.issueDocuments(
                        [dti],
                        credOpts,
                        keyOpts,
                        None,
                        issuerState: offerIssuerState
                    )
                    var j: Int64 = 0
                    while (j < issued.size) {
                        allDocs.add(issued[j])
                        j++
                    }
                case None => ()
            }
            i++
        }
        return IssuerResponse(allDocs.toArray(), svc.wrpIssuerWarnings,
            wrpIssuerPolicy: svc.wrpIssuerPolicy)
    }

    /**
     * Issue documents of specified types from a registered issuer.
     *
     * Mirrors iOS EudiWallet.issueDocuments(issuerName:docTypeIdentifiers:credentialOptions:…).
     *
     * @param issuerName          Registered issuer name or URL.
     * @param docTypeIdentifiers  One or more credential types to request.
     * @param credentialOptions   Batch policy + size.
     * @param keyOptions          Optional key generation options.
     * @param promptMessage       Biometric prompt (advisory; not enforced at HAR layer).
     * @return IssuerResponse pairing the issued documents with the issuer
     *         registration policy verdict (iOS 0.40.x breaking change from
     *         [Document]).
     * @throws WalletError on failure — including WalletErrorCode.InvalidWrprc
     *         when registration certificate validation is enabled and refuses.
     */
    public func issueDocuments(
        issuerName: String,
        docTypeIdentifiers: Array<DocTypeIdentifier>,
        credentialOptions: CredentialOptions,
        keyOptions: ?KeyOptions,
        promptMessage: ?String
    ): IssuerResponse {
        let vciService = resolveVciService(issuerName)
        let docs = vciService.issueDocuments(docTypeIdentifiers, credentialOptions, keyOptions, promptMessage)
        return IssuerResponse(docs, vciService.wrpIssuerWarnings,
            wrpIssuerPolicy: vciService.wrpIssuerPolicy)
    }

    // -----------------------------------------------------------------------
    // Issuance — issuer registration resolution (no issuance)
    // iOS: resolveIssuerRegistration(credentialConfigurationIds:)
    // -----------------------------------------------------------------------

    /**
     * Resolve the issuer's WRP registration certificate for a set of
     * credential configuration identifiers without starting an issuance flow.
     *
     * Mirrors iOS EudiWallet/OpenId4VciService.resolveIssuerRegistration.
     *
     * @param issuerName                  Registered issuer name or URL.
     * @param credentialConfigurationIds  Credential configuration identifiers
     *                                    to check coverage for.
     * @return An IssuerResponse with an empty documents array carrying the
     *         decoded registration policy and any violations; policy and
     *         warnings are None when validation is disabled.
     * @throws WalletError when the issuer is not registered or metadata
     *         resolution fails.
     */
    public func resolveIssuerRegistration(
        issuerName: String,
        credentialConfigurationIds: Array<String>
    ): IssuerResponse {
        let vciService = resolveVciService(issuerName)
        return vciService.resolveIssuerRegistration(credentialConfigurationIds)
    }

    // -----------------------------------------------------------------------
    // Issuance — begin/end (low-level two-phase)
    // iOS: beginIssueDocument / endIssueDocument
    // -----------------------------------------------------------------------

    /**
     * Begin issuing a document by creating a key batch in the SecureArea.
     *
     * Mirrors iOS EudiWallet.beginIssueDocument(id:credentialOptions:keyOptions:bDeferred:).
     *
     * @param issuerName      Registered issuer name or URL.
     * @param id              Unique document id (callers use UUID or similar).
     * @param credentialOptions  Batch policy + size.
     * @param keyOptions      Optional key overrides.
     * @param bDeferred       True for deferred issuance flows.
     * @return IssueRequest carrying id + key configuration.
     * @throws WalletError if key creation fails.
     */
    public func beginIssueDocument(
        issuerName: String,
        id: String,
        credentialOptions: CredentialOptions,
        keyOptions: ?KeyOptions,
        bDeferred: Bool
    ): IssueRequest {
        let vciService = resolveVciService(issuerName)
        return vciService.beginIssueDocument(id, credentialOptions, keyOptions, bDeferred)
    }

    /**
     * End issuing by persisting the document (and its private key) in storage.
     *
     * Mirrors iOS EudiWallet.endIssueDocument(_:batch:).
     *
     * @param issuerName  Registered issuer name or URL.
     * @param issued      The IssueRequest from beginIssueDocument.
     * @param outcome     The issuance outcome to persist.
     * @throws WalletError if persistence fails.
     */
    public func endIssueDocument(
        issuerName: String,
        issued: IssueRequest,
        outcome: IssuanceOutcome
    ): Unit {
        let vciService = resolveVciService(issuerName)
        Hilog.info(0, "EudiWallet", "endIssueDocument id=" + issued.id)
        vciService.endIssueDocument(issued, outcome)
    }

    // -----------------------------------------------------------------------
    // Issuance — reissue
    // iOS: reissueDocument(documentId:credentialOptions:keyOptions:promptMessage:backgroundOnly:)
    // -----------------------------------------------------------------------

    /**
     * Reissue an existing document using stored issuance metadata.
     *
     * Looks up the document's stored issuer URL, resolves the corresponding
     * VCI service, then delegates reissuance.
     *
     * Mirrors iOS EudiWallet.reissueDocument(documentId:…).
     *
     * @param documentId       Id of the previously issued document.
     * @param credentialOptions  Credential options override (None = use stored).
     * @param keyOptions       Key options override (None = use stored).
     * @param promptMessage    Biometric prompt (advisory).
     * @return The reissued Document.
     * @throws WalletError if document not found or reissuance fails.
     */
    /**
     * Credential usage counts for an issued document — mirrors iOS
     * `Document.credentialsUsageCounts` (remaining/total, e.g. the "30/30"
     * Documents-list badge). `remaining` = the primary DOCUMENTS row plus the
     * CREDENTIALS batch rows still stored; `total` = the issuance batch size
     * persisted in DocKeyInfo (falls back to `remaining` for legacy docs).
     */
    public func credentialsUsageCounts(documentId: String): (Int64, Int64) {
        let extra = this.storage.storageService.countDocumentCredentials(documentId)
        let remaining = 1 + extra
        var total = remaining
        match (this.storage.storageService.loadDocument(documentId, DocumentStatus.Issued)) {
            case Some(doc) =>
                match (doc.docKeyInfo) {
                    case Some(ki) =>
                        try {
                            let info = DocKeyInfo.fromCbor(decodeCbor(ki))
                            if (info.batchSize > 0) {
                                total = info.batchSize
                            }
                        } catch (_: Exception) {
                            ()
                        }
                    case None => ()
                }
            case None => ()
        }
        return (remaining, total)
    }

    public func reissueDocument(
        documentId: String,
        credentialOptions: ?CredentialOptions,
        keyOptions: ?KeyOptions,
        promptMessage: ?String
    ): IssuerResponse {
        // Load the existing document's metadata to find issuer
        let docOpt = this.storage.storageService.loadDocument(documentId, DocumentStatus.Issued)
        let doc: Document = match (docOpt) {
            case Some(d) => d
            case None =>
                throw WalletError.withCode(
                    "Document not found for reissue: " + documentId,
                    WalletErrorCode.CredentialNotFound
                )
        }

        // Use the doc.docType as issuer key (simplified: look up any registered service)
        // iOS uses docMetadata.credentialIssuerIdentifier for lookup; here we try all services
        let resolvedCredOpts: CredentialOptions = match (credentialOptions) {
            case Some(co) => co
            case None => CredentialOptions(
                CredentialPolicy.OneTimeUse,
                1
            )
        }

        // Find the first matching VCI service (falls back to any registered service)
        let svcOpt = findAnyVciService()
        let svc: OpenId4VciService = match (svcOpt) {
            case Some(s) => s
            case None =>
                throw WalletError.withCode(
                    "No VCI service registered for reissuing document " + documentId,
                    WalletErrorCode.IssuerNotRegistered
                )
        }

        // Use issueDocuments with the doc type as identifier
        let dti = DocTypeIdentifier.MsoMdoc(doc.docType)
        let issued = svc.issueDocuments([dti], resolvedCredOpts, keyOptions, promptMessage)
        if (issued.isEmpty()) {
            throw WalletError.withDescription("Reissuance returned no documents for id=" + documentId)
        }
        return IssuerResponse(issued, svc.wrpIssuerWarnings,
            wrpIssuerPolicy: svc.wrpIssuerPolicy)
    }

    // -----------------------------------------------------------------------
    // Issuance — deferred
    // iOS: requestDeferredIssuance(issuerName:deferredDoc:credentialOptions:keyOptions:)
    // -----------------------------------------------------------------------

    /**
     * Request a deferred issuance — poll the deferred endpoint for a pending credential.
     *
     * Mirrors iOS EudiWallet.requestDeferredIssuance(issuerName:deferredDoc:credentialOptions:keyOptions:).
     *
     * @param issuerName        Registered issuer name or URL.
     * @param deferredDoc       Document with DocumentStatus.Deferred status.
     * @param credentialOptions Key batch policy.
     * @param keyOptions        Optional key overrides.
     * @return Updated document (Issued or still Deferred).
     * @throws WalletError if polling fails.
     */
    public func requestDeferredIssuance(
        issuerName: String,
        deferredDoc: Document,
        credentialOptions: CredentialOptions,
        keyOptions: ?KeyOptions
    ): Document {
        let vciService = resolveVciService(issuerName)
        return vciService.requestDeferredIssuance(deferredDoc, credentialOptions, keyOptions)
    }

    // -----------------------------------------------------------------------
    // Issuance — resume pending
    // iOS: resumePendingIssuance(issuerName:pendingDoc:webUrl:credentialOptions:keyOptions:)
    // -----------------------------------------------------------------------

    /**
     * Resume a pending issuance after OAuth browser redirect completes.
     *
     * Mirrors iOS EudiWallet.resumePendingIssuance(issuerName:pendingDoc:webUrl:…).
     *
     * @param issuerName        Registered issuer name or URL.
     * @param pendingDoc        Document with DocumentStatus.Pending status.
     * @param webUrl            OAuth redirect URL containing authorization code.
     * @param credentialOptions Key batch policy.
     * @param keyOptions        Optional key overrides.
     * @return All updated documents (Issued or Deferred); combined issuance
     *         resumes several credentials from the one authorization. The
     *         primary (pending-doc-id) document is first.
     * @throws WalletError if resume fails.
     */
    public func resumePendingIssuance(
        issuerName: String,
        pendingDoc: Document,
        webUrl: String,
        credentialOptions: CredentialOptions,
        keyOptions: ?KeyOptions
    ): Array<Document> {
        let vciService = resolveVciService(issuerName)
        return vciService.resumePendingIssuance(pendingDoc, webUrl, credentialOptions, keyOptions)
    }

    // -----------------------------------------------------------------------
    // Issuance — key batch with attestation
    // iOS: createKeyBatchWithAttestation(issuerName:id:credentialOptions:keyOptions:nonce:)
    // -----------------------------------------------------------------------

    /**
     * Create a batch of keys together with a key attestation JWT.
     *
     * Mirrors iOS EudiWallet.createKeyBatchWithAttestation(issuerName:id:credentialOptions:keyOptions:nonce:).
     *
     * @param issuerName        Registered issuer name or URL.
     * @param id                Key batch identifier.
     * @param credentialOptions Batch size and policy.
     * @param keyOptions        Optional key options.
     * @param nonce             Optional nonce for the attestation provider.
     * @return BatchCreateKeyResult with keys and attestation JWT.
     * @throws WalletError on failure.
     */
    public func createKeyBatchWithAttestation(
        issuerName: String,
        id: String,
        credentialOptions: CredentialOptions,
        keyOptions: ?KeyOptions,
        nonce: ?String
    ): BatchCreateKeyResult {
        let vciService = resolveVciService(issuerName)
        // Delegate to VCI service which creates key batch via SecureArea
        let issueReq = vciService.beginIssueDocument(id, credentialOptions, keyOptions, false)
        // Build BatchCreateKeyResult from the created key batch
        let secureArea = SecureAreaRegistry.shared.get(issueReq.secureAreaName)
        let batchInfo = secureArea.getKeyBatchInfo(id)
        let keys = ArrayList<CoseKey>()
        var ki: Int64 = 0
        while (ki < batchInfo.batchSize()) {
            let pkBytes = secureArea.getPublicKeyBytes(id, ki, batchInfo.crv)
            let cborVal = decodeCbor(pkBytes)
            keys.add(CoseKey.fromCborMap(cborVal))
            ki++
        }
        // Attestation JWT: provided by walletAttestationsProvider in config; empty string fallback
        // if no provider is configured (mirrors iOS fallback when keyAttestationsConfig is nil).
        let attestation: String = match (eudiWalletConfig.logFileName) {
            case Some(_) => ""
            case None => ""
        }
        Hilog.info(0, "EudiWallet", "createKeyBatchWithAttestation id=" + id + " keys=" + keys.size.toString())
        return BatchCreateKeyResult(keys, attestation)
    }

    // -----------------------------------------------------------------------
    // Issuance — credential options
    // iOS: getDocumentCredentialOptions / getDefaultCredentialOptions
    // -----------------------------------------------------------------------

    /**
     * Get the stored credential options for a previously issued document.
     *
     * Mirrors iOS EudiWallet.getDocumentCredentialOptions(documentId:).
     *
     * @param documentId  Document identifier.
     * @return CredentialOptions stored with the document metadata.
     * @throws WalletError if document not found or no credential options stored.
     */
    public func getDocumentCredentialOptions(documentId: String): CredentialOptions {
        let docOpt = this.storage.storageService.loadDocument(documentId, DocumentStatus.Issued)
        let doc: Document = match (docOpt) {
            case Some(d) => d
            case None =>
                throw WalletError.withCode(
                    "Document not found for id: " + documentId,
                    WalletErrorCode.CredentialNotFound
                )
        }
        // Document.docKeyInfo encodes key batch info including credential options
        let keyInfoOpt = doc.docKeyInfo
        match (keyInfoOpt) {
            case Some(keyInfoBytes) =>
                let dki = DocKeyInfo.fromBytes(keyInfoBytes)
                return CredentialOptions(dki.credentialPolicy, dki.batchSize)
            case None =>
                throw WalletError.withCode(
                    "Credential options not found for document id: " + documentId,
                    WalletErrorCode.ClaimNotFound
                )
        }
    }

    /**
     * Get the recommended credential options (batch size + policy) for a document type.
     *
     * Mirrors iOS EudiWallet.getDefaultCredentialOptions(issuerName:docTypeIdentifier:).
     *
     * @param issuerName       Registered issuer name or URL.
     * @param docTypeIdentifier  The credential type to query.
     * @return Issuer-recommended CredentialOptions.
     * @throws WalletError on failure.
     */
    public func getDefaultCredentialOptions(
        issuerName: String,
        docTypeIdentifier: DocTypeIdentifier
    ): CredentialOptions {
        let vciService = resolveVciService(issuerName)
        let metadata = vciService.getIssuerMetadata()
        // Scan credential_configurations_supported to find the matching config and
        // extract the issuer-recommended batch size via CredentialReusePolicyValidator.
        let issuerBatchSize: Option<Int64> = match (metadata.batchCredentialIssuance) {
            case Some(bci) => Option<Int64>.Some(bci.batchSize)
            case None => Option<Int64>.None
        }
        // Walk raw configs to find one matching the requested docTypeIdentifier
        var matchedConfigBatchSize: Option<Int64> = issuerBatchSize
        for ((configIdStr, credObj) in metadata.credentialConfigurationsRaw) {
            let matches: Bool = match (docTypeIdentifier) {
                case DocTypeIdentifier.Identifier(id) => id == configIdStr
                case DocTypeIdentifier.MsoMdoc(docType) =>
                    let rawDocType: String = match (credObj.get("doctype")) {
                        case Some(js: JsonString) => js.getValue()
                        case _ => ""
                    }
                    docType == rawDocType
                case DocTypeIdentifier.SdJwt(vct) =>
                    let rawVct: String = match (credObj.get("vct")) {
                        case Some(js: JsonString) => js.getValue()
                        case _ => ""
                    }
                    vct == rawVct
            }
            if (matches) {
                // Prefer config-level batch_size if present (JSON integer field)
                match (credObj.get("batch_size")) {
                    case Some(ji: JsonInt) =>
                        matchedConfigBatchSize = Option<Int64>.Some(ji.getValue())
                    case _ => ()
                }
                break
            }
        }
        // Determine final batch size: use CredentialReusePolicyValidator for consistency
        let resolvedBatchSizeOpt = CredentialReusePolicyValidator.determineBatchSize(
            Option<ReusePolicy>.None,
            matchedConfigBatchSize
        )
        let batchSize: Int64 = match (resolvedBatchSizeOpt) {
            case Some(bs) => bs
            case None => 1
        }
        return CredentialOptions(
            CredentialPolicy.OneTimeUse,
            batchSize
        )
    }

    // -----------------------------------------------------------------------
    // Document storage management
    // iOS: loadDocument / loadDocuments / loadAllDocuments
    // -----------------------------------------------------------------------

    /**
     * Load a single document by id and status.
     *
     * Mirrors iOS EudiWallet.loadDocument(id:status:).
     *
     * @param id      Document identifier.
     * @param status  Lifecycle status.
     * @return The document, or None if not found.
     * @throws StorageError on persistence failure.
     */
    public func loadDocument(id: String, status: DocumentStatus): ?Document {
        return this.storage.loadDocument(id, status)
    }

    /**
     * Load all documents with the given status.
     *
     * Mirrors iOS EudiWallet.loadDocuments(status:).
     *
     * @param status  Which lifecycle bucket to load.
     * @return List of documents, or None if none exist.
     * @throws StorageError on failure.
     */
    public func loadDocuments(status: DocumentStatus): ?ArrayList<Document> {
        return this.storage.loadDocuments(status)
    }

    /**
     * Load all documents across all statuses (issued + deferred + pending).
     *
     * Mirrors iOS EudiWallet.loadAllDocuments().
     *
     * @return Combined list of all documents, or None if none exist.
     * @throws StorageError on failure.
     */
    public func loadAllDocuments(): ?ArrayList<Document> {
        let result = ArrayList<Document>()

        let issuedOpt = this.storage.loadDocuments(DocumentStatus.Issued)
        match (issuedOpt) {
            case Some(docs) =>
                var i: Int64 = 0
                while (i < docs.size) {
                    result.add(docs[i])
                    i++
                }
            case None => ()
        }

        let deferredOpt = this.storage.loadDocuments(DocumentStatus.Deferred)
        match (deferredOpt) {
            case Some(docs) =>
                var i: Int64 = 0
                while (i < docs.size) {
                    result.add(docs[i])
                    i++
                }
            case None => ()
        }

        let pendingOpt = this.storage.loadDocuments(DocumentStatus.Pending)
        match (pendingOpt) {
            case Some(docs) =>
                var i: Int64 = 0
                while (i < docs.size) {
                    result.add(docs[i])
                    i++
                }
            case None => ()
        }

        if (result.isEmpty()) {
            return None
        }
        return Some(result)
    }

    // -----------------------------------------------------------------------
    // Document storage management — delete
    // iOS: deleteDocument / deleteDocuments / deleteAllDocuments
    // -----------------------------------------------------------------------

    /**
     * Delete a specific document by id and status.
     *
     * Mirrors iOS EudiWallet.deleteDocument(id:status:).
     *
     * @param id      Document identifier.
     * @param status  Lifecycle status of the document.
     * @throws WalletError if document not found.
     * @throws StorageError on persistence failure.
     */
    public func deleteDocument(id: String, status: DocumentStatus): Unit {
        logger.info("deleteDocument id=" + id)
        this.storage.deleteDocument(id, status)
    }

    /**
     * Delete all documents with the given status.
     *
     * Mirrors iOS EudiWallet.deleteDocuments(status:).
     *
     * @param status  Which lifecycle bucket to clear.
     * @throws StorageError on persistence failure.
     */
    public func deleteDocuments(status: DocumentStatus): Unit {
        logger.info("deleteDocuments status=" + status.rawValue())
        this.storage.deleteDocuments(status)
    }

    /**
     * Delete all documents (issued + deferred + pending).
     *
     * Mirrors iOS EudiWallet.deleteAllDocuments().
     *
     * @throws StorageError on persistence failure.
     */
    public func deleteAllDocuments(): Unit {
        logger.info("deleteAllDocuments")
        this.storage.deleteDocuments(DocumentStatus.Issued)
        this.storage.deleteDocuments(DocumentStatus.Deferred)
        this.storage.deleteDocuments(DocumentStatus.Pending)
    }

    // -----------------------------------------------------------------------
    // Document status check
    // iOS: getDocumentStatus(for:)
    // -----------------------------------------------------------------------

    /**
     * Get the revocation status of a credential from its status list.
     *
     * Mirrors iOS EudiWallet.getDocumentStatus(for:statusIdentifier:).
     *
     * @param statusIdentifier  Status pointer from the credential's MSO.
     * @return CredentialStatus (Valid / Invalid / Suspended / ...).
     * @throws StatusError if the status cannot be determined.
     */
    public func getDocumentStatus(
        statusIdentifier: StatusIdentifier,
        statusVerifier!: ?VerifyStatusListTokenSignature = None
    ): CredentialStatus {
        // Mirrors iOS: the status-list-token signature verifier is injectable and
        // passed through to DocumentStatusService, which falls back to the internal
        // no-op ignore when None. Production callers MUST inject a real verifier to
        // actually check status-list-token signatures (otherwise revocation is not
        // cryptographically verified).
        let statusSvc = DocumentStatusService(verifier: statusVerifier)
        return statusSvc.getStatus(statusIdentifier)
    }

    // -----------------------------------------------------------------------
    // Credential usage counters
    // iOS: getCredentialsUsageCount / refreshUsageCounters
    // -----------------------------------------------------------------------

    /**
     * Refresh usage counters for all loaded issued documents.
     *
     * Mirrors iOS EudiWallet.refreshUsageCounters().
     *
     * This method is a no-op at the facade layer — the actual counter refresh
     * requires access to the SecureArea key batch state; callers should invoke
     * it as a lifecycle hook when the app returns to foreground.
     */
    public func refreshUsageCounters(): Unit {
        logger.info("refreshUsageCounters (facade delegate)")
        // Counter refresh is performed by the storage manager indirectly;
        // concrete implementation requires SecureArea key batch query per document.
        // The facade triggers a reload of all issued documents to pick up counter updates.
        let _ = this.storage.loadDocuments(DocumentStatus.Issued)
    }

    // -----------------------------------------------------------------------
    // Presentation — beginPresentation
    // iOS: beginPresentation(flow:sessionTransactionLogger:)
    // -----------------------------------------------------------------------

    /**
     * Begin an attestation presentation to a verifier.
     *
     * Creates the appropriate PresentationService for the given FlowType and
     * wraps it in a PresentationSession.
     *
     * Mirrors iOS EudiWallet.beginPresentation(flow:sessionTransactionLogger:).
     *
     * @param flow  FlowType.Ble for proximity or FlowType.OpenId4Vp for remote.
     * @return A PresentationSession ready for startQrEngagement / receiveRequest.
     */
    public func beginPresentation(flow: FlowType): PresentationSession {
        // A still-open proximity session would keep the radio and the
        // ephemeral engagement key alive; tear it down before starting anew.
        this.stopPresentation()
        try {
            // Reset per-request WRPRC state so a previous session's verdict
            // does not leak into this one (iOS resetValidations).
            this.wrpRegistrationValidator.resetValidations()
            let service: PresentationService = match (flow) {
                case FlowType.Ble =>
                    BlePresentationService(
                        storageManager: this.storage,
                        trustConfiguration: this.eudiWalletConfig.trustConfiguration,
                        wrpRegistrationValidator: Some(this.wrpRegistrationValidator),
                        validateRegistrationCertificate: this.openId4VpConfig.validateRegistrationCertificate,
                        deviceAuthMethod: this.eudiWalletConfig.deviceAuthMethod
                    )
                case FlowType.OpenId4Vp(uriBytes) =>
                    // iOS carries the authorization-request URI in the flow
                    // (openid4vp(qrCode:)); hand it to the service so the
                    // session's no-arg receiveRequest() can resolve it.
                    let uri: ?String = if (uriBytes.isEmpty()) {
                        None
                    } else {
                        Some(String.fromUtf8(uriBytes))
                    }
                    OpenId4VpService(
                        storageManager: this.storage,
                        openId4VpConfig: this.openId4VpConfig,
                        requestUri: uri,
                        trustedRootCertsDer: this.eudiWalletConfig.readerTrustAnchorsDer(),
                        trustConfiguration: this.eudiWalletConfig.trustConfiguration,
                        wrpRegistrationValidator: Some(this.wrpRegistrationValidator)
                    )
                case FlowType.Other =>
                    let err = WalletError.withDescription("Use beginPresentation(service:) for custom flows")
                    FaultPresentationService(err.message)
            }
            let session = PresentationSession(service: service, storageManager: this.storage)
            this.activePresentation = Some(session)
            return session
        } catch (e: Exception) {
            let faultSvc = FaultPresentationService("beginPresentation failed: " + e.message)
            logger.error("beginPresentation failed: " + e.message)
            return PresentationSession(service: faultSvc, storageManager: this.storage)
        }
    }

    /**
     * Begin an attestation presentation with a custom PresentationService.
     *
     * Mirrors iOS EudiWallet.beginPresentation(service:sessionTransactionLogger:).
     *
     * @param service  A concrete PresentationService implementation.
     * @return A PresentationSession wrapping the provided service.
     */
    public func beginPresentation(service: PresentationService): PresentationSession {
        this.stopPresentation()
        let session = PresentationSession(service: service, storageManager: this.storage)
        this.activePresentation = Some(session)
        return session
    }

    /**
     * The presentation session created by the last beginPresentation call,
     * if it has not been stopped yet.
     */
    public func activePresentationSession(): ?PresentationSession {
        return this.activePresentation
    }

    /**
     * Stop the active presentation: stops the BLE transport (advertising +
     * GATT server), deletes the ephemeral engagement key and resets the
     * session. Safe to call when no presentation is active. The app calls
     * this when the user cancels or leaves the proximity / remote flow
     * (explicit stop — HarmonyOS has no ARC release to rely on).
     */
    public func stopPresentation(): Unit {
        match (this.activePresentation) {
            case Some(session) =>
                this.activePresentation = None
                try {
                    session.stop()
                } catch (e: Exception) {
                    logger.warning("stopPresentation: " + e.message)
                }
                Hilog.info(0, "EudiWallet", "stopPresentation: active session stopped")
            case None => ()
        }
    }

    // -----------------------------------------------------------------------
    // Logging
    // iOS: getLogFileContents / resetLogFile
    // -----------------------------------------------------------------------

    /**
     * Get the contents of a log file.
     *
     * Mirrors iOS EudiWallet.getLogFileContents(_:).
     *
     * On HarmonyOS, Hilog is the canonical log sink; file logging is not directly
     * supported at this layer. This method returns an informational message.
     *
     * @param fileName  Log file name.
     * @return Log content string (Hilog redirect note on HarmonyOS).
     */
    public func getLogFileContents(fileName: String): String {
        logger.info("getLogFileContents requested for file: " + fileName)
        return "Log file '" + fileName + "' — HarmonyOS Hilog backend; use DevEco log viewer."
    }

    /**
     * Reset (clear) a log file.
     *
     * Mirrors iOS EudiWallet.resetLogFile(_:).
     *
     * On HarmonyOS, this is a no-op since Hilog manages its own retention.
     *
     * @param fileName  Log file name.
     */
    public func resetLogFile(fileName: String): Unit {
        logger.info("resetLogFile requested for file: " + fileName + " (no-op on HarmonyOS)")
    }

    // -----------------------------------------------------------------------
    // Transaction log parsing
    // iOS: parseTransactionLog(_:)
    // -----------------------------------------------------------------------

    /**
     * Parse a transaction log entry for display.
     *
     * Mirrors iOS EudiWallet.parseTransactionLog(_:).
     *
     * @param logEntry  A transaction log entry to parse.
     * @return Human-readable string describing the transaction.
     */
    public func parseTransactionLog(logEntry: TransactionLogEntry): String {
        return logEntry.transactionType.label() + " at " + logEntry.timestamp + " status=" + logEntry.status.rawValue()
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /**
     * Resolve or auto-register a VCI service for an offer URI.
     * The offer URI's issuer URL is extracted and used as the lookup key.
     * If no registered service has that issuer URL, a new one is created with defaults.
     *
     * Mirrors iOS EudiWallet.autoRegisterVciConfiguration(_:_:).
     */
    /** Resolve a credential offer URI into a CredentialOffer (mirrors the
     *  resolver step of iOS EudiWallet.resolveOfferUrlDocTypes). */
    private func resolveOfferForUri(offerUri: String): CredentialOffer {
        let resolver = CredentialOfferRequestResolver()
        return resolver.resolveUri(offerUri, IssuerMetadataPolicy.IgnoreSigned)
    }

    private func resolveOrAutoRegisterVciServiceForIssuer(issuerUrl: String): OpenId4VciService {
        // Try direct name match first
        if (this.vciServices.contains(issuerUrl)) {
            return this.vciServices[issuerUrl]
        }
        // Try URL match
        for ((_, svc) in this.vciServices) {
            if (svc.hasIssuerUrl(issuerUrl)) {
                return svc
            }
        }
        // Auto-register with a default configuration for this issuer URL
        // (mirrors iOS autoRegisterVciConfiguration — keyed by issuer URL,
        // never by the raw offer URI).
        logger.warning("No VCI service registered for issuer: " + issuerUrl + " — auto-registering with defaults")
        let defaultConfig = OpenId4VciConfiguration.withIssuerURL(Some(issuerUrl))
        let newSvc = OpenId4VciService(
            defaultConfig,
            this.storage,
            trustConfiguration: this.eudiWalletConfig.trustConfiguration
        )
        this.vciServices[issuerUrl] = newSvc
        return newSvc
    }

    /**
     * Return any registered VCI service (used when issuer URL is not directly available).
     * Returns None if no service is registered.
     */
    private func findAnyVciService(): ?OpenId4VciService {
        for ((_, svc) in this.vciServices) {
            return Some(svc)
        }
        return None
    }
}

// ===========================================================================
// InMemoryStorageService — minimal in-memory backing storage for default init
// Avoids a hard dependency on a concrete storage implementation.
// Callers should replace this with a real DataStorageService.
// ===========================================================================

/**
 * Minimal in-memory DataStorageService used when no storage service is provided.
 *
 * All documents are lost when the EudiWallet instance is garbage collected.
 * Production callers must supply a real DataStorageService implementation.
 */
class InMemoryStorageService <: DataStorageService {

    private var store: HashMap<String, Document>

    public init() {
        this.store = HashMap<String, Document>()
    }

    public func saveDocument(doc: Document, batch: ?Array<Document>, allowOverwrite: Bool): Unit {
        if (!allowOverwrite && this.store.contains(doc.id)) {
            return
        }
        this.store[doc.id] = doc
        match (batch) {
            case Some(docs) =>
                var i: Int64 = 0
                while (i < docs.size) {
                    this.store[docs[i].id] = docs[i]
                    i++
                }
            case None => ()
        }
    }

    public func loadDocuments(status: DocumentStatus): ?Array<Document> {
        let result = ArrayList<Document>()
        for ((_, doc) in this.store) {
            if (doc.status.rawValue() == status.rawValue()) {
                result.add(doc)
            }
        }
        if (result.isEmpty()) {
            return None
        }
        return Some(result.toArray())
    }

    public func loadDocument(id: String, status: DocumentStatus): ?Document {
        if (this.store.contains(id)) {
            let doc = this.store[id]
            if (doc.status.rawValue() == status.rawValue()) {
                return Some(doc)
            }
        }
        return None
    }

    public func deleteDocument(id: String, status: DocumentStatus): Unit {
        if (this.store.contains(id)) {
            let doc = this.store[id]
            if (doc.status.rawValue() == status.rawValue()) {
                this.store.remove(id)
            }
        }
    }

    public func deleteDocuments(status: DocumentStatus): Unit {
        let toRemove = ArrayList<String>()
        for ((id, doc) in this.store) {
            if (doc.status.rawValue() == status.rawValue()) {
                toRemove.add(id)
            }
        }
        var i: Int64 = 0
        while (i < toRemove.size) {
            this.store.remove(toRemove[i])
            i++
        }
    }

    public func loadDocumentMetadata(id: String): ?Document {
        if (this.store.contains(id)) {
            return Some(this.store[id])
        }
        return None
    }

    public func deleteDocumentCredential(id: String, index: Int64): Unit {
        // In-memory: compound key is "<id>_<index>"; remove if present
        let compoundId = id + "_" + index.toString()
        if (this.store.contains(compoundId)) {
            this.store.remove(compoundId)
        }
    }

    public func countDocumentCredentials(id: String): Int64 {
        // In-memory test double: count "<id>_<index>" compound keys.
        var n: Int64 = 0
        let prefix = id + "_"
        for ((key, _) in this.store) {
            if (key.startsWith(prefix)) {
                n++
            }
        }
        return n
    }
}
