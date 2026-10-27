/*
 * openid4vp_service.cj
 *
 * EUDI Wallet Kit — OpenID4VP remote presentation service.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Services/OpenId4VpService.swift
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.presentation
 *
 * Implements PresentationService for remote OpenID4VP presentation flows:
 *   1. receiveRequest()  — resolve authorization request via AuthorizationRequestResolver
 *   2. sendResponse()    — build DCQL VP token, dispatch via Dispatcher
 *
 * Upstream dependencies:
 *   - openid4vp-vci: AuthorizationRequestResolver, Dispatcher, DCQL, DcqlVpContent, etc.
 *   - mdoc-data-model: DocClaimsDecodable (via storageManager.docModels)
 *   - wallet.storage: StorageManager (for looking up stored credentials)
 *   - wallet.support: DcqlQueryable, DefaultDcqlQueryable
 *   - wallet.presentation: Openid4VpUtils, PresentationService
 *
 * Design decisions:
 *   - iOS async throws → synchronous with exceptions
 *   - iOS OpenID4VP engine → openid4vp-vci AuthorizationRequestResolver/Dispatcher
 *   - DCQL resolution: per-query DcqlQueryable (from stored credential claim maps)
 *   - BLE DeviceEngagement: None (remote flow uses OID4VP handover only)
 *   - mdocGeneratedNonce generated locally and included in SessionTranscript handover
 *   - Credential bytes: retrieved from storageService.loadDocuments() → Document.data
 *     (DocClaimsDecodable does NOT expose raw credential bytes)
 *
 * R-101: init named params use ! prefix in declarations.
 * R-103: HashMap uses subscript assignment.
 * R-104: HashMap reads use .contains() guard.
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.presentation

import kit.PerformanceAnalysisKit.Hilog

import eudi_lib_core_crypto.Base64Url

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.resolver.AuthorizationRequestResolver
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.service.Dispatcher
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.service.AcceptedOutcome
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.service.RejectedOutcome
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.request.AuthorizationRequest
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.request.UnvalidatedRequest
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.request.NotSecuredRequest
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.request.JwtRequest
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.request.InvalidResolution
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.request.ResolvedRequestData
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.request.VpTokenData
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.network.HttpFetcher
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.DCQL
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.CredentialQuery
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.ClaimsQuery
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.ClaimPath
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.VerifiablePresentation
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.GenericPresentation
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.types.DirectPost
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.types.DirectPostJWT
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.config.OpenId4VPWalletConfiguration
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.config.X509CertificateTrust
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.client.ClientIdPrefix
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.response.AuthorizationResponse
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.response.ClientConsent
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.response.VpTokenConsent
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.response.NegativeConsent
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.response.DcqlVpContent
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.response.ApuParam
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.response.EncryptionParameters

import ohos_app_cangjie_eudi_cjwallet_storage.storage.types.Document
import ohos_app_cangjie_eudi_cjwallet_storage.storage.types.DocumentStatus

import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.WalletError
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.WalletErrorCode
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.ClientIdScheme
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.OpenId4VpConfiguration
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.RequestItems
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.{WrpRegistrationPolicy, PresentationPolicyViolation}
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.RegistrationCertificateAuthorization
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.error.VpValidationError
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.storage.StorageManager
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.FlowType

import ohos_app_cangjie_eudi_cjmdoc_security.security.session.SessionTranscript
import ohos_app_cangjie_eudi_cjmdoc_transfer.transfer.framing.UserRequestInfo
import ohos_app_cangjie_eudi_cjmdoc_transfer.transfer.framing.RequestItem

import ohos_app_cangjie_eudi_cjetsi_1196x2.etsi_trust.TrustConfiguration
import std.collection.ArrayList
import std.collection.HashMap

class AccessManagerX509Trust <: X509CertificateTrust {
    private let trustConfiguration: TrustConfiguration

    public init(trustConfiguration: TrustConfiguration) {
        this.trustConfiguration = trustConfiguration
    }

    public func isTrusted(chainDer: Array<Array<UInt8>>): Bool {
        let (ok, reason) = this.trustConfiguration.accessTrustManager.validateCertTrustPath(chainDer)
        if (!ok) {
            match (reason) {
                case Some(r) => Hilog.warn(0, "OpenId4VpService", "reader x5c not trusted: ${r}")
                case None => Hilog.warn(0, "OpenId4VpService", "reader x5c not trusted")
            }
        }
        ok
    }
}

// ===========================================================================
// OpenId4VpService — remote OpenID4VP presentation
// Mirrors iOS class OpenId4VpService: PresentationService
// ===========================================================================

/**
 * Presentation service implementing OpenID4VP remote presentation.
 *
 * Flow:
 *   1. Caller invokes receiveRequest(uri) — resolves authorization request.
 *   2. Caller inspects UserRequestInfo, selects documents.
 *   3. Caller invokes sendResponse(userSelected) — builds DCQL VP tokens,
 *      dispatches via Dispatcher (HTTP direct_post).
 */
public class OpenId4VpService <: PresentationService {

    // -----------------------------------------------------------------------
    // Fields
    // -----------------------------------------------------------------------

    private let storageManager: StorageManager
    private let openId4VpConfig: OpenId4VpConfiguration
    private let resolver: AuthorizationRequestResolver

    /** Resolved request data from the most recent receiveRequest() call. */
    private var resolvedRequestData: ?ResolvedRequestData

    /** Generated mdocGeneratedNonce for the current session. */
    private var mdocGeneratedNonce: ?String

    /** Transaction log for the current session. */
    private var txLog: TransactionLog

    /** Authorization-request URI handed over at construction (iOS carries it in
     *  FlowType.openid4vp(qrCode:)); consumed by the no-arg receiveRequest(). */
    private var pendingRequestUri: ?String

    /** OpenID4VP session transcript / verifier identity captured at
     *  receiveRequest time — consumed by the holder-binding proof builders. */
    private var vpSessionTranscript: ?SessionTranscript = None
    private var vpClientId: String = ""
    private var vpNonce: String = ""

    /** DER-encoded trust anchors for verifier x5c chain validation (the wallet's
     *  trustedReaderRootCertificates — iOS hands the same set to its OpenID4VP
     *  engine); fail-closed resolver rejects x509_* clients without them. */
    private let trustedRootCertsDer: ?Array<Array<UInt8>>
    private let trustConfiguration: ?TrustConfiguration

    /** Validator for the relying-party WRPRC (shared with the wallet facade so
     *  the app layer can read wrpVpRegistrationPolicy after a failed request). */
    private let wrpRegistrationValidator: ?WrpVpRegistrationValidator

    // -----------------------------------------------------------------------
    // Initialiser
    // -----------------------------------------------------------------------

    public init(
        storageManager!: StorageManager,
        openId4VpConfig!: OpenId4VpConfiguration,
        requestUri!: ?String = None,
        trustedRootCertsDer!: ?Array<Array<UInt8>> = None,
        trustConfiguration!: ?TrustConfiguration = None,
        wrpRegistrationValidator!: ?WrpVpRegistrationValidator = None
    ) {
        this.storageManager = storageManager
        this.openId4VpConfig = openId4VpConfig
        this.resolver = AuthorizationRequestResolver()
        this.resolvedRequestData = None
        this.mdocGeneratedNonce = None
        this.txLog = TransactionLog()
        this.pendingRequestUri = requestUri
        this.trustedRootCertsDer = trustedRootCertsDer
        this.trustConfiguration = trustConfiguration
        this.wrpRegistrationValidator = wrpRegistrationValidator
    }

    // -----------------------------------------------------------------------
    // PresentationService implementation
    // -----------------------------------------------------------------------

    public func flow(): FlowType {
        match (this.pendingRequestUri) {
            case Some(uri) => return FlowType.OpenId4Vp(uri.toArray())
            case None => return FlowType.OpenId4Vp(Array<UInt8>())
        }
    }

    /**
     * OpenID4VP is a remote flow — no QR engagement needed.
     * Returns empty string (no-op).
     */
    public func startQrEngagement(): String {
        return ""
    }

    /**
     * Interface-required receiveRequest() — resolves the URI handed over at
     * construction (iOS gets it from FlowType.openid4vp(qrCode:)). Throws when
     * the service was built without a URI.
     */
    public func receiveRequest(): UserRequestInfo {
        match (this.pendingRequestUri) {
            case Some(uri) => return receiveRequest(uri)
            case None =>
                throw WalletError.withDescription(
                    "OpenId4VpService.receiveRequest() requires a URI. Use receiveRequest(uri:) instead."
                )
        }
    }

    /**
     * Resolve an OpenID4VP authorization request from a URI.
     *
     * @param uri — the openid4vp:// or eudi-openid4vp:// URI from the QR code / deep link
     * @return UserRequestInfo with requested documents/claims
     *
     * Mirrors iOS OpenId4VpService.receiveRequest() — which gets the URI from the wallet
     * controller context.
     */
    public func receiveRequest(uri: String): UserRequestInfo {
        // Generate per-session mdoc nonce
        let nonce = Openid4VpUtils.generateMdocGeneratedNonce()
        this.mdocGeneratedNonce = Some(nonce)

        // Build wallet configuration for the resolver
        let walletConf = buildWalletConfiguration()

        // Parse the URI into an UnvalidatedRequest
        let unvalidated = UnvalidatedRequest.make(uri)

        // Resolve to AuthorizationRequest
        // request_uri (pass-by-reference) requests need an HTTP fetcher to GET
        // the request JWT — without it the resolver fails ValidationError.
        let authRequest = this.resolver.resolve(walletConf, unvalidated, httpFetcher: Some(HttpFetcher()))

        // Handle the resolution result
        match (authRequest) {
            case nr: NotSecuredRequest =>
                return handleRequestData(nr.data)
            case jr: JwtRequest =>
                return handleRequestData(jr.request)
            case ir: InvalidResolution =>
                let errMsg = ir.error.message
                Hilog.error(0, "OpenId4VpService",
                    "Authorization request resolution failed: " + errMsg)
                throw WalletError.withDescription("OpenID4VP resolution failed: " + errMsg)
            case _ =>
                throw WalletError.withDescription("OpenID4VP: unexpected authorization request type")
        }
    }

    /**
     * Send VP token response for the user-selected documents.
     *
     * Builds DCQL verifiable presentations from the selected RequestItems,
     * creates AuthorizationResponse, and dispatches via Dispatcher.
     *
     * Mirrors iOS OpenId4VpService.sendResponse(userSelected:)
     */
    public func sendResponse(
        userSelected: RequestItems,
        onSuccess: ?((String) -> Unit),
        onCancel: ?(String) -> Unit
    ): Unit {
        let rrd = match (this.resolvedRequestData) {
            case None =>
                throw WalletError.withDescription(
                    "OpenId4VpService.sendResponse: no resolved request; call receiveRequest first")
            case Some(rrd) => rrd
        }

        // Build the DCQL VP content from user-selected items
        let vpContentOpt = buildDcqlVpContent(rrd, userSelected)
        let consent: ClientConsent = match (vpContentOpt) {
            case None =>
                NegativeConsent("No verifiable presentations could be built")
            case Some(vpContent) =>
                VpTokenConsent(vpContent)
        }

        // Determine encryption parameters from resolved request
        let encParams: ?EncryptionParameters = buildEncryptionParameters(rrd)

        // Build AuthorizationResponse from consent
        let authResponse = AuthorizationResponse.fromConsent(
            resolvedRequest: rrd,
            consent: consent,
            encryptionParameters: encParams
        )

        // Dispatch via Dispatcher
        let dispatcher = Dispatcher(authorizationResponse: authResponse)
        let outcome = dispatcher.dispatch()

        match (outcome) {
            case ao: AcceptedOutcome =>
                let redirectUri = match (ao.redirectUri) {
                    case Some(uri) => uri
                    case None => ""
                }
                this.txLog.add("sendResponse", "accepted redirect=" + redirectUri)
                match (onSuccess) {
                    case Some(cb) => cb(redirectUri)
                    case None => ()
                }
            case ro: RejectedOutcome =>
                this.txLog.add("sendResponse", "rejected reason=" + ro.reason)
                match (onCancel) {
                    case Some(cb) => cb(ro.reason)
                    case None => ()
                }
            case _ =>
                match (onCancel) {
                    case Some(cb) => cb("Unknown dispatch outcome")
                    case None => ()
                }
        }
    }

    public func transactionLog(): ?TransactionLog {
        return Some(this.txLog)
    }

    public func zkpDocumentIds(): Array<String> {
        return Array<String>()
    }

    /**
     * Verifier display name = the resolved client's certificate subject CN
     * (e.g. "Verifier Signer dev"), mirroring iOS OpenId4VpService which shows
     * getCN(from: x509.subject). (legalName() surfaces the Organization instead
     * — "Niscy" — which diverged from iOS.) None before the request resolves.
     */
    public func readerCertIssuerName(): ?String {
        match (this.resolvedRequestData) {
            case Some(rrd) =>
                try {
                    return rrd.request.client.commonName()
                } catch (_: Exception) {
                    return None
                }
            case None => return None
        }
    }

    /**
     * Reader trust = the request resolved with an x509 client. The resolver is
     * fail-closed (buildWalletConfiguration hands it trustedRootCertsPem and
     * rejects x509 clients whose x5c chain does not validate), so once a
     * resolvedRequestData carries an x509_* client the reader chain has already
     * been verified against the wallet's trusted reader anchors. Mirrors iOS
     * `readerAuthValidated`.
     */
    public func readerCertIssuerValid(): Bool {
        match (this.resolvedRequestData) {
            case Some(rrd) =>
                try {
                    return rrd.request.client.id().clientId().startsWith("x509_")
                } catch (_: Exception) {
                    return false
                }
            case None => return false
        }
    }

    public func wrpVerifierPolicy(): ?WrpRegistrationPolicy {
        match (this.wrpRegistrationValidator) {
            case Some(validator) => return validator.wrpVpRegistrationPolicy
            case None => return None
        }
    }

    public func wrpVerifierWarnings(): ?HashMap<String, Array<PresentationPolicyViolation>> {
        if (!this.openId4VpConfig.validateRegistrationCertificate) {
            return None
        }
        match (this.wrpRegistrationValidator) {
            case Some(validator) => return Some(validator.wrpVpWarnings)
            case None => return None
        }
    }

    public func readerCertificateChainDer(): ?Array<Array<UInt8>> {
        match (this.resolvedRequestData) {
            case Some(rrd) =>
                match (rrd.request.client.leafCertificate()) {
                    case Some(leaf) =>
                        try {
                            return Some([leaf.toDer()])
                        } catch (_: Exception) {
                            return None
                        }
                    case None => return None
                }
            case None => return None
        }
    }

    /**
     * Stop the remote presentation: drop the resolved request and the
     * holder-binding session state so a stale request cannot be answered.
     * There is no transport to tear down for OpenID4VP (synchronous HTTP).
     * Mirrors iOS PresentationService.stop() for the remote flow.
     */
    public func stop(): Unit {
        this.resolvedRequestData = None
        this.mdocGeneratedNonce = None
        this.vpSessionTranscript = None
        this.vpClientId = ""
        this.vpNonce = ""
        Hilog.info(0, "OpenId4VpService", "stop: request state cleared")
    }

    public func waitForDisconnect(): Unit {
        // Remote flow: no persistent connection to wait for
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /**
     * Build OpenId4VPWalletConfiguration from EudiWallet OpenId4VpConfiguration.
     * Mirrors iOS OpenId4VpService.getWalletConf().
     */
    private func buildWalletConfiguration(): OpenId4VPWalletConfiguration {
        let schemes = ArrayList<ClientIdPrefix>()
        var i: Int64 = 0
        while (i < this.openId4VpConfig.clientIdSchemes.size) {
            let scheme = this.openId4VpConfig.clientIdSchemes[i]
            match (scheme) {
                case ClientIdScheme.Preregistered(_) =>
                    schemes.add(ClientIdPrefix.PreRegistered)
                case ClientIdScheme.X509SanDns =>
                    schemes.add(ClientIdPrefix.X509SanDns)
                case ClientIdScheme.X509Hash =>
                    schemes.add(ClientIdPrefix.X509Hash)
                case ClientIdScheme.RedirectUri =>
                    schemes.add(ClientIdPrefix.RedirectUri)
            }
            i += 1
        }
        if (schemes.isEmpty()) {
            schemes.add(ClientIdPrefix.PreRegistered)
        }
        let liveTrust: ?X509CertificateTrust = match (this.trustConfiguration) {
            case Some(cfg) => Some(AccessManagerX509Trust(cfg))
            case None => None
        }
        return OpenId4VPWalletConfiguration(
            supportedClientIdSchemes: schemes.toArray(),
            trustedRootCertsPem: derCertsToPem(this.trustedRootCertsDer),
            x509ChainTrust: liveTrust
        )
    }

    /** DER trust anchors → one concatenated PEM string (Cert.fromPem input);
     *  None / empty → None, keeping the resolver's fail-closed behaviour. */
    private static func derCertsToPem(certs: ?Array<Array<UInt8>>): ?String {
        match (certs) {
            case None => return None
            case Some(list) =>
                if (list.isEmpty()) { return None }
                var pem = ""
                for (der in list) {
                    pem = pem + "-----BEGIN CERTIFICATE-----\n"
                    let b64 = base64StdEncode(der)
                    var i: Int64 = 0
                    while (i < b64.size) {
                        let end = if (i + 64 < b64.size) { i + 64 } else { b64.size }
                        pem = pem + b64[i..end] + "\n"
                        i = end
                    }
                    pem = pem + "-----END CERTIFICATE-----\n"
                }
                return Some(pem)
        }
    }

    /** Standard (RFC 4648) base64 with padding — PEM bodies require +/ and =,
     *  which Base64Url deliberately does not produce. */
    private static func base64StdEncode(data: Array<UInt8>): String {
        let table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        let chars = table.toArray()
        let out = ArrayList<UInt8>()
        var i: Int64 = 0
        while (i + 2 < data.size) {
            let n = (UInt32(data[i]) << 16) | (UInt32(data[i + 1]) << 8) | UInt32(data[i + 2])
            out.add(chars[Int64((n >> 18) & 63)])
            out.add(chars[Int64((n >> 12) & 63)])
            out.add(chars[Int64((n >> 6) & 63)])
            out.add(chars[Int64(n & 63)])
            i += 3
        }
        let rem = data.size - i
        if (rem == 1) {
            let n = UInt32(data[i]) << 16
            out.add(chars[Int64((n >> 18) & 63)])
            out.add(chars[Int64((n >> 12) & 63)])
            out.add(b'=')
            out.add(b'=')
        } else if (rem == 2) {
            let n = (UInt32(data[i]) << 16) | (UInt32(data[i + 1]) << 8)
            out.add(chars[Int64((n >> 18) & 63)])
            out.add(chars[Int64((n >> 12) & 63)])
            out.add(chars[Int64((n >> 6) & 63)])
            out.add(b'=')
        }
        return String.fromUtf8(out.toArray())
    }

    /**
     * Extract DCQL from resolved request and build a synthetic UserRequestInfo.
     * Mirrors iOS OpenId4VpService.handleRequestData(_:).
     */
    private func handleRequestData(rrd: ResolvedRequestData): UserRequestInfo {
        this.resolvedRequestData = Some(rrd)

        // Capture verifier identity + build the OpenID4VP SessionTranscript for
        // the holder-binding proofs (mdoc DeviceAuth / SD-JWT KB-JWT).
        this.vpClientId = rrd.request.client.id().clientId()
        this.vpNonce = rrd.request.nonce
        let responseUri: String = match (rrd.request.responseMode) {
            case Some(dpj: DirectPostJWT) => dpj.responseUri
            case Some(dp: DirectPost) => dp.responseUri
            case _ => ""
        }
        let jwksJson: ?String = match (rrd.request.clientMetaData) {
            case Some(meta) => meta.jwkSetJson
            case None => None
        }
        let thumbprint = Oid4VpDeviceAuth.encryptionJwkThumbprint(jwksJson)
        let tpLen = match (thumbprint) { case Some(t) => t.size; case None => -1 }
        Hilog.info(0, "VPFLOW", "transcript clientId=" + this.vpClientId +
            " responseUri=" + responseUri + " nonce=" + this.vpNonce + " tpLen=" + tpLen.toString())
        this.vpSessionTranscript = Some(Oid4VpDeviceAuth.buildSessionTranscript(
            this.vpClientId, responseUri, this.vpNonce, thumbprint))

        // Extract DCQL from the request
        let dcqlOpt = rrd.dcql()
        let dcql = match (dcqlOpt) {
            case None =>
                throw WalletError.withDescription(
                    "OpenID4VP: only DCQL queries supported (PresentationDefinition not supported)")
            case Some(d) => d
        }

        // Validate the relying-party WRPRC (registration certificate) when
        // enabled — mirrors iOS OpenId4VpService authorize path with
        // registrationCertificatePolicy configured.
        validateVerifierRegistration(rrd, dcql)

        // Parse format info
        let formatEntries = Openid4VpUtils.parseDcqlFormats(dcql)

        // Build UserRequestInfo from DCQL credential queries
        // itemsRequested: Array<(String, Array<RequestItem>)> — docType → items
        let items = ArrayList<(String, Array<RequestItem>)>()
        var i: Int64 = 0
        while (i < formatEntries.size) {
            let entry = formatEntries[i]
            let credQuery = findCredentialQuery(dcql, entry.queryId)
            var requestItems: ArrayList<RequestItem> = ArrayList<RequestItem>()
            match (credQuery) {
                case Some(cq) =>
                    match (cq.claims) {
                        case Some(claims) =>
                            requestItems = Openid4VpUtils.getRequestItems(claims, false)
                        case None =>
                            requestItems = ArrayList<RequestItem>()
                    }
                case None => ()
            }
            let docType = match (entry.docType) {
                case Some(dt) => dt
                case None => entry.queryId
            }
            items.add((docType, requestItems.toArray()))
            i += 1
        }

        return UserRequestInfo(Array<UInt8>(), items.toArray())
    }

    /**
     * WRPRC validation for the resolved request. No-op when
     * validateRegistrationCertificate is disabled or no validator was
     * injected. A missing WRPRC records a request-level violation (Warning
     * policy) or blocks the request (Enforce). A NotGranted verdict throws
     * WalletError(InvalidWrprc) wrapping VpValidationError
     * AuthorizationPolicyNotMet — the marker the app layer detects.
     */
    private func validateVerifierRegistration(rrd: ResolvedRequestData, dcql: DCQL): Unit {
        if (!this.openId4VpConfig.validateRegistrationCertificate) {
            return
        }
        let validator: WrpVpRegistrationValidator = match (this.wrpRegistrationValidator) {
            case Some(v) => v
            case None => return
        }
        let wrpac = rrd.request.client.leafCertificate()
        let verdict: RegistrationCertificateAuthorization = match (rrd.registrationCertificate()) {
            case Some(wrprc) => validator.validateCertificate(wrpac, wrprc, Some(dcql))
            case None => validator.recordMissingCertificate("verifier_info missing")
        }
        match (verdict) {
            case RegistrationCertificateAuthorization.Granted => ()
            case RegistrationCertificateAuthorization.NotGranted(reason) =>
                Hilog.error(0, "OpenId4VpService",
                    "WRPRC policy not met: " + reason)
                throw WalletError.withInner(
                    "OpenID4VP request error: " + reason,
                    WalletErrorCode.InvalidWrprc,
                    VpValidationError.AuthorizationPolicyNotMet(reason)
                )
        }
    }

    /**
     * Find a CredentialQuery in a DCQL by queryId.
     */
    private func findCredentialQuery(dcql: DCQL, queryId: String): ?CredentialQuery {
        var i: Int64 = 0
        while (i < dcql.credentials.size) {
            if (dcql.credentials[i].queryId.value == queryId) {
                return Some(dcql.credentials[i])
            }
            i += 1
        }
        return None
    }

    /**
     * Build DCQL VP content from user-selected documents.
     * Mirrors iOS OpenId4VpService.SendVpTokens().
     *
     * For each DCQL credential query, looks up the matching document in
     * StorageManager, retrieves raw credential bytes from storageService,
     * generates a VP token (CBOR base64url for mDoc, SD-JWT string for SD-JWT),
     * and places it in the DcqlVpContent map.
     */
    private func buildDcqlVpContent(
        rrd: ResolvedRequestData,
        userSelected: RequestItems
    ): ?DcqlVpContent {
        let dcqlOpt = rrd.dcql()
        let dcql = match (dcqlOpt) {
            case None => return None
            case Some(d) => d
        }

        let formatEntries = Openid4VpUtils.parseDcqlFormats(dcql)
        let vpMap = HashMap<String, Array<VerifiablePresentation>>()

        // Load all issued documents from storage service once
        let issuedDocsOpt = this.storageManager.loadDocuments(DocumentStatus.Issued)

        var i: Int64 = 0
        while (i < formatEntries.size) {
            let entry = formatEntries[i]
            let queryId = entry.queryId
            let fmt = entry.format
            let docType = match (entry.docType) {
                case Some(dt) => dt
                case None => queryId
            }

            // Find items selected for this credential. The request UI keys its
            // selection by the STORED document id (disclosedDocuments surfaces
            // storage ids); accept a direct docType key too for callers that
            // still key by type.
            var selKey: ?String = None
            var selDocId: ?String = None
            if (userSelected.contains(docType)) {
                selKey = Some(docType)
            } else {
                match (issuedDocsOpt) {
                    case Some(docs) =>
                        for (doc in docs) {
                            if (doc.docType == docType && userSelected.contains(doc.id)) {
                                selKey = Some(doc.id)
                                selDocId = Some(doc.id)
                                break
                            }
                        }
                    case None => ()
                }
            }
            let selectedNsItems = match (selKey) {
                case None =>
                    Hilog.warn(0, "OpenId4VpService",
                        "No selected items for docType=" + docType)
                    i += 1
                    continue
                case Some(k) => userSelected[k]
            }

            // Build VP token bytes based on format
            let vpTokenOpt = buildVpToken(fmt, docType, selDocId, selectedNsItems, rrd, issuedDocsOpt)
            match (vpTokenOpt) {
                case Some(vpToken) =>
                    vpMap[queryId] = [GenericPresentation(vpToken)]
                case None =>
                    Hilog.warn(0, "OpenId4VpService",
                        "Failed to build VP token for queryId=" + queryId)
            }
            i += 1
        }

        if (vpMap.isEmpty()) {
            return None
        }
        return Some(DcqlVpContent(vpMap))
    }

    /**
     * Build a single VP token string for the given format and docType.
     *
     * For mso_mdoc: builds a CBOR DeviceResponse (base64url-encoded).
     * For vc+sd-jwt / dc+sd-jwt: retrieves the SD-JWT token from the credential.
     */
    private func buildVpToken(
        format: String,
        docType: String,
        selectedDocId: ?String,
        nsItems: HashMap<String, Array<RequestItem>>,
        rrd: ResolvedRequestData,
        issuedDocs: ?ArrayList<Document>
    ): ?String {
        if (format == "mso_mdoc") {
            return buildMdocVpToken(docType, selectedDocId, nsItems, rrd, issuedDocs)
        } else if (format == "vc+sd-jwt" || format == "dc+sd-jwt") {
            return buildSdJwtVpToken(docType, selectedDocId, issuedDocs)
        } else {
            Hilog.warn(0, "OpenId4VpService",
                "Unsupported VP format: " + format)
            return None
        }
    }

    /**
     * Build a CBOR mso_mdoc DeviceResponse VP token.
     *
     * Retrieves the raw IssuerSigned CBOR bytes (Document.data) from the storage
     * service, wraps it in OID4VP handover context, and returns a base64url-encoded
     * presentation string.
     *
     * Mirrors iOS OpenId4VpService.makeCborClaimData / buildDeviceResponse.
     */
    private func buildMdocVpToken(
        docType: String,
        selectedDocId: ?String,
        nsItems: HashMap<String, Array<RequestItem>>,
        rrd: ResolvedRequestData,
        issuedDocs: ?ArrayList<Document>
    ): ?String {
        // Prefer the user-selected stored document; fall back to docType lookup.
        let rawDoc = findRawDocument(docType, selectedDocId, issuedDocs)
        match (rawDoc) {
            case None =>
                Hilog.warn(0, "OpenId4VpService",
                    "No stored document found for docType=" + docType)
                return None
            case Some(doc) =>
                // doc.data contains the raw IssuerSigned CBOR bytes for mso_mdoc
                if (doc.data.isEmpty()) {
                    Hilog.warn(0, "OpenId4VpService",
                        "Empty credential data for docType=" + docType)
                    return None
                }
                // Wrap in a DeviceResponse with a deviceSignature DeviceAuth
                // over the OpenID4VP SessionTranscript (a bare IssuerSigned is
                // not decodable as a DeviceResponse on the verifier side).
                let transcript = match (this.vpSessionTranscript) {
                    case Some(t) => t
                    case None =>
                        Hilog.warn(0, "OpenId4VpService", "No session transcript for DeviceAuth")
                        return None
                }
                let responseBytes = Oid4VpDeviceAuth.buildDeviceResponse(
                    doc.data, docType, doc.id, doc.docKeyInfo, transcript)
                return Some(Openid4VpUtils.buildMdocVpToken(responseBytes))
        }
    }

    /**
     * Build an SD-JWT VP token from stored credential.
     *
     * Retrieves the raw credential bytes (UTF-8 encoded SD-JWT string) from
     * the storage service Document.data.
     *
     * Mirrors iOS OpenId4VpService.makeSdJwtClaimData.
     */
    private func buildSdJwtVpToken(
        docType: String,
        selectedDocId: ?String,
        issuedDocs: ?ArrayList<Document>
    ): ?String {
        let rawDoc = findRawDocument(docType, selectedDocId, issuedDocs)
        match (rawDoc) {
            case None => return None
            case Some(doc) =>
                if (doc.data.isEmpty()) {
                    return None
                }
                // SD-JWT credential data is stored as UTF-8 encoded JWT string.
                // Append the KB-JWT signed by the document's holder key — the
                // verifier rejects presentations without key binding.
                let sdJwtStr = String.fromUtf8(doc.data)
                return Some(Oid4VpDeviceAuth.appendKbJwt(
                    sdJwtStr, this.vpClientId, this.vpNonce, doc.id, doc.docKeyInfo))
        }
    }

    /**
     * Find a raw Document matching the given docType from an ArrayList of issued docs.
     *
     * Document.docType is the ISO 18013-5 document type string (for mDoc)
     * or the sd-jwt vct value (for SD-JWT-VC).
     */
    private func findRawDocument(
        docType: String,
        selectedDocId: ?String,
        issuedDocs: ?ArrayList<Document>
    ): ?Document {
        match ((selectedDocId, issuedDocs)) {
            case (Some(id), Some(docs)) =>
                for (doc in docs) {
                    if (doc.id == id) { return Some(doc) }
                }
            case _ => ()
        }
        return findRawDocumentByDocType(docType, issuedDocs)
    }

    private func findRawDocumentByDocType(
        docType: String,
        issuedDocs: ?ArrayList<Document>
    ): ?Document {
        match (issuedDocs) {
            case None => return None
            case Some(docs) =>
                var idx: Int64 = 0
                while (idx < docs.size) {
                    let doc = docs[idx]
                    if (doc.docType == docType) {
                        return Some(doc)
                    }
                    idx += 1
                }
                return None
        }
    }

    /**
     * Build OID4VP SessionTranscript handover bytes.
     * clientId, responseUri, nonce, mdocGeneratedNonce → CBOR handover bytes.
     */
    private func buildOid4VpHandover(rrd: ResolvedRequestData): Array<UInt8> {
        let clientId = rrd.request.client.id().clientId()
        let responseUri = extractResponseUri(rrd.request)
        let nonce = rrd.request.nonce
        let mdocNonce = match (this.mdocGeneratedNonce) {
            case Some(n) => n
            case None => Openid4VpUtils.generateMdocGeneratedNonce()
        }
        return Openid4VpUtils.generateOpenId4VpHandover(clientId, responseUri, nonce, mdocNonce)
    }

    /**
     * Extract response URI from the response mode of the resolved request.
     */
    private func extractResponseUri(vpTokenData: VpTokenData): String {
        match (vpTokenData.responseMode) {
            case Some(dp: DirectPost) => return dp.responseUri
            case Some(dpj: DirectPostJWT) => return dpj.responseUri
            case _ => return ""
        }
    }

    /**
     * Build EncryptionParameters for JARM (direct_post.jwt) if required.
     * Mirrors iOS ApuParam generation from mdocGeneratedNonce.
     */
    private func buildEncryptionParameters(rrd: ResolvedRequestData): ?EncryptionParameters {
        match (rrd.request.responseEncryptionSpecification) {
            case None => return None
            case Some(_) =>
                let nonce = match (this.mdocGeneratedNonce) {
                    case Some(n) => n
                    case None => Openid4VpUtils.generateMdocGeneratedNonce()
                }
                return Some(ApuParam(nonce))
        }
    }
}
