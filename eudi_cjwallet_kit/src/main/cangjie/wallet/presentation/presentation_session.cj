/*
 * presentation_session.cj
 *
 * EUDI Wallet Kit — PresentationService interface, PresentationSession,
 * and FaultPresentationService.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Services/PresentationService.swift  (protocol)
 *   Sources/EudiWalletKit/Services/PresentationSession.swift  (session coordinator)
 *   Sources/EudiWalletKit/Services/FaultPresentationService.swift
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.presentation
 *
 * Design decisions:
 *   - iOS protocol PresentationService → Cangjie interface PresentationService
 *   - iOS async throws → synchronous with exceptions
 *   - iOS ObservableObject / @Published → plain var fields
 *   - PresentationSession wraps a PresentationService implementation
 *   - FaultPresentationService always throws — mirrors iOS FaultPresentationService
 *
 * R-101: init named params require ! prefix in declaration.
 * R-103: HashMap insert/update uses subscript [k] = v.
 * R-104: HashMap reads use .contains() guard.
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.presentation

import kit.PerformanceAnalysisKit.Hilog

import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.WalletError
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.RequestItems
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.{
    WrpRegistrationPolicy, PresentationPolicyViolation, DisclosedDocumentSet,
    DocElements, MsoMdocElements, SdJwtElements, NameSpacedElements,
    MsoMdocElement, SdJwtElement
}
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.storage.StorageManager
import ohos_app_cangjie_eudi_cjwallet_storage.storage.types.{Document, DocumentStatus}
import ohos_app_cangjie_eudi_cjwallet_storage.storage.types.DocDataFormat as StorageDocDataFormat
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.FlowType
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.PresentationTransactionRecord

import ohos_app_cangjie_eudi_cjmdoc_transfer.transfer.framing.UserRequestInfo
import ohos_app_cangjie_eudi_cjmdoc_transfer.transfer.framing.RequestItem
import ohos_app_cangjie_eudi_cjmdoc_transfer.transfer.framing.TransferStatus

import std.collection.ArrayList
import std.collection.HashMap

// ===========================================================================
// TransactionLog — simple key/value log for a presentation flow
// Mirrors iOS PresentationSession.transactionLog: AuditLog
// ===========================================================================

/** Minimal transaction log for auditing presentation flows. */
public class TransactionLog {
    private var entries: ArrayList<(String, String)>

    public init() {
        this.entries = ArrayList<(String, String)>()
    }

    public func add(key: String, value: String): Unit {
        this.entries.add((key, value))
    }

    public func getAll(): ArrayList<(String, String)> {
        return this.entries
    }

    public func isEmpty(): Bool {
        return this.entries.isEmpty()
    }
}

// ===========================================================================
// PresentationStatus — mirrors iOS PresentationSession status enum
// ===========================================================================

/**
 * Lifecycle status of a presentation session.
 *
 * Mirrors iOS PresentationSession status states.
 */
public enum PresentationStatus {
    /** Session is initializing / not yet started. */
    | Initializing
    /** Transport initialised (GATT server created), radio not yet confirmed. */
    | Initialized
    /** Radio confirmed on (peripheral manager powered on). */
    | PoweredOn
    /** QR engagement started; payload is the device engagement QR content. */
    | QrEngagementReady(String)
    /** Verifier connected (BLE central subscribed). */
    | Connected
    /** Verifier wrote START on the State characteristic; the session is open. */
    | Started
    /** Request received from verifier. */
    | RequestReceived
    /** User selected documents to disclose. */
    | UserSelected
    /** Response sent successfully. */
    | ResponseSent
    /** Session error; payload is the error message. */
    | SessionError(String)
    /** Session disconnected. */
    | Disconnected

    public func isError(): Bool {
        match (this) {
            case SessionError(_) => return true
            case _ => return false
        }
    }
}

// ===========================================================================
// PresentationRequestInfo — decoded request info for UI display
// Simplified substitute for iOS docRequestInfo/DisclosedDocuments
// ===========================================================================

/**
 * Per-docType decoded request info: which element identifiers were requested.
 */
public class PresentationRequestInfo {
    /** Document type string (docType for mDL; vct for SD-JWT). */
    public let docType: String
    /** Requested element identifiers across all namespaces (flat list for display). */
    public let requestedElements: ArrayList<String>
    /** Stored document ids matching this docType (resolved at decode time so the
     *  UI can fetch the concrete documents — iOS disclosedDocuments carries the
     *  matched storage documents, not the raw docType). */
    public var matchedDocIds: Array<String>

    public init(docType: String, requestedElements: ArrayList<String>) {
        this.docType = docType
        this.requestedElements = requestedElements
        this.matchedDocIds = Array<String>()
    }
}

// ===========================================================================
// PresentationService — interface
// Mirrors iOS protocol PresentationService
// ===========================================================================

/**
 * Interface for presentation service implementations.
 *
 * Two concrete implementations:
 *   - OpenId4VpService        — remote OpenID4VP presentation
 *   - BlePresentationService  — BLE proximity (ISO 18013-5)
 */
public interface PresentationService {

    /**
     * The flow type (Ble / OpenId4Vp).
     * Mirrors iOS var flow: FlowType { get }
     */
    func flow(): FlowType

    /**
     * Start QR engagement (BLE only; no-op for remote).
     * Returns the QR code content string (device engagement URI) or empty string.
     * Mirrors iOS func startQrEngagement() async throws -> String
     */
    func startQrEngagement(): String

    /**
     * Receive a presentation request from the verifier.
     * Returns a UserRequestInfo describing requested documents / claims.
     * Throws WalletError on failure.
     * Mirrors iOS func receiveRequest() async throws -> UserRequestInfo
     */
    func receiveRequest(): UserRequestInfo

    /**
     * Return the transaction log accumulated so far.
     * Mirrors iOS var transactionLog: AuditLog? { get }
     */
    func transactionLog(): ?TransactionLog

    /**
     * ZKP document IDs for flows that require zero-knowledge proofs (may be empty).
     * Mirrors iOS var zkpDocumentIds: [String] { get }
     */
    func zkpDocumentIds(): Array<String>

    /**
     * Verifier display name resolved from the request (e.g. the reader/verifier
     * certificate Organization). None when unavailable. Mirrors the reader-cert
     * issuer iOS surfaces on the session after a request is received.
     */
    func readerCertIssuerName(): ?String

    /**
     * Whether the verifier's reader certificate chain validated against the
     * wallet's trusted reader anchors. Mirrors iOS `readerAuthValidated` — the
     * green "verified" badge on the relying-party row. The OpenID4VP resolver is
     * fail-closed on x509 clients (untrusted chains are rejected at resolve
     * time), so a successfully-resolved x509 client is a trusted verifier.
     */
    func readerCertIssuerValid(): Bool

    /**
     * The verifier (relying party) registration policy decoded from the WRPRC
     * carried in the request, if the service validated one. None when
     * validation is disabled or no WRPRC was carried.
     */
    func wrpVerifierPolicy(): ?WrpRegistrationPolicy

    /**
     * Verifier registration warnings: the empty key holds request-wide
     * violations (the registration itself failed); per-docType keys hold
     * over-asking violations. None when validation is disabled / not evaluated.
     */
    func wrpVerifierWarnings(): ?HashMap<String, Array<PresentationPolicyViolation>>

    /**
     * DER certificate chain of the relying party (reader-auth / x5c chain of
     * the resolved client), for transaction-log recording. None before a
     * request is received or when no chain was presented.
     */
    func readerCertificateChainDer(): ?Array<Array<UInt8>>

    /**
     * Send the response for the user-selected disclosed items.
     * @param userSelected  — RequestItems: docId → (namespace → [RequestItem])
     * @param onSuccess     — called with optional redirect URI on success
     * @param onCancel      — called with reason string on cancellation/error
     * Mirrors iOS func sendResponse(userSelected:onSuccess:onCancel:) async throws
     */
    func sendResponse(
        userSelected: RequestItems,
        onSuccess: ?((String) -> Unit),
        onCancel: ?(String) -> Unit
    ): Unit

    /**
     * Block until the verifier disconnects (BLE) or return immediately (remote).
     * BLE waits with a deadline (no busy-spin) for the reader's END signal /
     * link drop, then tears the transport down.
     * Mirrors iOS func waitForDisconnect() async
     */
    func waitForDisconnect(): Unit

    /**
     * Stop the presentation: stop the transport (advertising + GATT server),
     * delete the ephemeral engagement key and reset the session state.
     * Idempotent. Mirrors iOS BlePresentationService.stop().
     */
    func stop(): Unit
}

// ===========================================================================
// PresentationSession — session coordinator
// Mirrors iOS class PresentationSession: ObservableObject
// ===========================================================================

/**
 * Coordinates a presentation flow through a PresentationService.
 *
 * Callers (EudiWallet facade) use this as the primary interface for:
 *   1. startQrEngagement() — BLE proximity
 *   2. receiveRequest()    — block until request arrives
 *   3. sendResponse()      — after user selection
 *
 * Status changes are broadcast to an optional onStatusChange callback.
 */
public class PresentationSession {

    // -----------------------------------------------------------------------
    // State fields (mirrors iOS @Published vars)
    // -----------------------------------------------------------------------

    /** The underlying presentation service implementation. */
    public let service: PresentationService

    /** Current session status. */
    public var status: PresentationStatus

    /** The raw request as received from the verifier. */
    public var userRequestInfo: ?UserRequestInfo

    /** Per-docType decoded request info (for UI display). */
    public var requestInfoList: ArrayList<PresentationRequestInfo>

    /** Reader (verifier) certificate issuer name, if available. */
    public var readerCertIssuer: ?String

    /** Whether the verifier certificate chain is trusted. */
    public var readerCertIssuerValid: Bool

    /**
     * Request items selectable by the user, one set per received request,
     * paired with registration-policy warnings for that request.
     * Mirrors iOS PresentationSession.disclosedDocumentSets (v0.40.9,
     * breaking change from [[DocElements]]).
     */
    public var disclosedDocumentSets: Array<DisclosedDocumentSet>

    /**
     * The verifier (wallet relying party) registration policy decoded from
     * the WRPRC carried in the request, if any.
     */
    public var wrpVerifierPolicy: ?WrpRegistrationPolicy

    /**
     * Verifier registration warnings. Convention: the empty key holds
     * request-level violations (registration itself failed); per-docType keys
     * hold over-asking violations.
     */
    public var wrpVerifierWarnings: ?HashMap<String, Array<PresentationPolicyViolation>>

    /**
     * DER certificate chain of the relying party captured from the request
     * (leaf first), for transaction-log recording.
     */
    public var readerCertificateChain: ?Array<Array<UInt8>>

    /** Error from the most recent operation, if any. */
    public var uiError: ?WalletError

    /**
     * QR engagement payload "mdoc:" + base64url(CBOR DeviceEngagement), set
     * by startQrEngagement for proximity flows. Mirrors iOS
     * PresentationSession.deviceEngagement.
     */
    public var deviceEngagement: ?String

    /**
     * Full record of the proximity presentation (relying party, raw request,
     * cleartext response, session transcript), available after sendResponse
     * for BLE flows; Completed only when the transport delivered the response.
     */
    public var transactionRecord: ?PresentationTransactionRecord

    /**
     * Redirect URI returned by the verifier on the most recent successful
     * response, if any. Mirrors iOS: the sendResponse success carries the
     * redirect (AcceptedOutcome.redirectUri); the RQES service authorization
     * relies on it to continue the QTSP OAuth flow. None when the verifier
     * returns no redirect (ordinary presentation).
     */
    public var lastRedirect: ?String = None

    /** Storage manager (for looking up issued documents). */
    public let storageManager: StorageManager

    /** Optional status callback (UI can register to receive updates). */
    public var onStatusChange: ?((PresentationStatus) -> Unit)

    // -----------------------------------------------------------------------
    // Initialiser
    // -----------------------------------------------------------------------

    public init(service!: PresentationService, storageManager!: StorageManager) {
        this.service = service
        this.storageManager = storageManager
        this.status = PresentationStatus.Initializing
        this.userRequestInfo = None
        this.requestInfoList = ArrayList<PresentationRequestInfo>()
        this.readerCertIssuer = None
        this.readerCertIssuerValid = false
        this.disclosedDocumentSets = Array<DisclosedDocumentSet>()
        this.wrpVerifierPolicy = None
        this.wrpVerifierWarnings = None
        this.readerCertificateChain = None
        this.uiError = None
        this.deviceEngagement = None
        this.transactionRecord = None
        this.onStatusChange = None
        // Proximity: relay the transport lifecycle (Initialized / PoweredOn /
        // Connected / Started / Disconnected) to the session observers.
        // QrEngagementReady, RequestReceived, UserSelected and ResponseSent
        // are emitted by the session itself once the corresponding data is
        // populated / delivered (ResponseSent only after the transport
        // confirmed delivery); Error surfaces as SessionError via the thrown
        // WalletError / onCancel path, never as a bare status.
        match (service) {
            case ble: BlePresentationService =>
                let self0 = this
                ble.setTransferStatusObserver(Some({ st: TransferStatus =>
                    self0.onTransferStatus(st)
                }))
            case _ => ()
        }
    }

    // -----------------------------------------------------------------------
    // Public methods
    // -----------------------------------------------------------------------

    /**
     * Start QR engagement for BLE proximity flows.
     * Returns the QR code content (BLE device engagement URI).
     * For remote flows returns empty string.
     */
    public func startQrEngagement(): String {
        try {
            let qrContent = this.service.startQrEngagement()
            if (!qrContent.isEmpty()) {
                this.deviceEngagement = Some(qrContent)
                setStatus(PresentationStatus.QrEngagementReady(qrContent))
            }
            return qrContent
        } catch (e: Exception) {
            let errMsg = e.message
            setStatus(PresentationStatus.SessionError(errMsg))
            this.uiError = Some(WalletError.withDescription("startQrEngagement failed: " + errMsg))
            return ""
        }
    }

    /**
     * Receive a presentation request from the verifier.
     * Populates userRequestInfo and decodes requestInfoList.
     */
    public func receiveRequest(): Unit {
        try {
            Hilog.info(0, "VPFLOW", "session.receiveRequest -> service.receiveRequest()")
            let info = this.service.receiveRequest()
            this.userRequestInfo = Some(info)
            decodeRequest(info)
            // Surface the verifier display name (from its certificate) so the
            // request UI + transaction log show the real name, not "Verifier".
            match (this.service.readerCertIssuerName()) {
                case Some(name) where !name.isEmpty() => this.readerCertIssuer = Some(name)
                case _ => ()
            }
            // Surface reader-chain trust so the request UI shows the green
            // "verified" badge (iOS readerAuthValidated). The resolver is
            // fail-closed, so a resolved x509 verifier is a trusted one.
            this.readerCertIssuerValid = this.service.readerCertIssuerValid()
            // Surface the WRPRC verdict + verifier certificate chain
            // (iOS PresentationSession.decodeRequest tail).
            this.wrpVerifierPolicy = this.service.wrpVerifierPolicy()
            this.wrpVerifierWarnings = this.service.wrpVerifierWarnings()
            this.readerCertificateChain = this.service.readerCertificateChainDer()
            Hilog.info(0, "VPFLOW", "session.receiveRequest OK itemsRequested=" + info.itemsRequested.size.toString() + " readerTrusted=" + this.readerCertIssuerValid.toString())
            setStatus(PresentationStatus.RequestReceived)
        } catch (e: WalletError) {
            // Preserve the structured error (code / innerError) — the app
            // layer branches on WalletErrorCode.InvalidWrprc / TrustError and
            // on the wrapped OpenID4VP authorizationPolicyNotMet inner error.
            Hilog.error(0, "VPFLOW", "session.receiveRequest FAILED: " + e.message)
            setStatus(PresentationStatus.SessionError(e.message))
            this.uiError = Some(e)
        } catch (e: Exception) {
            let errMsg = e.message
            Hilog.error(0, "VPFLOW", "session.receiveRequest FAILED: " + errMsg)
            setStatus(PresentationStatus.SessionError(errMsg))
            this.uiError = Some(WalletError.withDescription("receiveRequest failed: " + errMsg))
        }
    }

    /**
     * Send selected presentation response.
     * @param userSelected — filtered RequestItems for disclosure.
     */
    public func sendResponse(userSelected: RequestItems): Unit {
        try {
            setStatus(PresentationStatus.UserSelected)
            this.service.sendResponse(
                userSelected,
                Some({ redirectUri: String =>
                    Hilog.info(0, "PresentationSession",
                        "sendResponse success, redirect: " + redirectUri)
                    captureTransactionRecord()
                    this.lastRedirect = if (redirectUri.isEmpty()) {
                        None
                    } else {
                        Some(redirectUri)
                    }
                    setStatus(PresentationStatus.ResponseSent)
                }),
                Some({ reason: String =>
                    captureTransactionRecord()
                    this.uiError = Some(WalletError.withDescription(reason))
                    setStatus(PresentationStatus.SessionError(reason))
                })
            )
        } catch (e: Exception) {
            let errMsg = e.message
            captureTransactionRecord()
            setStatus(PresentationStatus.SessionError(errMsg))
            this.uiError = Some(WalletError.withDescription("sendResponse failed: " + errMsg))
        }
    }

    /**
     * Block until the verifier disconnects (proximity: reader END signal or
     * link drop, bounded by the service deadline). Remote flows return at once.
     */
    public func waitForDisconnect(): Unit {
        try {
            this.service.waitForDisconnect()
        } catch (e: Exception) {
            Hilog.warn(0, "PresentationSession", "waitForDisconnect: " + e.message)
        }
    }

    /**
     * Stop the presentation: stops the transport, deletes the ephemeral
     * engagement key and resets the service. A session stopped while still
     * in progress reports Disconnected; a completed (ResponseSent) or failed
     * session keeps its terminal status. Idempotent and re-entrant: it may
     * be called from inside a status callback (e.g. on ResponseSent).
     */
    public func stop(): Unit {
        try {
            this.service.stop()
        } catch (e: Exception) {
            Hilog.warn(0, "PresentationSession", "stop: " + e.message)
        }
        match (this.status) {
            case PresentationStatus.SessionError(_) => ()
            case PresentationStatus.Disconnected => ()
            case PresentationStatus.ResponseSent => ()
            case _ => setStatus(PresentationStatus.Disconnected)
        }
    }

    /**
     * Cancel the current session with an optional reason (stops the transport).
     */
    public func cancel(reason: String): Unit {
        Hilog.info(0, "PresentationSession", "session cancelled: " + reason)
        this.stop()
    }

    /** Return flow type from the underlying service. */
    public func flow(): FlowType {
        return this.service.flow()
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private func setStatus(newStatus: PresentationStatus): Unit {
        this.status = newStatus
        match (this.onStatusChange) {
            case Some(cb) => cb(newStatus)
            case None => ()
        }
    }

    /**
     * Transport lifecycle relay (BLE): Connected / Started / Disconnected are
     * surfaced as they happen; the data-bearing states are emitted by the
     * session methods. A Disconnected after an error keeps the error visible.
     */
    private func onTransferStatus(st: TransferStatus): Unit {
        match (st) {
            case TransferStatus.Initialized =>
                match (this.status) {
                    case PresentationStatus.Initializing => setStatus(PresentationStatus.Initialized)
                    case _ => ()
                }
            case TransferStatus.PoweredOn =>
                match (this.status) {
                    case PresentationStatus.Initializing => setStatus(PresentationStatus.PoweredOn)
                    case PresentationStatus.Initialized => setStatus(PresentationStatus.PoweredOn)
                    case _ => ()
                }
            case TransferStatus.Connected => setStatus(PresentationStatus.Connected)
            case TransferStatus.Started => setStatus(PresentationStatus.Started)
            case TransferStatus.Disconnected =>
                match (this.status) {
                    case PresentationStatus.SessionError(_) => ()
                    case PresentationStatus.Disconnected => ()
                    case _ => setStatus(PresentationStatus.Disconnected)
                }
            case _ => ()
        }
    }

    /** Copy the proximity transaction record out of the BLE service. */
    private func captureTransactionRecord(): Unit {
        match (this.service) {
            case ble: BlePresentationService => this.transactionRecord = ble.transactionRecord()
            case _ => ()
        }
    }

    /**
     * Decode a received UserRequestInfo into PresentationRequestInfo list for UI.
     * Mirrors iOS PresentationSession.decodeRequest(_:).
     * itemsRequested: Array<(String, Array<RequestItem>)>
     *   where each tuple = (docType, [RequestItem])
     */
    private func decodeRequest(info: UserRequestInfo): Unit {
        this.requestInfoList = ArrayList<PresentationRequestInfo>()
        let disclosedElements = ArrayList<DocElements>()
        let issuedDocsOpt = this.storageManager.loadDocuments(DocumentStatus.Issued)
        var i: Int64 = 0
        while (i < info.itemsRequested.size) {
            let (docType, items) = info.itemsRequested[i]
            let elementNames = ArrayList<String>()
            var j: Int64 = 0
            while (j < items.size) {
                let ri = items[j]
                if (!ri.elementPath.isEmpty()) {
                    // For mDoc: path is [namespace, elementId]; take last component
                    elementNames.add(ri.elementPath[ri.elementPath.size - 1])
                }
                j += 1
            }
            let reqInfo = PresentationRequestInfo(docType, elementNames)
            // Resolve the requested docType to the stored documents so the UI
            // can fetch them by id (iOS disclosedDocuments carries the matched
            // documents; the raw docType is not a storage identifier). Match on
            // the raw issued Documents — docModels is populated by no caller in
            // this port, but the raw store carries docType directly.
            let matched = ArrayList<String>()
            match (issuedDocsOpt) {
                case Some(docs) =>
                    for (doc in docs) {
                        Hilog.info(0, "VPFLOW", "decode match: stored docType=" + doc.docType + " vs requested=" + docType)
                        if (doc.docType == docType) {
                            matched.add(doc.id)
                            // Build the selectable elements for this document
                            // (iOS decodeRequest extractMsoMdocElements /
                            // extractSdJwtElements equivalents in this port).
                            disclosedElements.add(buildDocElements(doc, docType, items))
                        }
                    }
                case None => ()
            }
            Hilog.info(0, "VPFLOW", "decode: matched=" + matched.size.toString() + " for docType=" + docType)
            reqInfo.matchedDocIds = matched.toArray()
            this.requestInfoList.add(reqInfo)
            i += 1
        }
        // One DisclosedDocumentSet per received request (this port processes
        // one UserRequestInfo per session), carrying the over-asking warnings
        // (all non-empty keys of wrpVerifierWarnings — the empty key holds
        // request-level violations surfaced separately).
        let setWarnings: ?Array<PresentationPolicyViolation> = collectOveraskWarnings()
        this.disclosedDocumentSets = [DisclosedDocumentSet(disclosedElements.toArray(), setWarnings)]
        Hilog.info(0, "PresentationSession",
            "Decoded request: " + info.itemsRequested.size.toString() + " docTypes")
    }

    /**
     * Build the selectable DocElements for one stored document matching a
     * requested docType, from the requested items.
     * mso_mdoc paths are [namespace, elementId] (single-component paths get
     * the empty namespace); SD-JWT paths pass through unchanged.
     */
    private func buildDocElements(doc: Document, docType: String, items: Array<RequestItem>): DocElements {
        match (doc.docDataFormat) {
            case StorageDocDataFormat.Cbor =>
                // Group requested items by namespace, preserving request order.
                let nsOrder = ArrayList<String>()
                let nsElements = HashMap<String, ArrayList<MsoMdocElement>>()
                var j: Int64 = 0
                while (j < items.size) {
                    let ri = items[j]
                    if (!ri.elementPath.isEmpty()) {
                        let ns: String = if (ri.elementPath.size >= 2) { ri.elementPath[0] } else { "" }
                        let elementId = ri.elementPath[ri.elementPath.size - 1]
                        if (!nsElements.contains(ns)) {
                            nsElements[ns] = ArrayList<MsoMdocElement>()
                            nsOrder.add(ns)
                        }
                        nsElements[ns].add(MsoMdocElement(
                            elementId,
                            ri.isOptional ?? !isMandatoryMdocElement(docType, ns, elementId),
                            ri.intentToRetain ?? false,
                            None,
                            None,
                            true,
                            true
                        ))
                    }
                    j += 1
                }
                let namespaced = ArrayList<NameSpacedElements>()
                for (ns in nsOrder) {
                    namespaced.add(NameSpacedElements(ns, nsElements[ns]))
                }
                return DocElements.MsoMdoc(MsoMdocElements(
                    doc.id, docType, doc.displayName, true, namespaced))
            case StorageDocDataFormat.Sdjwt =>
                let sdElements = ArrayList<SdJwtElement>()
                var j: Int64 = 0
                while (j < items.size) {
                    let ri = items[j]
                    if (!ri.elementPath.isEmpty()) {
                        sdElements.add(SdJwtElement(
                            ri.elementPath,
                            ri.isOptional ?? false,
                            ri.intentToRetain ?? false,
                            None,
                            None,
                            true,
                            true,
                            None
                        ))
                    }
                    j += 1
                }
                return DocElements.SdJwt(SdJwtElements(
                    doc.id, docType, doc.displayName, true, sdElements))
        }
    }

    /**
     * All over-asking violations (non-empty keys of wrpVerifierWarnings).
     * None when validation was not evaluated or produced no such warnings.
     */
    private func collectOveraskWarnings(): ?Array<PresentationPolicyViolation> {
        let warningsMap: HashMap<String, Array<PresentationPolicyViolation>> =
            match (this.wrpVerifierWarnings) {
                case Some(m) => m
                case None =>
                    match (this.service.wrpVerifierWarnings()) {
                        case Some(m) => m
                        case None => return None
                    }
            }
        let acc = ArrayList<PresentationPolicyViolation>()
        for ((key, list) in warningsMap) {
            if (key.isEmpty()) {
                continue
            }
            for (v in list) {
                acc.add(v)
            }
        }
        if (acc.size == 0) {
            return None
        }
        return Some(acc.toArray())
    }
}

/** iOS `MsoMdocElements.getMandatoryElementKeys`: ISO DeviceRequest does not
 * carry optionality, so only schema-mandatory PID/mDL elements are locked. */
func isMandatoryMdocElement(docType: String, namespace: String, elementId: String): Bool {
    if (docType == "eu.europa.ec.eudi.pid.1" && namespace == "eu.europa.ec.eudi.pid.1") {
        return presentationStringInSet(elementId, [
            "age_over_18", "family_name", "given_name", "birth_date",
            "birth_place", "nationality"
        ])
    }
    if (docType == "org.iso.18013.5.1.mDL" && namespace == "org.iso.18013.5.1") {
        return presentationStringInSet(elementId, [
            "family_name", "given_name", "birth_date", "issue_date", "expiry_date",
            "issuing_country", "issuing_authority", "document_number", "portrait",
            "driving_privileges", "un_distinguishing_sign"
        ])
    }
    return false
}

func presentationStringInSet(value: String, values: Array<String>): Bool {
    for (candidate in values) {
        if (candidate == value) { return true }
    }
    return false
}

// ===========================================================================
// FaultPresentationService — always fails
// Mirrors iOS class FaultPresentationService: PresentationService
// ===========================================================================

/**
 * A PresentationService that always throws WalletError.
 * Used as a safe default when no real service is configured.
 */
public class FaultPresentationService <: PresentationService {

    private let reason: String

    public init(reason: String) {
        this.reason = reason
    }

    public func flow(): FlowType {
        return FlowType.Other
    }

    public func startQrEngagement(): String {
        throw WalletError.withDescription("FaultPresentationService: " + this.reason)
    }

    public func receiveRequest(): UserRequestInfo {
        throw WalletError.withDescription("FaultPresentationService: " + this.reason)
    }

    public func transactionLog(): ?TransactionLog {
        return None
    }

    public func zkpDocumentIds(): Array<String> {
        return Array<String>()
    }

    public func readerCertIssuerName(): ?String {
        return None
    }

    public func readerCertIssuerValid(): Bool {
        return false
    }

    public func wrpVerifierPolicy(): ?WrpRegistrationPolicy {
        return None
    }

    public func wrpVerifierWarnings(): ?HashMap<String, Array<PresentationPolicyViolation>> {
        return None
    }

    public func readerCertificateChainDer(): ?Array<Array<UInt8>> {
        return None
    }

    public func sendResponse(
        userSelected: RequestItems,
        onSuccess: ?((String) -> Unit),
        onCancel: ?(String) -> Unit
    ): Unit {
        match (onCancel) {
            case Some(cb) => cb("FaultPresentationService: " + this.reason)
            case None => ()
        }
    }

    public func waitForDisconnect(): Unit {
        // no-op — fault service has no connection to wait for
    }

    public func stop(): Unit {
        // no-op — fault service holds no transport or keys
    }
}
