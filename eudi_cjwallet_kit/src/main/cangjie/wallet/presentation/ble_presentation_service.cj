/*
 * ble_presentation_service.cj
 *
 * EUDI Wallet Kit — BLE proximity presentation service (ISO 18013-5 §8).
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Services/BlePresentationService.swift
 *   (+ the MdocHelpers orchestration it drives: decodeRequestAndInformUser,
 *      getDeviceResponseToSend, getSessionDataToSend)
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.presentation
 *
 * Protocol path (peripheral-server mode, QR engagement, ISO 18013-5):
 *   1. startQrEngagement()  — ephemeral P-256 EDeviceKey in the SecureArea
 *      (HUKS key-agreement key), DeviceEngagement{1.0, Security[1, EDeviceKey],
 *      BLE(peripheral server, uuid)} → "mdoc:" + base64url(CBOR). The exact
 *      encoded bytes are kept (iOS qrCoded) for the SessionTranscript. The
 *      transport advertises the service UUID; the payload is only returned
 *      once the radio reported PoweredOn / QrEngagementReady.
 *   2. receiveRequest()     — waits (condition wait with a deadline) for the
 *      reassembled SessionEstablishment; SessionTranscript = [tag24(DE),
 *      tag24(EReaderKey), null]; ECKA-DH through the SecureArea key
 *      (SessionKeyAgreement seam), HKDF SKReader, AES-256-GCM decrypt →
 *      DeviceRequest; ReaderAuth COSE_Sign1 signature + chain
 *      (accessTrustManager); WRPRC (euWrprc) policy; UserRequestInfo.
 *   3. sendResponse()       — per selected document (keyed by storage id):
 *      IssuerNameSpaces filtered to the selected elements (missing → Errors),
 *      DeviceSigned with DeviceAuth = deviceMac (EMacKey from ECDH(document
 *      device key, EReaderKey)) or deviceSignature (ES256 COSE_Sign1 through
 *      the SecureArea), assembled via MdocHelpers.getDeviceResponseToSend;
 *      DeviceResponse → HKDF SKDevice encrypt → SessionData(status 20). An
 *      error SessionData(status 11) is pre-built so a frame is always sent
 *      (iOS defer semantics). onSuccess fires only after the transport
 *      reported ResponseSent; one-time-use credentials are consumed then.
 *   4. waitForDisconnect()  — waits for the reader's END (0x02) / link drop
 *      with a deadline, then stops the transport and deletes the key.
 *   5. stop()               — explicit teardown (transport + ephemeral key).
 *
 * Threading: transport callbacks arrive on the ConnectivityKit thread; all
 * session state is guarded by a Monitor and the blocking calls wait on it
 * (no busy-spin).
 *
 * R-101: init named params require ! prefix.
 * R-103: HashMap uses subscript assignment.
 * R-104: HashMap reads use .contains() guard.
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.presentation

import kit.PerformanceAnalysisKit.Hilog

import std.collection.ArrayList
import std.collection.HashMap
import std.sync.Monitor
import std.time.MonoTime

import ohos_app_cangjie_eudi_cjmdoc_transfer.transfer.ble.MdocGattServer
import ohos_app_cangjie_eudi_cjmdoc_transfer.transfer.ble.MdocOfflineDelegate
import ohos_app_cangjie_eudi_cjmdoc_transfer.transfer.ble.DeviceEngagementInfo
import ohos_app_cangjie_eudi_cjmdoc_transfer.transfer.framing.TransferStatus
import ohos_app_cangjie_eudi_cjmdoc_transfer.transfer.framing.ErrorCode
import ohos_app_cangjie_eudi_cjmdoc_transfer.transfer.framing.UserRequestInfo
import ohos_app_cangjie_eudi_cjmdoc_transfer.transfer.framing.RequestItem
import ohos_app_cangjie_eudi_cjmdoc_transfer.transfer.orchestration.ReaderCertTrust
import ohos_app_cangjie_eudi_cjmdoc_transfer.transfer.orchestration.MdocHelpers
import ohos_app_cangjie_eudi_cjmdoc_transfer.transfer.orchestration.DecodeRequestResult

import ohos_app_cangjie_eudi_cjmdoc_security.security.session.{
    SessionEncryption, SessionRole, SessionEstablishment, SessionKeyAgreement,
    buildP256X963PublicKey
}
import ohos_app_cangjie_eudi_cjmdoc_security.security.device_auth.{
    DeviceAuthMethod, MdocAuthentication
}

import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.engagement.{
    DeviceEngagement, Security, CoseKey, CoseKeyPrivate, CoseKeyExchange
}
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.engagement.CoseEcCurve as EngCoseEcCurve
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.{
    SecureArea, SecureAreaRegistry, CredentialOptions, CredentialPolicy,
    KeyOptions, KeyPurpose, SigningAlgorithm, KeyBatchInfo, DocKeyInfo
}
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.CoseEcCurve as SaCoseEcCurve
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.request.{DeviceRequest, DocRequest}
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.response.{
    DeviceResponse, IssuerSigned, IssuerNameSpaces, IssuerSignedItem,
    DeviceSigned, DeviceAuth, DeviceNameSpaces, DeviceSignedItems,
    MdocErrors, DocumentError
}
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.response.Document as MdocDocument
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.issuerauth.KeyAuthorizations

import ohos_app_cangjie_eudi_cjcbor.cbor.decodeCbor

import ohos_app_cangjie_eudi_cjwallet_storage.storage.types.Document
import ohos_app_cangjie_eudi_cjwallet_storage.storage.types.DocumentStatus
import ohos_app_cangjie_eudi_cjwallet_storage.storage.types.DocDataFormat as StorageDocDataFormat

import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.WalletError
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.WalletErrorCode
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.RequestItems
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.{WrpRegistrationPolicy, PresentationPolicyViolation}
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.RegistrationCertificateAuthorization
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.PresentationTransactionRecord
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.TransactionLogUtils
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.storage.StorageManager
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.FlowType

import ohos_app_cangjie_eudi_cjx509.x509.core.Cert
import ohos_app_cangjie_eudi_cjx509.x509.core.subjectAttributeValue
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.{
    DCQL, CredentialQuery, ClaimsQuery, QueryId, Format
}

import ohos_app_cangjie_eudi_cjetsi_1196x2.etsi_trust.TrustConfiguration

import eudi_lib_core_crypto.Rng
import eudi_lib_core_crypto.EcdsaP256
import eudi_lib_core_crypto.Base64Url
import eudi_lib_core_crypto.Hkdf

// ===========================================================================
// Constants
// ===========================================================================

/** CBOR null — the QR handover element of the SessionTranscript (§9.1.5.1). */
let QR_HANDOVER_NULL: Array<UInt8> = [0xF6u8]

/** X.509 commonName attribute OID (reader display name). */
let OID_COMMON_NAME: String = "2.5.4.3"

/** X.509 organizationName attribute OID (fallback display name). */
let OID_ORGANIZATION_NAME: String = "2.5.4.10"

/** HKDF info for the optional BLE Ident characteristic (§8.3.3.1.5). */
let BLE_IDENT_INFO: Array<UInt8> = [0x42u8, 0x4Cu8, 0x45u8, 0x49u8, 0x64u8, 0x65u8, 0x6Eu8, 0x74u8]

// ===========================================================================
// AccessManagerReaderTrust — live reader chain trust (iOS accessTrustManager)
// ===========================================================================

class AccessManagerReaderTrust <: ReaderCertTrust {
    private let trustConfiguration: TrustConfiguration

    public init(trustConfiguration: TrustConfiguration) {
        this.trustConfiguration = trustConfiguration
    }

    public func validateCertTrustPath(chain: Array<Array<UInt8>>): (Bool, ?String) {
        this.trustConfiguration.accessTrustManager.validateCertTrustPath(chain)
    }
}

// ===========================================================================
// SecureAreaSessionKeyAgreement — ECKA-DH via the SecureArea ephemeral key
// ===========================================================================

/**
 * ECDH provider handed to SessionEncryption: the ephemeral EDeviceKey lives
 * in the SecureArea (HUKS agree key), so the shared secret is computed by
 * SecureArea.keyAgreement with the reader's ephemeral public key.
 */
class SecureAreaSessionKeyAgreement <: SessionKeyAgreement {
    private let secureArea: SecureArea
    private let keyId: String
    private let keyIndex: Int64

    public init(secureArea: SecureArea, keyId: String, keyIndex: Int64) {
        this.secureArea = secureArea
        this.keyId = keyId
        this.keyIndex = keyIndex
    }

    public func agree(peerPublicKeyX963: Array<UInt8>): Array<UInt8> {
        return this.secureArea.keyAgreement(this.keyId, this.keyIndex, peerPublicKeyX963, None)
    }
}

// ===========================================================================
// PresentedDocument — what went into the response (for the log + consumption)
// ===========================================================================

class PresentedDocument {
    public let docId: String
    public let docType: String
    public let keyIndex: Int64
    public let secureAreaName: ?String

    public init(docId: String, docType: String, keyIndex: Int64, secureAreaName: ?String) {
        this.docId = docId
        this.docType = docType
        this.keyIndex = keyIndex
        this.secureAreaName = secureAreaName
    }
}

// ===========================================================================
// BlePresentationService — BLE proximity presentation
// Mirrors iOS class BlePresentationService: PresentationService, MdocOfflineDelegate
// ===========================================================================

/**
 * Presentation service implementing BLE proximity presentation (ISO 18013-5 §8).
 *
 * Uses MdocGattServer as the peripheral (holder) role BLE transport and
 * implements MdocOfflineDelegate to receive transport callbacks.
 */
public class BlePresentationService <: PresentationService & MdocOfflineDelegate {

    // -----------------------------------------------------------------------
    // Configuration / collaborators
    // -----------------------------------------------------------------------

    private let storageManager: StorageManager
    private let transport: MdocGattServer
    private let trustConfiguration: ?TrustConfiguration
    private let readerCertTrust: ?ReaderCertTrust

    /** Validator for the relying-party WRPRC carried in requestInfo (euWrprc). */
    private let wrpRegistrationValidator: ?WrpVpRegistrationValidator

    /** Whether WRPRC validation is enabled (OpenId4VpConfiguration flag). */
    private let validateRegistrationCertificate: Bool

    /**
     * Device authentication method for DeviceAuth (iOS dauthMethod).
     * DeviceMac: COSE_Mac0 with EMacKey = HKDF(ECDH(document device key,
     * EReaderKey)); DeviceSignature: ES256 COSE_Sign1 via the SecureArea.
     */
    public let deviceAuthMethod: DeviceAuthMethod

    /**
     * When DeviceMac is configured but the document's SecureArea key cannot
     * perform ECDH (HarmonyOS HUKS document keys are SIGN-only; a key cannot
     * carry SIGN|AGREE), fall back to deviceSignature for that document
     * instead of failing the presentation. Logged at warning level.
     */
    public var deviceMacFallbackToSignature: Bool = true

    /** Deadline for the radio to report PoweredOn / QrEngagementReady. */
    public var engagementTimeout: Duration = Duration.second * 15
    /** Deadline for the reader to deliver the SessionEstablishment. */
    public var requestTimeout: Duration = Duration.minute * 5
    /** Deadline for the transport to drain the response (ResponseSent). */
    public var responseTimeout: Duration = Duration.second * 30
    /** Deadline for the reader END signal / link drop in waitForDisconnect. */
    public var disconnectTimeout: Duration = Duration.second * 15

    // -----------------------------------------------------------------------
    // Session state (guarded by monitor)
    // -----------------------------------------------------------------------

    private let monitor: Monitor

    /** Radio reported PoweredOn / QrEngagementReady. */
    private var radioReady: Bool
    /** Reassembled SessionEstablishment bytes from the transport. */
    private var requestBuffer: ?Array<UInt8>
    /** Transport reported ResponseSent for the last sendData. */
    private var responseDelivered: Bool
    /** Reader wrote END (0x02) or the link dropped. */
    private var linkDisconnected: Bool
    /** Explicit stop() was called for this session. */
    private var stopped: Bool
    /** Transport error (didFinishedWithError / TransferStatus.Error). */
    private var failure: ?String
    /** Last transport status observed. */
    private var lastStatus: TransferStatus

    /** Observer of the raw transport lifecycle (PresentationSession relay). */
    private var transferStatusObserver: ?((TransferStatus) -> Unit)

    // Engagement
    private var engagementSecureArea: ?SecureArea
    private var engagementKeyId: ?String
    private var devicePublicKey: ?CoseKey
    private var deviceEngagementObj: ?DeviceEngagement
    /** Exact encoded DeviceEngagement bytes (iOS qrCoded) — transcript input. */
    private var deviceEngagementRaw: ?Array<UInt8>
    private var qrPayload: ?String
    /** Current BLE engagement info (bleServiceUuid) read by the transport. */
    private var engagementInfo: ?DeviceEngagementInfo

    // Request
    private var sessionEncryption: ?SessionEncryption
    private var deviceRequest: ?DeviceRequest
    private var lastUserRequestInfo: ?UserRequestInfo
    private var lastReaderIssuer: ?String
    private var lastReaderTrusted: Bool
    /** DER chain of the last reader authentication (leaf first), if any. */
    private var lastReaderChain: ?Array<Array<UInt8>>
    private var lastReaderAuthBytes: ?Array<UInt8>
    private var rawRequestBytes: ?Array<UInt8>

    // Response
    private var deviceResponseBytes: ?Array<UInt8>
    private var presentedDocumentIds: Array<String>
    /** Device-signed namespaces to include per document id (usually none). */
    private var deviceNameSpacesToSend: HashMap<String, DeviceNameSpaces>

    // Transaction log
    private var txLog: TransactionLog
    private var txRecord: ?PresentationTransactionRecord

    // -----------------------------------------------------------------------
    // Initialiser
    // -----------------------------------------------------------------------

    public init(storageManager!: StorageManager, trustConfiguration!: ?TrustConfiguration = None,
                wrpRegistrationValidator!: ?WrpVpRegistrationValidator = None,
                validateRegistrationCertificate!: Bool = false,
                deviceAuthMethod!: DeviceAuthMethod = DeviceAuthMethod.DeviceMac) {
        this.storageManager = storageManager
        this.transport = MdocGattServer()
        this.trustConfiguration = trustConfiguration
        this.readerCertTrust = match (trustConfiguration) {
            case Some(cfg) => Some(AccessManagerReaderTrust(cfg))
            case None => None
        }
        this.wrpRegistrationValidator = wrpRegistrationValidator
        this.validateRegistrationCertificate = validateRegistrationCertificate
        this.deviceAuthMethod = deviceAuthMethod
        this.monitor = Monitor()
        this.radioReady = false
        this.requestBuffer = None
        this.responseDelivered = false
        this.linkDisconnected = false
        this.stopped = false
        this.failure = None
        this.lastStatus = TransferStatus.Initializing
        this.transferStatusObserver = None
        this.engagementSecureArea = None
        this.engagementKeyId = None
        this.devicePublicKey = None
        this.deviceEngagementObj = None
        this.deviceEngagementRaw = None
        this.qrPayload = None
        this.engagementInfo = None
        this.sessionEncryption = None
        this.deviceRequest = None
        this.lastUserRequestInfo = None
        this.lastReaderIssuer = None
        this.lastReaderTrusted = false
        this.lastReaderChain = None
        this.lastReaderAuthBytes = None
        this.rawRequestBytes = None
        this.deviceResponseBytes = None
        this.presentedDocumentIds = Array<String>()
        this.deviceNameSpacesToSend = HashMap<String, DeviceNameSpaces>()
        this.txLog = TransactionLog()
        this.txRecord = None
        this.transport.setDelegate(this)
        match (trustConfiguration) {
            case Some(_) =>
                Hilog.info(0, "BLE-TRUST", "proximity reader chain uses accessTrustManager")
            case None =>
                Hilog.warn(0, "BLE-TRUST", "no TrustConfiguration; reader x5c will not be live-validated")
        }
    }

    // -----------------------------------------------------------------------
    // Public surface beyond PresentationService
    // -----------------------------------------------------------------------

    /**
     * Register an observer of the raw transport lifecycle (Connected /
     * Started / RequestReceived / ResponseSent / Disconnected / Error).
     * Invoked on the transport thread, outside the service lock.
     */
    public func setTransferStatusObserver(observer: ?((TransferStatus) -> Unit)): Unit {
        synchronized(monitor) {
            this.transferStatusObserver = observer
        }
    }

    /** The QR payload of the current engagement ("mdoc:" + base64url). */
    public func qrCodePayload(): ?String {
        synchronized(monitor) {
            return this.qrPayload
        }
    }

    /** The exact encoded DeviceEngagement bytes used in the SessionTranscript. */
    public func deviceEngagementBytes(): ?Array<UInt8> {
        synchronized(monitor) {
            return this.deviceEngagementRaw
        }
    }

    /** Last transport status. */
    public func currentTransferStatus(): TransferStatus {
        synchronized(monitor) {
            return this.lastStatus
        }
    }

    /** Cleartext DeviceResponse CBOR of the last successful send. */
    public func lastDeviceResponseBytes(): ?Array<UInt8> {
        synchronized(monitor) {
            return this.deviceResponseBytes
        }
    }

    /** Storage ids of the documents included in the last response. */
    public func documentIds(): Array<String> {
        synchronized(monitor) {
            return this.presentedDocumentIds
        }
    }

    /**
     * Device-signed namespaces to include in the response for a document
     * (storage id). They are checked against the MSO keyAuthorizations
     * before signing (iOS deviceNameSpacesRequested).
     */
    public func setDeviceNameSpacesToSend(docId: String, nameSpaces: ?DeviceNameSpaces): Unit {
        synchronized(monitor) {
            match (nameSpaces) {
                case Some(ns) => this.deviceNameSpacesToSend[docId] = ns
                case None => this.deviceNameSpacesToSend.remove(docId)
            }
        }
    }

    /**
     * The proximity transaction record: available once a request was
     * decoded; Completed only after the transport delivered the response.
     */
    public func transactionRecord(): ?PresentationTransactionRecord {
        synchronized(monitor) {
            return this.txRecord
        }
    }

    // -----------------------------------------------------------------------
    // PresentationService implementation
    // -----------------------------------------------------------------------

    public func flow(): FlowType {
        return FlowType.Ble
    }

    /**
     * Perform device engagement and start advertising.
     *
     * Creates the ephemeral EDeviceKey in the SecureArea, builds the
     * DeviceEngagement (peripheral-server BLE, fresh UUID), starts the
     * transport and waits for the radio. Returns the QR payload only when
     * the radio reported ready; on radio failure / timeout the key is
     * deleted and a WalletError is thrown.
     *
     * Mirrors iOS performDeviceEngagement + startQrEngagement.
     */
    public func startQrEngagement(): String {
        // A previous session on this service is torn down first.
        this.stop()
        synchronized(monitor) {
            this.stopped = false
            this.failure = None
            this.radioReady = false
            this.linkDisconnected = false
            this.responseDelivered = false
            this.requestBuffer = None
        }

        // 1. Ephemeral P-256 EDeviceKey (key-agreement purpose) in the SecureArea.
        let secureArea = SecureAreaRegistry.shared.get(None)
        let keyId = "engagement-" + bytesToHex(Rng.bytes(8), 0, 8)
        let keyOptions = KeyOptions(
            SaCoseEcCurve.P256, None, None, None, Some([KeyPurpose.KeyAgreement]), None
        )
        try {
            let _ = secureArea.createKeyBatch(keyId, CredentialOptions(CredentialPolicy.OneTimeUse, 1), Some(keyOptions))
        } catch (e: Exception) {
            throw WalletError.withCode(
                "Cannot create the ephemeral engagement key: " + e.message,
                WalletErrorCode.BleNotSupported
            )
        }
        synchronized(monitor) {
            this.engagementSecureArea = Some(secureArea)
            this.engagementKeyId = Some(keyId)
        }
        let devicePub: CoseKey
        try {
            let x963 = secureArea.getPublicKeyBytes(keyId, 0, SaCoseEcCurve.P256)
            devicePub = coseKeyFromX963(x963)
        } catch (e: Exception) {
            this.deleteEphemeralKey()
            throw WalletError.withDescription("Cannot read the ephemeral engagement key: " + e.message)
        }

        // 2. DeviceEngagement (BLE peripheral server mode, fresh v4 UUID).
        let uuidRaw = Rng.bytes(16)
        uuidRaw[6] = (uuidRaw[6] & 0x0Fu8) | 0x40u8
        uuidRaw[8] = (uuidRaw[8] & 0x3Fu8) | 0x80u8
        let serviceUuid = formatAsUuid(uuidRaw)
        // ISO 18013-5 encodes the BLE service UUID as a 16-byte CBOR byte
        // string. Passing the 32 hexadecimal characters as ASCII makes
        // Multipaz/iOS reject DeviceEngagement in UUID.fromByteArray().
        let de: DeviceEngagement = match (DeviceEngagement.forBle(Security(devicePub), false, true, uuidRaw)) {
            case Some(d) => d
            case None =>
                this.deleteEphemeralKey()
                throw WalletError.withDescription("Cannot build the device engagement")
        }
        let deRaw = de.toCborBytes()
        let payload = de.getQrCodePayload()
        synchronized(monitor) {
            this.devicePublicKey = Some(devicePub)
            this.deviceEngagementObj = Some(de)
            this.deviceEngagementRaw = Some(deRaw)
            this.qrPayload = Some(payload)
            this.engagementInfo = Some(DeviceEngagementInfo(serviceUuid))
        }
        this.txLog.add("startQrEngagement", "serviceUuid=" + serviceUuid + " keyId=" + keyId)

        // 3. Ident characteristic value = HKDF-SHA256(salt "", ikm EDeviceKeyBytes,
        //    info "BLEIdent", 16) (§8.3.3.1.5 — optional, interop aid).
        let eDeviceKeyBytes = devicePub.toTaggedEncoded().encode()
        this.transport.setIdentValue(Hkdf.derive(Array<UInt8>(), eDeviceKeyBytes, BLE_IDENT_INFO, 16))

        // 4. Advertise and wait for the radio (PoweredOn / QrEngagementReady).
        this.transport.startBleAdvertising()
        let self_ = this
        let ready = this.awaitCondition(this.engagementTimeout, { =>
            self_.radioReady || self_.failure.isSome() || self_.stopped
        })
        let failureNow: ?String = synchronized(monitor) { this.failure }
        match (failureNow) {
            case Some(reason) =>
                this.teardown()
                throw WalletError.withCode(
                    "Bluetooth is not available: " + reason,
                    WalletErrorCode.BleNotSupported
                )
            case None => ()
        }
        let readyNow: Bool = synchronized(monitor) { this.radioReady }
        if (!ready || !readyNow) {
            this.teardown()
            throw WalletError.withCode(
                "Bluetooth did not power on in time",
                WalletErrorCode.BleNotSupported
            )
        }
        Hilog.info(0, "BlePresentationService",
            "QR engagement ready, serviceUuid=" + serviceUuid + " deLen=" + deRaw.size.toString())
        return payload
    }

    /**
     * Wait for the reader's SessionEstablishment (condition wait with
     * deadline), then establish the session and decode the request.
     * Mirrors iOS receiveRequest + handleStatusChange(.requestReceived).
     */
    public func receiveRequest(): UserRequestInfo {
        let self_ = this
        let arrived = this.awaitCondition(this.requestTimeout, { =>
            self_.requestBuffer.isSome() || self_.failure.isSome() || self_.linkDisconnected || self_.stopped
        })
        let (data, failureNow, disconnectedNow, stoppedNow) = synchronized(monitor) {
            (this.requestBuffer, this.failure, this.linkDisconnected, this.stopped)
        }
        match (failureNow) {
            case Some(reason) => throw WalletError.withDescription("BLE session failed: " + reason)
            case None => ()
        }
        let bytes: Array<UInt8> = match (data) {
            case Some(b) => b
            case None =>
                if (stoppedNow) {
                    throw WalletError.withDescription("Presentation stopped before a request was received")
                }
                if (disconnectedNow) {
                    throw WalletError.withDescription("Reader disconnected before sending a request")
                }
                if (!arrived) {
                    throw WalletError.withDescription("BLE receiveRequest timed out waiting for the reader")
                }
                throw WalletError.withDescription("No request data received")
        }
        // The engagement is consumed once a reader connected (iOS stops
        // advertising on requestReceived).
        this.transport.stopBleAdvertising()
        return this.decodeSessionEstablishment(bytes)
    }

    /**
     * Build, encrypt and send the DeviceResponse for the user-selected
     * items (keyed by storage document id). A frame is always sent: the
     * pre-built error SessionData(status 11) when the response cannot be
     * built. onSuccess fires only after the transport reported ResponseSent.
     *
     * Mirrors iOS sendResponse → userSelected (defer semantics).
     */
    public func sendResponse(
        userSelected: RequestItems,
        onSuccess: ?((String) -> Unit),
        onCancel: ?(String) -> Unit
    ): Unit {
        let (seOpt, drOpt) = synchronized(monitor) {
            (this.sessionEncryption, this.deviceRequest)
        }
        let se: SessionEncryption = match (seOpt) {
            case Some(s) => s
            case None =>
                invokeCancel(onCancel, "Session encryption not initialized")
                return
        }
        let request: DeviceRequest = match (drOpt) {
            case Some(d) => d
            case None =>
                invokeCancel(onCancel, "No device request to answer")
                return
        }
        this.txLog.add("sendResponse", "userSelected docs=" + userSelected.size.toString())

        // Defer semantics: always send something. Start with the error frame.
        var bytesToSend: Array<UInt8> = MdocHelpers.getSessionDataToSend(
            se, TransferStatus.Error, DeviceResponse(DeviceResponse.DEFAULT_VERSION, None, None, UInt64(0)))
        var cleartext: ?Array<UInt8> = None
        var errorReason: ?String = None
        var presented = ArrayList<PresentedDocument>()
        try {
            let (response, docs, clear) = this.buildDeviceResponse(request, se, userSelected)
            match (response.documents) {
                case Some(list) where list.size > 0 =>
                    bytesToSend = MdocHelpers.getSessionDataToSend(se, TransferStatus.RequestReceived, response)
                    cleartext = Some(clear)
                    presented = docs
                case _ =>
                    let docTypeReq: String = if (request.docRequests.size > 0) {
                        request.docRequests[0].itemsRequest.docType
                    } else {
                        ""
                    }
                    errorReason = Some("No document to return for " + docTypeReq)
            }
        } catch (e: WalletError) {
            errorReason = Some(e.message)
        } catch (e: Exception) {
            errorReason = Some("Cannot build the device response: " + e.message)
        }

        synchronized(monitor) {
            this.responseDelivered = false
        }
        Hilog.info(0, "BlePresentationService",
            "Sending " + bytesToSend.size.toString() + " bytes (error=" + errorReason.isSome().toString() + ")")
        this.transport.sendData(bytesToSend)

        match (errorReason) {
            case Some(reason) =>
                Hilog.error(0, "BlePresentationService", "Error response sent: " + reason)
                this.txLog.add("sendResponse", "error: " + reason)
                this.markRecordFailed(reason)
                invokeCancel(onCancel, reason)
                return
            case None => ()
        }

        // Success only when the transport drained the response.
        let self_ = this
        let _ = this.awaitCondition(this.responseTimeout, { =>
            self_.responseDelivered || self_.failure.isSome() || self_.linkDisconnected || self_.stopped
        })
        let (delivered, failureNow, disconnectedNow) = synchronized(monitor) {
            (this.responseDelivered, this.failure, this.linkDisconnected)
        }
        if (!delivered) {
            let reason: String = match (failureNow) {
                case Some(f) => "BLE transport error while sending the response: " + f
                case None =>
                    if (disconnectedNow) {
                        "Reader disconnected before the response was delivered"
                    } else {
                        "Timed out sending the response over BLE"
                    }
            }
            this.txLog.add("sendResponse", "not delivered: " + reason)
            this.markRecordFailed(reason)
            invokeCancel(onCancel, reason)
            return
        }

        let docIds = ArrayList<String>()
        let docTypes = ArrayList<String>()
        for (p in presented) {
            docIds.add(p.docId)
            docTypes.add(p.docType)
        }
        synchronized(monitor) {
            this.deviceResponseBytes = cleartext
            this.presentedDocumentIds = docIds.toArray()
            match ((this.txRecord, cleartext)) {
                case (Some(record), Some(clear)) =>
                    record.markCompleted(clear, docIds.toArray(), docTypes.toArray())
                case _ => ()
            }
        }
        this.txLog.add("sendResponse", "delivered " + bytesToSend.size.toString() + " bytes, docs=" + docIds.size.toString())
        Hilog.info(0, "BlePresentationService",
            "DeviceResponse delivered: " + bytesToSend.size.toString() + " bytes, docs=" + docIds.size.toString())
        this.consumeOneTimeUseCredentials(presented)
        match (onSuccess) {
            case Some(cb) => cb("")
            case None => ()
        }
    }

    public func transactionLog(): ?TransactionLog {
        return Some(this.txLog)
    }

    public func zkpDocumentIds(): Array<String> {
        return Array<String>()
    }

    public func readerCertIssuerName(): ?String {
        synchronized(monitor) {
            return this.lastReaderIssuer
        }
    }

    public func readerCertIssuerValid(): Bool {
        synchronized(monitor) {
            return this.lastReaderTrusted
        }
    }

    public func wrpVerifierPolicy(): ?WrpRegistrationPolicy {
        match (this.wrpRegistrationValidator) {
            case Some(validator) => return validator.wrpVpRegistrationPolicy
            case None => return None
        }
    }

    public func wrpVerifierWarnings(): ?HashMap<String, Array<PresentationPolicyViolation>> {
        if (!this.validateRegistrationCertificate) {
            return None
        }
        match (this.wrpRegistrationValidator) {
            case Some(validator) =>
                // None when the request carried no WRPRC (not evaluated).
                match (validator.wrpVpRegistrationPolicy) {
                    case Some(_) => return Some(validator.wrpVpWarnings)
                    case None =>
                        if (validator.wrpVpWarnings.size > 0) {
                            return Some(validator.wrpVpWarnings)
                        }
                        return None
                }
            case None => return None
        }
    }

    public func readerCertificateChainDer(): ?Array<Array<UInt8>> {
        synchronized(monitor) {
            return this.lastReaderChain
        }
    }

    /**
     * Wait (with deadline) for the reader to end the session (State 0x02 /
     * link drop), then tear the transport down and delete the ephemeral key.
     * Mirrors iOS waitForDisconnect + handleStatusChange(.disconnected → stop).
     */
    public func waitForDisconnect(): Unit {
        let self_ = this
        let ended = this.awaitCondition(this.disconnectTimeout, { =>
            self_.linkDisconnected || self_.failure.isSome() || self_.stopped
        })
        if (!ended) {
            Hilog.warn(0, "BlePresentationService",
                "waitForDisconnect: reader did not end the session in time; closing")
        }
        this.teardown()
    }

    /**
     * Stop the presentation: stop advertising / close the GATT server,
     * delete the ephemeral engagement key and reset the session. Idempotent.
     */
    public func stop(): Unit {
        synchronized(monitor) {
            this.stopped = true
            this.monitor.notifyAll()
        }
        this.teardown()
        synchronized(monitor) {
            this.sessionEncryption = None
            this.deviceRequest = None
            this.requestBuffer = None
            this.deviceEngagementObj = None
            this.deviceEngagementRaw = None
            this.devicePublicKey = None
            this.qrPayload = None
            this.engagementInfo = None
        }
        this.txLog.add("stop", "session stopped")
    }

    // -----------------------------------------------------------------------
    // MdocOfflineDelegate implementation
    // -----------------------------------------------------------------------

    /**
     * Called when BLE subsystem powers on.
     * Mirrors iOS BlePresentationService.didPoweredOn.
     */
    public func didPoweredOn(isPeripheralManager: Bool): Unit {
        Hilog.info(0, "BlePresentationService",
            "BLE powered on, isPeripheralManager=" + isPeripheralManager.toString())
        synchronized(monitor) {
            if (isPeripheralManager) {
                this.radioReady = true
            }
            this.monitor.notifyAll()
        }
        this.txLog.add("didPoweredOn", isPeripheralManager.toString())
    }

    /**
     * Called when a BLE connection is established.
     * Mirrors iOS BlePresentationService.didConnected.
     */
    public func didConnected(isPeripheral: Bool, deviceName: ?String): Unit {
        let name = match (deviceName) {
            case Some(n) => n
            case None => "unknown"
        }
        Hilog.info(0, "BlePresentationService",
            "BLE connected, isPeripheral=" + isPeripheral.toString() + " deviceName=" + name)
        this.txLog.add("didConnected", name)
    }

    /**
     * Called when BLE transfer status changes.
     * Mirrors iOS BlePresentationService.didChangeStatus / handleStatusChange.
     */
    public func didChangeStatus(newStatus: TransferStatus): Unit {
        let statusStr = transferStatusToString(newStatus)
        Hilog.info(0, "BlePresentationService", "BLE status changed: " + statusStr)
        this.txLog.add("didChangeStatus", statusStr)

        var observer: ?((TransferStatus) -> Unit) = None
        var deleteKey = false
        synchronized(monitor) {
            this.lastStatus = newStatus
            match (newStatus) {
                case TransferStatus.PoweredOn => this.radioReady = true
                case TransferStatus.QrEngagementReady => this.radioReady = true
                case TransferStatus.ResponseSent => this.responseDelivered = true
                case TransferStatus.Disconnected =>
                    this.linkDisconnected = true
                    deleteKey = true
                case TransferStatus.Error =>
                    match (this.failure) {
                        case Some(_) => ()
                        case None => this.failure = Some("BLE transport error")
                    }
                case _ => ()
            }
            this.monitor.notifyAll()
            observer = this.transferStatusObserver
        }
        // The reader ended the session (0x02) or the link dropped: the
        // ephemeral key is no longer needed (transport contract: our job).
        if (deleteKey) {
            this.deleteEphemeralKey()
        }
        match (observer) {
            case Some(cb) => cb(newStatus)
            case None => ()
        }
    }

    /**
     * Called when the transport has reassembled the full SessionEstablishment
     * bytes. Stores them for receiveRequest() to consume.
     * Mirrors iOS BlePresentationService.didReceiveRequest.
     */
    public func didReceiveRequest(data: Array<UInt8>): Unit {
        Hilog.info(0, "BlePresentationService",
            "Received BLE request: " + data.size.toString() + " bytes")
        synchronized(monitor) {
            this.requestBuffer = Some(data)
            this.monitor.notifyAll()
        }
        this.txLog.add("didReceiveRequest", data.size.toString() + " bytes")
    }

    /**
     * Called when a non-recoverable BLE error occurs.
     * Mirrors iOS BlePresentationService.didFinishedWithError.
     */
    public func didFinishedWithError(code: ErrorCode, message: String): Unit {
        Hilog.error(0, "BlePresentationService",
            "BLE error code=" + code.describe() + " msg=" + message)
        synchronized(monitor) {
            this.failure = Some(code.describe() + ": " + message)
            this.monitor.notifyAll()
        }
        this.txLog.add("didFinishedWithError", message)
    }

    /**
     * Return the DeviceEngagementInfo for BLE advertising.
     * Called by the transport layer to get the service UUID.
     */
    public func deviceEngagement(): ?DeviceEngagementInfo {
        synchronized(monitor) {
            return this.engagementInfo
        }
    }

    // -----------------------------------------------------------------------
    // Session establishment + request decoding (WP2 / WP3)
    // -----------------------------------------------------------------------

    /**
     * Establish the session from the reader's SessionEstablishment and
     * decode the request:
     *   SessionTranscript = [tag24(DE raw), tag24(EReaderKey raw), null]
     *   ECKA-DH via the SecureArea ephemeral key → HKDF SKReader → AES-GCM
     *   DeviceRequest → ReaderAuth signature + chain → WRPRC → UserRequestInfo
     */
    private func decodeSessionEstablishment(data: Array<UInt8>): UserRequestInfo {
        let (deRawOpt, keyIdOpt, saOpt, devicePubOpt) = synchronized(monitor) {
            this.lastReaderIssuer = None
            this.lastReaderTrusted = false
            this.lastReaderChain = None
            this.lastReaderAuthBytes = None
            (this.deviceEngagementRaw, this.engagementKeyId, this.engagementSecureArea, this.devicePublicKey)
        }
        let deRaw: Array<UInt8> = match (deRawOpt) {
            case Some(b) => b
            case None => throw WalletError.withDescription("Device engagement not initialized")
        }
        let keyId: String = match (keyIdOpt) {
            case Some(k) => k
            case None => throw WalletError.withDescription("Device engagement key not available")
        }
        let secureArea: SecureArea = match (saOpt) {
            case Some(sa) => sa
            case None => throw WalletError.withDescription("SecureArea not available for the session")
        }
        let devicePub: CoseKey = match (devicePubOpt) {
            case Some(k) => k
            case None => throw WalletError.withDescription("Device engagement public key not available")
        }

        // SessionEstablishment { eReaderKey: tag24(COSE_Key), data: bstr }
        let se: SessionEstablishment
        try {
            se = SessionEstablishment.fromCborBytes(data)
        } catch (e: Exception) {
            throw WalletError.withDescription("Request is not a SessionEstablishment: " + e.message)
        }
        let eReaderRaw: Array<UInt8> = match (se.eReaderKeyRawData) {
            case Some(b) => b
            case None => throw WalletError.withDescription("Reader key not available in SessionEstablishment")
        }
        let eReaderKey: CoseKey
        try {
            eReaderKey = CoseKey.fromCborMap(decodeCbor(eReaderRaw))
        } catch (e: Exception) {
            throw WalletError.withDescription("Could not decode the reader ephemeral key: " + e.message)
        }

        // SessionEncryption for the mdoc role; ECDH through the SecureArea key.
        let devicePriv = CoseKeyPrivate(Some(devicePub), keyId, EngCoseEcCurve.P256)
        let sessionEnc = SessionEncryption(
            SessionRole.Mdoc,
            CoseKeyExchange(Some(eReaderKey), devicePriv),
            deRaw,
            eReaderRaw,
            QR_HANDOVER_NULL
        )
        sessionEnc.keyAgreement = Some(SecureAreaSessionKeyAgreement(secureArea, keyId, 0))

        // Decrypt + decode + reader authentication (signature AND chain).
        let decoded: DecodeRequestResult
        try {
            decoded = MdocHelpers.decodeRequestAndInformUser(
                data,
                sessionEnc,
                this.readerRootAnchors(),
                readerCertTrust: this.readerCertTrust
            )
        } catch (e: Exception) {
            Hilog.error(0, "BlePresentationService", "decodeRequestAndInformUser failed: " + e.message)
            throw WalletError.withDescription("Cannot decode the device request: " + e.message)
        }
        let request = decoded.deviceRequest

        // Reader identity + trust for the UI and the transaction log.
        var sawReaderAuth = false
        var allTrusted = true
        var chain: ?Array<Array<UInt8>> = None
        var readerAuthBytes: ?Array<UInt8> = None
        for (docReq in request.docRequests) {
            match (docReq.readerAuth) {
                case Some(ra) =>
                    sawReaderAuth = true
                    if (chain.isNone() && ra.x5chain.size > 0) {
                        chain = Some(ra.x5chain)
                    }
                    if (readerAuthBytes.isNone()) {
                        match (docReq.readerAuthRawCbor) {
                            case Some(raw) => readerAuthBytes = Some(raw.encode())
                            case None => readerAuthBytes = Some(ra.toCbor().encode())
                        }
                    }
                case None => allTrusted = false
            }
        }
        for ((docType, validated) in decoded.userRequestInfo.readerAuthResults) {
            if (!validated) {
                allTrusted = false
                Hilog.warn(0, "BLE-TRUST", "reader auth not validated docType=" + docType)
            } else {
                Hilog.info(0, "BLE-TRUST", "reader auth validated docType=" + docType)
            }
        }
        let readerTrusted = sawReaderAuth && allTrusted && request.docRequests.size > 0
        let readerName: ?String = match (chain) {
            case Some(c) => readerDisplayName(c[0])
            case None => None
        }
        synchronized(monitor) {
            this.lastReaderChain = chain
            this.lastReaderAuthBytes = readerAuthBytes
            this.lastReaderIssuer = readerName
            this.lastReaderTrusted = readerTrusted
        }

        // WRPRC (euWrprc) — Enforce throws WalletError(InvalidWrprc).
        this.validateDeviceRequestRegistration(request)

        // Requested items keyed by docType, paths [namespace, elementId].
        var userInfo = UserRequestInfo(
            decoded.userRequestInfo.deviceRequestBytes,
            buildItemsRequested(request)
        )
        userInfo.readerAuthResults = decoded.userRequestInfo.readerAuthResults

        // Relying party name: WRPRC policy name, else reader certificate CN.
        let policyName: ?String = match (this.wrpVerifierPolicy()) {
            case Some(policy) => policy.name
            case None => None
        }
        let rpName: ?String = match (policyName) {
            case Some(n) where !n.isEmpty() => Some(n)
            case _ => readerName
        }
        let record = PresentationTransactionRecord(
            TransactionLogUtils.getTimestamp(),
            rpName,
            readerTrusted,
            chain,
            readerAuthBytes,
            Some(decoded.userRequestInfo.deviceRequestBytes),
            Some(sessionEnc.sessionTranscript().toCborBytes())
        )
        synchronized(monitor) {
            this.sessionEncryption = Some(sessionEnc)
            this.deviceRequest = Some(request)
            this.lastUserRequestInfo = Some(userInfo)
            this.rawRequestBytes = Some(decoded.userRequestInfo.deviceRequestBytes)
            this.txRecord = Some(record)
        }
        this.txLog.add("receiveRequest",
            "docRequests=" + request.docRequests.size.toString() + " readerTrusted=" + readerTrusted.toString())

        // iOS: an invalid request (no stored document matches) answers with
        // the error SessionData and fails the session.
        if (!decoded.isValidRequest || !this.anyStoredDocumentMatches(request)) {
            let errorFrame = MdocHelpers.getSessionDataToSend(
                sessionEnc, TransferStatus.Error,
                DeviceResponse(DeviceResponse.DEFAULT_VERSION, None, None, UInt64(0)))
            this.transport.sendData(errorFrame)
            record.markFailed("No document available for the requested document types")
            throw WalletError.withCode(
                "No document available for the requested document types",
                WalletErrorCode.NoDocumentsAvailable
            )
        }
        return userInfo
    }

    /**
     * WRPRC validation for a decoded DeviceRequest. No-op when validation is
     * disabled, no validator was injected, or the request carries no euWrprc
     * entry (registration not evaluated → app shows notSupported). A
     * NotGranted verdict (Enforce policy) throws WalletError(InvalidWrprc);
     * under the Warning policy violations surface via wrpVerifierWarnings.
     */
    private func validateDeviceRequestRegistration(deviceRequest: DeviceRequest): Unit {
        if (!this.validateRegistrationCertificate) {
            return
        }
        let validator: WrpVpRegistrationValidator = match (this.wrpRegistrationValidator) {
            case Some(v) => v
            case None => return
        }
        // WRPAC = the reader authentication leaf certificate, when available.
        let chainNow: ?Array<Array<UInt8>> = synchronized(monitor) { this.lastReaderChain }
        let wrpac: ?Cert = match (chainNow) {
            case Some(chain) =>
                try {
                    Some(Cert.fromDer(chain[0]))
                } catch (_: Exception) {
                    None
                }
            case None => None
        }
        // DCQL equivalent of the requested items, for scope validation
        // (mirrors iOS OpenId4VpUtils.makeDcql(itemsRequested:)).
        let dcql: ?DCQL = try {
            Some(makeDcqlFromDeviceRequest(deviceRequest))
        } catch (e: Exception) {
            Hilog.warn(0, "BLE-TRUST", "cannot build DCQL for WRPRC scope check: " + e.message)
            None
        }
        match (validator.validateDeviceRequestCertificate(wrpac, deviceRequest, dcql)) {
            case None =>
                Hilog.info(0, "BLE-TRUST", "device request carries no WRPRC (euWrprc)")
            case Some(RegistrationCertificateAuthorization.Granted) => ()
            case Some(RegistrationCertificateAuthorization.NotGranted(reason)) =>
                Hilog.error(0, "BLE-TRUST", "WRPRC policy not met: " + reason)
                throw WalletError.withCode(
                    "Proximity request blocked by WRPRC policy: " + reason,
                    WalletErrorCode.InvalidWrprc
                )
        }
    }

    /**
     * Build a DCQL query equivalent to the items requested in an ISO/IEC
     * 18013-5 device request: one mso-mdoc credential query per requested
     * document type. Mirrors iOS OpenId4VpUtils.makeDcql(itemsRequested:).
     */
    private func makeDcqlFromDeviceRequest(deviceRequest: DeviceRequest): DCQL {
        let credentials = ArrayList<CredentialQuery>()
        var index: Int64 = 0
        for (docReq in deviceRequest.docRequests) {
            let itemsReq = docReq.itemsRequest
            let claims = ArrayList<ClaimsQuery>()
            for ((ns, rde) in itemsReq.requestNameSpaces.nameSpaces) {
                for ((elementId, intentToRetain) in rde.dataElements) {
                    claims.add(ClaimsQuery.mdoc(
                        namespace: ns,
                        claimName: elementId,
                        intentToRetain: Some(intentToRetain)
                    ))
                }
            }
            let claimsOpt: ?Array<ClaimsQuery> = if (claims.size == 0) {
                None
            } else {
                Some(claims.toArray())
            }
            credentials.add(CredentialQuery(
                queryId: QueryId("cred" + index.toString()),
                format: Format.msoMdoc(),
                metaJson: Some("{\"doctype_value\":\"" + itemsReq.docType + "\"}"),
                claims: claimsOpt
            ))
            index += 1
        }
        return DCQL(credentials.toArray())
    }

    /** True when an issued mso_mdoc document exists for any requested docType. */
    private func anyStoredDocumentMatches(deviceRequest: DeviceRequest): Bool {
        let issued: ArrayList<Document> = match (this.storageManager.loadDocuments(DocumentStatus.Issued)) {
            case Some(docs) => docs
            case None => return false
        }
        for (docReq in deviceRequest.docRequests) {
            let docType = docReq.itemsRequest.docType
            for (doc in issued) {
                if (doc.docType == docType && isCborDocument(doc)) {
                    return true
                }
            }
        }
        return false
    }

    /** Trusted reader root anchors (DER) for the offline chain path. */
    private func readerRootAnchors(): Array<Array<UInt8>> {
        match (this.trustConfiguration) {
            case Some(cfg) => cfg.accessTrustManager.trustAnchorsDer()
            case None => Array<Array<UInt8>>()
        }
    }

    // -----------------------------------------------------------------------
    // Response construction (WP4)
    // -----------------------------------------------------------------------

    /**
     * Build the DeviceResponse for the selected items (docId → namespace →
     * [RequestItem]). Per document: IssuerNameSpaces filtered to the selected
     * elements (elements requested but absent go to Errors), DeviceSigned
     * with the configured DeviceAuth, assembled through
     * MdocHelpers.getDeviceResponseToSend. Unknown ids are skipped; documents
     * with nothing to disclose become documentErrors.
     *
     * @return (response, presented documents, cleartext DeviceResponse CBOR)
     */
    private func buildDeviceResponse(
        request: DeviceRequest,
        se: SessionEncryption,
        userSelected: RequestItems
    ): (DeviceResponse, ArrayList<PresentedDocument>, Array<UInt8>) {
        let issued: ArrayList<Document> = match (this.storageManager.loadDocuments(DocumentStatus.Issued)) {
            case Some(docs) => docs
            case None => throw WalletError.withCode("No issued documents", WalletErrorCode.NoDocumentsAvailable)
        }
        let rootAnchors = this.readerRootAnchors()
        let docsOut = ArrayList<MdocDocument>()
        let docErrors = ArrayList<DocumentError>()
        let presented = ArrayList<PresentedDocument>()

        for ((docId, nsSelection) in userSelected) {
            let stored: Document = match (findStoredDocument(issued, docId)) {
                case Some(d) => d
                case None =>
                    Hilog.warn(0, "BlePresentationService", "selected docId not stored: " + docId)
                    continue
            }
            let issuerSigned = parseIssuerSigned(stored.data)
            let docType = issuerSigned.issuerAuth.mso.docType
            let docReqOpt = findDocRequest(request, docType)
            let issuerNs: IssuerNameSpaces = match (issuerSigned.issuerNameSpaces) {
                case Some(ns) => ns
                case None =>
                    Hilog.error(0, "BlePresentationService", "document without issuer namespaces: " + docId)
                    docErrors.add(documentErrorFor(docType))
                    continue
            }

            // Namespaces / element identifiers to respond with: the user's
            // selection, or everything the issuer signed when the selection
            // carries no namespaces (iOS: empty docSelectedItems).
            let wanted = HashMap<String, ArrayList<String>>()
            let wantedOrder = ArrayList<String>()
            if (nsSelection.size == 0) {
                for ((ns, items) in issuerNs.nameSpaces) {
                    let ids = ArrayList<String>()
                    for (item in items) {
                        ids.add(item.elementIdentifier)
                    }
                    wanted[ns] = ids
                    wantedOrder.add(ns)
                }
            } else {
                for ((ns, reqItems) in nsSelection) {
                    let ids = ArrayList<String>()
                    for (ri in reqItems) {
                        if (ri.elementPath.size > 0) {
                            ids.add(ri.elementPath[ri.elementPath.size - 1])
                        }
                    }
                    wanted[ns] = ids
                    wantedOrder.add(ns)
                }
            }

            let filteredNs = HashMap<String, ArrayList<IssuerSignedItem>>()
            let nsErrors = HashMap<String, HashMap<String, UInt64>>()
            let keptItems = ArrayList<RequestItem>()
            for (ns in wantedOrder) {
                let ids = wanted[ns]
                let itemsOpt = issuerNs.get(ns)
                let items: ArrayList<IssuerSignedItem> = match (itemsOpt) {
                    case Some(list) => list
                    case None =>
                        let missing = HashMap<String, UInt64>()
                        for (id in ids) {
                            missing[id] = UInt64(0)
                        }
                        nsErrors[ns] = missing
                        continue
                }
                let present = HashMap<String, Bool>()
                let kept = ArrayList<IssuerSignedItem>()
                for (item in items) {
                    if (containsString(ids, item.elementIdentifier)) {
                        kept.add(item)
                        present[item.elementIdentifier] = true
                        let intent: ?Bool = match (docReqOpt) {
                            case Some(dr) =>
                                match (dr.itemsRequest.requestNameSpaces.get(ns)) {
                                    case Some(rde) =>
                                        if (rde.dataElements.contains(item.elementIdentifier)) {
                                            Some(rde.dataElements[item.elementIdentifier])
                                        } else {
                                            None
                                        }
                                    case None => None
                                }
                            case None => None
                        }
                        keptItems.add(RequestItem([item.elementIdentifier], intent, None))
                    }
                }
                if (kept.size > 0) {
                    filteredNs[ns] = kept
                }
                let missing = HashMap<String, UInt64>()
                for (id in ids) {
                    if (!present.contains(id)) {
                        missing[id] = UInt64(0)
                    }
                }
                if (missing.size > 0) {
                    nsErrors[ns] = missing
                }
            }
            if (filteredNs.size == 0) {
                docErrors.add(documentErrorFor(docType))
                continue
            }

            // DeviceSigned: DeviceAuth over the SessionTranscript with the
            // document's SecureArea key.
            let keyInfo: ?DocKeyInfo = decodeDocKeyInfo(stored.docKeyInfo)
            let secureAreaName: ?String = match (keyInfo) {
                case Some(ki) => ki.secureAreaName
                case None => None
            }
            let secureArea = SecureAreaRegistry.shared.get(secureAreaName)
            let keyIndex = Oid4VpDeviceAuth.matchDeviceKeyIndex(secureArea, docId, issuerSigned)
            let deviceSigned = this.buildDeviceSigned(
                docId, keyIndex, docType, issuerSigned, se, secureArea, stored.docKeyInfo)

            // Assemble through the orchestration layer (per document, so
            // several documents of one docType never collide).
            let filteredIssuerSigned = IssuerSigned(Some(IssuerNameSpaces(filteredNs)), issuerSigned.issuerAuth)
            let assembled = MdocHelpers.getDeviceResponseToSend(
                request,
                [(docId, filteredIssuerSigned)],
                [(docType, keptItems.toArray())],
                se,
                rootAnchors,
                [(docType, deviceSigned)],
                readerCertTrust: this.readerCertTrust
            )
            match (assembled.documents) {
                case Some(list) where list.size > 0 =>
                    let d = list[0]
                    let errorsOpt: ?MdocErrors = if (nsErrors.size > 0) {
                        Some(MdocErrors(nsErrors))
                    } else {
                        None
                    }
                    docsOut.add(MdocDocument(d.docType, d.issuerSigned, d.deviceSigned, errorsOpt))
                    presented.add(PresentedDocument(docId, docType, keyIndex, secureAreaName))
                case _ =>
                    docErrors.add(documentErrorFor(docType))
            }
        }

        let docsOpt: ?ArrayList<MdocDocument> = if (docsOut.size > 0) { Some(docsOut) } else { None }
        let errOpt: ?ArrayList<DocumentError> = if (docErrors.size > 0) { Some(docErrors) } else { None }
        let response = DeviceResponse(DeviceResponse.DEFAULT_VERSION, docsOpt, errOpt, UInt64(0))
        return (response, presented, response.toCbor().encode())
    }

    /**
     * DeviceSigned for one document: DeviceNameSpaces (requested device
     * namespaces checked against the MSO keyAuthorizations, else empty) and
     * DeviceAuth per the configured method:
     *   deviceMac       — EMacKey = HKDF(ECDH(document device key, EReaderKey),
     *                     salt SessionTranscriptBytes, "EMacKey"), COSE_Mac0
     *   deviceSignature — ES256 COSE_Sign1 signed inside the SecureArea
     *                     (or a persisted software proof key for legacy docs)
     */
    private func buildDeviceSigned(
        docId: String,
        keyIndex: Int64,
        docType: String,
        issuerSigned: IssuerSigned,
        se: SessionEncryption,
        secureArea: SecureArea,
        docKeyInfo: ?Array<UInt8>
    ): DeviceSigned {
        let deviceNs: DeviceNameSpaces = synchronized(monitor) {
            if (this.deviceNameSpacesToSend.contains(docId)) {
                this.deviceNameSpacesToSend[docId]
            } else {
                DeviceNameSpaces(ArrayList<(String, DeviceSignedItems)>())
            }
        }
        enforceKeyAuthorizations(docId, issuerSigned.issuerAuth.mso.deviceKeyInfo.keyAuthorizations, deviceNs)
        let nsBytes = deviceNs.toCbor().encode()
        let transcript = se.sessionTranscript()
        let auth = MdocAuthentication(transcript, se.sessionKeys)
        let softwareKey = Oid4VpDeviceAuth.holderProofKey(docKeyInfo)

        match (this.deviceAuthMethod) {
            case DeviceAuthMethod.DeviceMac =>
                if (softwareKey.isNone()) {
                    try {
                        let eReaderKey: CoseKey = match (se.sessionKeys.publicKey) {
                            case Some(k) => k
                            case None => throw WalletError.withDescription("Reader ephemeral key missing")
                        }
                        let peerX963 = buildP256X963PublicKey(eReaderKey.x, eReaderKey.y)
                        let shared = secureArea.keyAgreement(docId, keyIndex, peerX963, None)
                        let mac0 = auth.makeDeviceMac(docType, nsBytes, shared)
                        Hilog.info(0, "BlePresentationService", "DeviceAuth deviceMac docId=" + docId)
                        return DeviceSigned(deviceNs, DeviceAuth(false, mac0.toCborArray()))
                    } catch (e: Exception) {
                        if (!this.deviceMacFallbackToSignature) {
                            throw WalletError.withDescription(
                                "deviceMac unavailable for " + docId + ": " + e.message)
                        }
                        Hilog.warn(0, "BlePresentationService",
                            "deviceMac unavailable for " + docId + " (" + e.message
                            + "); falling back to deviceSignature")
                    }
                } else if (!this.deviceMacFallbackToSignature) {
                    throw WalletError.withDescription(
                        "deviceMac unavailable for " + docId + ": software proof key cannot do ECDH")
                }
            case DeviceAuthMethod.DeviceSignature => ()
        }

        // ES256 COSE_Sign1 (detached) over DeviceAuthenticationBytes.
        let sign1 = match (softwareKey) {
            case Some(priv) =>
                Hilog.info(0, "BlePresentationService", "DeviceAuth deviceSignature (persisted proof key) docId=" + docId)
                auth.makeDeviceSignatureWithSigner(docType, nsBytes, { input: Array<UInt8> =>
                    EcdsaP256.sign(priv, input)
                })
            case None =>
                Hilog.info(0, "BlePresentationService",
                    "DeviceAuth deviceSignature (SecureArea keyIndex=" + keyIndex.toString() + ") docId=" + docId)
                auth.makeDeviceSignatureWithSigner(docType, nsBytes, { input: Array<UInt8> =>
                    secureArea.signature(docId, keyIndex, SigningAlgorithm.ES256, input, None)
                })
        }
        // ISO 18013-5 embeds DeviceSignature as the bare COSE_Sign1 array.
        // Do not add the optional RFC 9052 tag 18 here.  The iOS wallet's
        // DeviceAuth.toCBOR likewise stores Cose.toCBOR(), and strict readers
        // (including Multipaz) reject a tagged value at this field.
        return DeviceSigned(deviceNs, DeviceAuth(true, sign1.toCbor()))
    }

    /**
     * One-time-use consumption after a delivered response (iOS
     * updateKeyBatchInfoAndDeleteCredentialIfNeeded): bump the key's usage
     * count in the SecureArea batch info and, under the OneTimeUse policy,
     * delete the presented credential row so the remaining count drops.
     */
    private func consumeOneTimeUseCredentials(presented: ArrayList<PresentedDocument>): Unit {
        for (p in presented) {
            try {
                let secureArea = SecureAreaRegistry.shared.get(p.secureAreaName)
                let batchInfo = secureArea.getKeyBatchInfo(p.docId)
                if (p.keyIndex < 0 || p.keyIndex >= batchInfo.batchSize()) {
                    continue
                }
                let updated = KeyBatchInfo.afterUse(batchInfo, p.keyIndex)
                let metaSlot = HashMap<String, Array<UInt8>>()
                metaSlot["kbiBytes"] = updated.toBytes()
                secureArea.getStorage().writeKeyInfo(p.docId + "_meta", metaSlot)
                match (updated.credentialPolicy) {
                    case CredentialPolicy.OneTimeUse =>
                        let storageService = this.storageManager.storageService
                        if (storageService.countDocumentCredentials(p.docId) > 0) {
                            storageService.deleteDocumentCredential(p.docId, p.keyIndex)
                            Hilog.info(0, "BlePresentationService",
                                "one-time-use credential consumed docId=" + p.docId + " index=" + p.keyIndex.toString())
                        }
                    case CredentialPolicy.RotateUse => ()
                }
            } catch (e: Exception) {
                Hilog.warn(0, "BlePresentationService",
                    "credential usage update failed docId=" + p.docId + ": " + e.message)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Lifecycle helpers
    // -----------------------------------------------------------------------

    /** Stop the transport and delete the ephemeral key (idempotent). */
    private func teardown(): Unit {
        try {
            this.transport.stop()
        } catch (e: Exception) {
            Hilog.warn(0, "BlePresentationService", "transport.stop: " + e.message)
        }
        this.deleteEphemeralKey()
    }

    /** Delete the ephemeral EDeviceKey from the SecureArea, once. */
    private func deleteEphemeralKey(): Unit {
        let (saOpt, keyIdOpt) = synchronized(monitor) {
            let pair = (this.engagementSecureArea, this.engagementKeyId)
            this.engagementKeyId = None
            pair
        }
        match ((saOpt, keyIdOpt)) {
            case (Some(sa), Some(keyId)) =>
                try {
                    sa.deleteKeyBatch(keyId, 0, 1)
                } catch (e: Exception) {
                    Hilog.warn(0, "BlePresentationService", "deleteKeyBatch " + keyId + ": " + e.message)
                }
                try {
                    sa.deleteKeyInfo(keyId)
                } catch (e: Exception) {
                    Hilog.warn(0, "BlePresentationService", "deleteKeyInfo " + keyId + ": " + e.message)
                }
                Hilog.info(0, "BlePresentationService", "ephemeral engagement key deleted: " + keyId)
            case _ => ()
        }
    }

    private func markRecordFailed(reason: String): Unit {
        synchronized(monitor) {
            match (this.txRecord) {
                case Some(record) => record.markFailed(reason)
                case None => ()
            }
        }
    }

    /**
     * Block until predicate() holds or the deadline elapses (condition wait,
     * no busy-spin). Returns whether the predicate held on exit.
     */
    private func awaitCondition(deadline: Duration, predicate: () -> Bool): Bool {
        synchronized(monitor) {
            var remaining = deadline
            while (!predicate()) {
                if (remaining <= Duration.Zero) {
                    break
                }
                let started = MonoTime.now()
                this.monitor.wait(timeout: remaining)
                remaining = remaining - (MonoTime.now() - started)
            }
            return predicate()
        }
    }

    private func invokeCancel(onCancel: ?(String) -> Unit, reason: String): Unit {
        match (onCancel) {
            case Some(cb) => cb(reason)
            case None => ()
        }
    }

    /** Convert TransferStatus enum to a descriptive string for logging. */
    private func transferStatusToString(status: TransferStatus): String {
        match (status) {
            case TransferStatus.Initializing => return "Initializing"
            case TransferStatus.Initialized => return "Initialized"
            case TransferStatus.PoweredOn => return "PoweredOn"
            case TransferStatus.QrEngagementReady => return "QrEngagementReady"
            case TransferStatus.Connected => return "Connected"
            case TransferStatus.Started => return "Started"
            case TransferStatus.RequestReceived => return "RequestReceived"
            case TransferStatus.UserSelected => return "UserSelected"
            case TransferStatus.ResponseSent => return "ResponseSent"
            case TransferStatus.Disconnected => return "Disconnected"
            case TransferStatus.Error => return "Error"
        }
    }
}

// ===========================================================================
// Module-level helpers
// ===========================================================================

/** Requested items keyed by docType with element paths [namespace, elementId]. */
func buildItemsRequested(deviceRequest: DeviceRequest): Array<(String, Array<RequestItem>)> {
    let out = ArrayList<(String, Array<RequestItem>)>()
    for (docReq in deviceRequest.docRequests) {
        let itemsReq = docReq.itemsRequest
        let items = ArrayList<RequestItem>()
        for ((ns, rde) in itemsReq.requestNameSpaces.nameSpaces) {
            for ((elementId, intentToRetain) in rde.dataElements) {
                items.add(RequestItem([ns, elementId], Some(intentToRetain), None))
            }
        }
        out.add((itemsReq.docType, items.toArray()))
    }
    return out.toArray()
}

/** The DocRequest for a docType, if the reader asked for it. */
func findDocRequest(deviceRequest: DeviceRequest, docType: String): ?DocRequest {
    for (docReq in deviceRequest.docRequests) {
        if (docReq.itemsRequest.docType == docType) {
            return Some(docReq)
        }
    }
    return None
}

/** Issued mso_mdoc document by storage id. */
func findStoredDocument(issued: ArrayList<Document>, docId: String): ?Document {
    for (doc in issued) {
        if (doc.id == docId && isCborDocument(doc)) {
            return Some(doc)
        }
    }
    return None
}

func isCborDocument(doc: Document): Bool {
    match (doc.docDataFormat) {
        case StorageDocDataFormat.Cbor => true
        case _ => false
    }
}

/**
 * Stored credential data is either raw IssuerSigned CBOR or the base64url
 * text of it (issuance stores the encoded form) — same dual-path decode as
 * the OpenID4VP holder proof.
 */
func parseIssuerSigned(data: Array<UInt8>): IssuerSigned {
    let raw = if (presLooksLikeBase64UrlTextBytes(data)) {
        Base64Url.decode(String.fromUtf8(data))
    } else {
        data
    }
    return IssuerSigned.fromCbor(decodeCbor(raw))
}

func decodeDocKeyInfo(bytes: ?Array<UInt8>): ?DocKeyInfo {
    match (bytes) {
        case Some(b) =>
            try {
                Some(DocKeyInfo.fromBytes(b))
            } catch (_: Exception) {
                None
            }
        case None => None
    }
}

func documentErrorFor(docType: String): DocumentError {
    let errMap = HashMap<String, UInt64>()
    errMap[docType] = UInt64(0)
    return DocumentError(errMap)
}

func containsString(list: ArrayList<String>, value: String): Bool {
    for (s in list) {
        if (s == value) {
            return true
        }
    }
    return false
}

/**
 * Device-signed namespaces must be authorised by the MSO keyAuthorizations:
 * either the whole namespace, or every device-signed element of it.
 * Mirrors iOS MdocHelpers.getDeviceResponseToSend (returns nil there; here a
 * WalletError so the presentation fails with a reason).
 */
func enforceKeyAuthorizations(docId: String, keyAuthorizations: ?KeyAuthorizations, deviceNs: DeviceNameSpaces): Unit {
    for ((ns, items) in deviceNs.deviceNameSpaces) {
        let nsAuthorised: Bool = match (keyAuthorizations) {
            case Some(ka) =>
                match (ka.nameSpaces) {
                    case Some(list) => containsString(list, ns)
                    case None => false
                }
            case None => false
        }
        if (nsAuthorised) {
            continue
        }
        for ((elementId, _) in items.items) {
            let elementAuthorised: Bool = match (keyAuthorizations) {
                case Some(ka) =>
                    match (ka.dataElements) {
                        case Some(map) =>
                            if (map.contains(ns)) {
                                containsString(map[ns], elementId)
                            } else {
                                false
                            }
                        case None => false
                    }
                case None => false
            }
            if (!elementAuthorised) {
                throw WalletError.withDescription(
                    "Requested device namespace is not authorized by issuer auth: docId=" + docId
                    + " namespace=" + ns + " element=" + elementId)
            }
        }
    }
}

/** Reader display name from the leaf certificate subject (CN, else O). */
func readerDisplayName(leafDer: Array<UInt8>): ?String {
    try {
        let cert = Cert.fromDer(leafDer)
        match (subjectAttributeValue(cert, OID_COMMON_NAME)) {
            case Some(cn) where !cn.isEmpty() => return Some(cn)
            case _ => ()
        }
        match (subjectAttributeValue(cert, OID_ORGANIZATION_NAME)) {
            case Some(o) where !o.isEmpty() => return Some(o)
            case _ => ()
        }
        return None
    } catch (e: Exception) {
        Hilog.warn(0, "BLE-TRUST", "reader certificate subject not readable: " + e.message)
        return None
    }
}

/** COSE_Key (P-256) from a 65-byte uncompressed x963 point. */
func coseKeyFromX963(x963: Array<UInt8>): CoseKey {
    if (x963.size != 65 || x963[0] != 0x04u8) {
        throw WalletError.withDescription("SecureArea public key is not an uncompressed P-256 point")
    }
    let x = Array<UInt8>(32, {i => x963[1 + i]})
    let y = Array<UInt8>(32, {i => x963[33 + i]})
    return CoseKey(EngCoseEcCurve.P256, x, y)
}

/**
 * Format 16 bytes as a UUID string (8-4-4-4-12 lowercase hex groups) — the
 * form ConnectivityKit takes for the GATT service / advertising UUID.
 */
func formatAsUuid(bytes: Array<UInt8>): String {
    let g1 = bytesToHex(bytes, 0, 4)
    let g2 = bytesToHex(bytes, 4, 6)
    let g3 = bytesToHex(bytes, 6, 8)
    let g4 = bytesToHex(bytes, 8, 10)
    let g5 = bytesToHex(bytes, 10, 16)
    return g1 + "-" + g2 + "-" + g3 + "-" + g4 + "-" + g5
}

/** Convert bytes[start..<end] to lowercase hex string. */
func bytesToHex(bytes: Array<UInt8>, start: Int64, end: Int64): String {
    let hexChars: Array<UInt8> = [
        0x30u8, 0x31u8, 0x32u8, 0x33u8, 0x34u8, 0x35u8, 0x36u8, 0x37u8,
        0x38u8, 0x39u8, 0x61u8, 0x62u8, 0x63u8, 0x64u8, 0x65u8, 0x66u8
    ]
    let count = end - start
    let out = Array<UInt8>(count * 2, repeat: 0u8)
    var i: Int64 = start
    var j: Int64 = 0
    while (i < end) {
        let b = bytes[i]
        out[j] = hexChars[Int64(b >> 4)]
        out[j + 1] = hexChars[Int64(b & 0x0Fu8)]
        i += 1
        j += 2
    }
    return String.fromUtf8(out)
}
