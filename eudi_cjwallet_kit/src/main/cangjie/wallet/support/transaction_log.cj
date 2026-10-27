/*
 * transaction_log.cj
 *
 * EUDI Wallet Kit — Transaction log data model and utilities.
 *
 * Cangjie ports of:
 *   Sources/EudiWalletKit/Services/TransactionLogData.swift
 *   Sources/EudiWalletKit/Services/TransactionLogUtils.swift
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.support  (S-002)
 *
 * iOS TransactionLog types come from WalletStorage (not a Cangjie third_party).
 * iOS TransactionLogData is an enum with associated values for presentation,
 * issuance, deletion, and signing transactions.
 *
 * Cangjie mapping:
 *   - TransactionType enum captures the iOS FlowType + action semantics.
 *   - TransactionLogEntry is the persisted record (replaces iOS TransactionLog struct).
 *   - PresentationLogData / IssuanceLogData / DeletionLogData are plain classes.
 *   - TransactionLogUtils provides factory/mutation helpers as static methods.
 *   - No WalletStorage or OpenID4VP third-party dependency is introduced here;
 *     callers pass raw typed data (claim dictionaries as String arrays).
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.support

import kit.PerformanceAnalysisKit.Hilog

import std.collection.HashMap
import std.collection.ArrayList
import std.time.DateTime

// ===========================================================================
// TransactionType — what happened
// ===========================================================================

/**
 * Classification of a wallet transaction.
 *
 * Mirrors iOS combination of FlowType + action name:
 *   presentation (BLE / OpenID4VP / other)
 *   issuance
 *   deletion
 *   signing
 */
public enum TransactionType {
    /** mDoc/SD-JWT presentation via BLE proximity. */
    | PresentationBle
    /** mDoc/SD-JWT presentation via OpenID4VP remote protocol. */
    | PresentationOpenId4Vp
    /** mDoc/SD-JWT presentation via unspecified other channel. */
    | PresentationOther
    /** Credential issuance (OpenID4VCI or CBOR issuance). */
    | Issuance
    /** Credential deletion by the user. */
    | Deletion
    /** Signing / DPoP proof. */
    | Signing

    /** Human-readable label for logging. */
    public func label(): String {
        match (this) {
            case PresentationBle => return "presentation_ble"
            case PresentationOpenId4Vp => return "presentation_openid4vp"
            case PresentationOther => return "presentation_other"
            case Issuance => return "issuance"
            case Deletion => return "deletion"
            case Signing => return "signing"
        }
    }
}

// ===========================================================================
// TransactionStatus — outcome
// ===========================================================================

/**
 * Outcome of a transaction.
 * Maps to iOS TransactionLog status strings.
 */
public enum TransactionStatus {
    | Completed
    | Failed
    | Cancelled

    public func rawValue(): String {
        match (this) {
            case Completed => return "completed"
            case Failed => return "failed"
            case Cancelled => return "cancelled"
        }
    }

    public static func fromRaw(raw: String): ?TransactionStatus {
        match (raw) {
            case "completed" => return Some(TransactionStatus.Completed)
            case "failed"    => return Some(TransactionStatus.Failed)
            case "cancelled" => return Some(TransactionStatus.Cancelled)
            case _ => return None
        }
    }
}

// ===========================================================================
// PresentationLogData
// ===========================================================================

/**
 * Log data specific to a credential presentation transaction.
 *
 * Mirrors iOS PresentationLogData struct.
 */
public class PresentationLogData {
    /** Document type (e.g. "org.iso.18013.5.1.mDL"). */
    public let docType: String
    /** Relying party identifier (name or client_id). */
    public let relyingPartyId: ?String
    /** List of claim names disclosed to the relying party. */
    public let disclosedClaims: Array<String>
    /** Request nonce (for replay protection). */
    public let requestNonce: ?String
    /**
     * DER certificate chain of the relying party (leaf first), as presented
     * in the request (reader-auth x5chain / OpenID4VP client x5c). Lets the
     * app derive the presenter name from the leaf certificate subject.
     * Mirrors iOS TransactionLog.RelyingParty.certificateChain (v0.40.9).
     */
    public let relyingPartyCertificateChain: ?Array<Array<UInt8>>
    /** Whether the relying party certificate chain validated against the
     *  wallet trust anchors (iOS RelyingParty.isVerified). */
    public let relyingPartyIsVerified: Bool

    public init(
        docType: String,
        relyingPartyId: ?String,
        disclosedClaims: Array<String>,
        requestNonce: ?String,
        relyingPartyCertificateChain!: ?Array<Array<UInt8>> = None,
        relyingPartyIsVerified!: Bool = false
    ) {
        this.docType = docType
        this.relyingPartyId = relyingPartyId
        this.disclosedClaims = disclosedClaims
        this.requestNonce = requestNonce
        this.relyingPartyCertificateChain = relyingPartyCertificateChain
        this.relyingPartyIsVerified = relyingPartyIsVerified
    }
}

// ===========================================================================
// PresentationTransactionRecord — full record of one proximity presentation
// ===========================================================================

/**
 * Everything the app-side transaction logger needs for one ISO 18013-5
 * proximity presentation. Captured by BlePresentationService: the relying
 * party (WRPRC policy name, else the reader certificate CN; whether its
 * reader-auth chain validated; the DER chain leaf first; the raw ReaderAuth
 * COSE_Sign1 bytes), the plaintext DeviceRequest, the plaintext
 * DeviceResponse actually sent, and the SessionTranscript. The record only
 * reaches Completed after the transport confirmed the response was
 * delivered; a failed send leaves it Failed with the reason.
 *
 * Mirrors iOS TransactionLog(type: .presentation, dataFormat: .cbor) with
 * TransactionLog.RelyingParty.
 */
public class PresentationTransactionRecord {
    /** ISO-8601 timestamp of the request. */
    public let timestamp: String
    /** Outcome; Completed only after a delivered response. */
    public var status: TransactionStatus
    /** Reason when status == Failed. */
    public var errorMessage: ?String
    /** Relying party display name: WRPRC policy name, else reader cert CN. */
    public let relyingPartyName: ?String
    /** Whether the reader-auth signature and chain validated (iOS isVerified). */
    public let relyingPartyIsVerified: Bool
    /** Reader certificate chain, DER, leaf first. */
    public let relyingPartyCertificateChain: ?Array<Array<UInt8>>
    /** Raw ReaderAuth (COSE_Sign1) CBOR bytes of the first DocRequest. */
    public let readerAuthBytes: ?Array<UInt8>
    /** Plaintext DeviceRequest CBOR. */
    public let rawRequest: ?Array<UInt8>
    /** Plaintext DeviceResponse CBOR that was sent (None until sent). */
    public var rawResponse: ?Array<UInt8>
    /** SessionTranscript CBOR (array form, not tag-24 wrapped). */
    public let sessionTranscript: ?Array<UInt8>
    /** Storage ids of the documents included in the response. */
    public var documentIds: Array<String>
    /** ISO doctypes of the documents included in the response. */
    public var docTypes: Array<String>

    public init(
        timestamp: String,
        relyingPartyName: ?String,
        relyingPartyIsVerified: Bool,
        relyingPartyCertificateChain: ?Array<Array<UInt8>>,
        readerAuthBytes: ?Array<UInt8>,
        rawRequest: ?Array<UInt8>,
        sessionTranscript: ?Array<UInt8>
    ) {
        this.timestamp = timestamp
        this.status = TransactionStatus.Failed
        this.errorMessage = None
        this.relyingPartyName = relyingPartyName
        this.relyingPartyIsVerified = relyingPartyIsVerified
        this.relyingPartyCertificateChain = relyingPartyCertificateChain
        this.readerAuthBytes = readerAuthBytes
        this.rawRequest = rawRequest
        this.rawResponse = None
        this.sessionTranscript = sessionTranscript
        this.documentIds = Array<String>()
        this.docTypes = Array<String>()
    }

    /** Mark the response as delivered. */
    public func markCompleted(rawResponse: Array<UInt8>, documentIds: Array<String>, docTypes: Array<String>): Unit {
        this.rawResponse = Some(rawResponse)
        this.documentIds = documentIds
        this.docTypes = docTypes
        this.status = TransactionStatus.Completed
        this.errorMessage = None
    }

    /** Mark the presentation as failed (nothing delivered or an error frame sent). */
    public func markFailed(reason: String): Unit {
        this.status = TransactionStatus.Failed
        this.errorMessage = Some(reason)
    }

    /** Convert into the generic log entry shape used by TransactionLog. */
    public func toLogEntry(id: String): TransactionLogEntry {
        let entry = TransactionLogEntry(id, TransactionType.PresentationBle, this.timestamp, this.status)
        entry.errorMessage = this.errorMessage
        let docType: String = if (this.docTypes.size > 0) { this.docTypes[0] } else { "" }
        entry.presentationData = Some(PresentationLogData(
            docType,
            this.relyingPartyName,
            this.docTypes,
            None,
            relyingPartyCertificateChain: this.relyingPartyCertificateChain,
            relyingPartyIsVerified: this.relyingPartyIsVerified
        ))
        return entry
    }
}

// ===========================================================================
// IssuanceLogData
// ===========================================================================

/**
 * Log data specific to a credential issuance transaction.
 *
 * Mirrors iOS IssuanceLogData struct.
 */
public class IssuanceLogData {
    /** Document type being issued. */
    public let docType: String
    /** Issuer URL or identifier. */
    public let issuerUrl: ?String
    /** Whether issuance was deferred. */
    public let isDeferred: Bool

    public init(docType: String, issuerUrl: ?String, isDeferred: Bool) {
        this.docType = docType
        this.issuerUrl = issuerUrl
        this.isDeferred = isDeferred
    }
}

// ===========================================================================
// DeletionLogData
// ===========================================================================

/**
 * Log data specific to a credential deletion transaction.
 *
 * Mirrors iOS DeletionLogData struct.
 */
public class DeletionLogData {
    /** Document type deleted. */
    public let docType: String
    /** Document ID (opaque storage key). */
    public let documentId: String

    public init(docType: String, documentId: String) {
        this.docType = docType
        this.documentId = documentId
    }
}

// ===========================================================================
// SigningLogData
// ===========================================================================

/**
 * Log data specific to a signing / DPoP-proof transaction.
 *
 * Mirrors iOS signing log.
 */
public class SigningLogData {
    /** Algorithm used (e.g. "ES256"). */
    public let algorithm: String
    /** Optional claim set identifier. */
    public let claimSetId: ?String

    public init(algorithm: String, claimSetId: ?String) {
        this.algorithm = algorithm
        this.claimSetId = claimSetId
    }
}

// ===========================================================================
// TransactionLogEntry
// ===========================================================================

/**
 * Persisted transaction log record.
 *
 * Mirrors iOS TransactionLog struct from WalletStorage (not in Cangjie third_party).
 * All fields are strings for generic serialization; callers embed typed sub-data
 * via one of the typed log data classes.
 */
public class TransactionLogEntry {
    /** Unique log entry identifier (UUID string). */
    public let id: String
    /** Transaction type. */
    public let transactionType: TransactionType
    /** ISO-8601 timestamp of when the transaction started. */
    public let timestamp: String
    /** Transaction outcome. */
    public var status: TransactionStatus
    /** Error message if status == Failed. */
    public var errorMessage: ?String

    /** Presentation-specific payload (present when transactionType is Presentation*). */
    public var presentationData: ?PresentationLogData
    /** Issuance-specific payload. */
    public var issuanceData: ?IssuanceLogData
    /** Deletion-specific payload. */
    public var deletionData: ?DeletionLogData
    /** Signing-specific payload. */
    public var signingData: ?SigningLogData

    public init(
        id: String,
        transactionType: TransactionType,
        timestamp: String,
        status: TransactionStatus
    ) {
        this.id = id
        this.transactionType = transactionType
        this.timestamp = timestamp
        this.status = status
        this.errorMessage = None
        this.presentationData = None
        this.issuanceData = None
        this.deletionData = None
        this.signingData = None
    }
}

// ===========================================================================
// TransactionLog — in-memory log store
// ===========================================================================

/**
 * In-memory ordered store of transaction log entries.
 *
 * Mirrors iOS TransactionLog actor (single-writer, multiple-reader semantics
 * achieved here through Cangjie's sequential class methods).
 *
 * Downstream features (presentation / issuance) hold a reference to a shared
 * TransactionLog instance (typically stored in the WalletCore or WalletFacade).
 */
public class TransactionLog {
    private var entries: ArrayList<TransactionLogEntry>

    public init() {
        entries = ArrayList<TransactionLogEntry>()
    }

    /** Append a new entry to the log. */
    public func append(entry: TransactionLogEntry): Unit {
        entries.add(entry)
        Hilog.info(0, "TransactionLog",
            "append id=" + entry.id + " type=" + entry.transactionType.label()
            + " status=" + entry.status.rawValue())
    }

    /** Return all entries in insertion order. */
    public func allEntries(): Array<TransactionLogEntry> {
        return entries.toArray()
    }

    /** Return the most recent entry, or None if the log is empty. */
    public func lastEntry(): ?TransactionLogEntry {
        let n = entries.size
        if (n == 0) {
            return None
        }
        return Some(entries[n - 1])
    }

    /** Number of entries currently stored. */
    public func count(): Int64 {
        return entries.size
    }

    /**
     * Remove all entries from the log.
     * Useful for cleanup between test runs.
     */
    public func clear(): Unit {
        entries = ArrayList<TransactionLogEntry>()
    }
}

// ===========================================================================
// TransactionLogUtils — factory and mutation helpers
// ===========================================================================

/**
 * Static utilities for creating and updating TransactionLogEntry objects.
 *
 * Mirrors iOS TransactionLogUtils static methods.
 */
public class TransactionLogUtils {

    private init() {}

    // -----------------------------------------------------------------------
    // getTimestamp
    // -----------------------------------------------------------------------

    /**
     * Return the current time as an ISO-8601-like string.
     *
     * Mirrors iOS TransactionLogUtils.getTimestamp() -> String.
     * Format: "YYYY-MM-DDTHH:MM:SS.sssZ" (UTC approximation using DateTime).
     */
    public static func getTimestamp(): String {
        let now = DateTime.now()
        // DateTime.toString() returns ISO-8601 on stdx; use directly.
        return now.toString()
    }

    // -----------------------------------------------------------------------
    // initializeTransactionLog — create a new pending entry
    // -----------------------------------------------------------------------

    /**
     * Create a new TransactionLogEntry in Completed state with the current timestamp.
     *
     * Mirrors iOS TransactionLogUtils.initializeTransactionLog(id:type:).
     *
     * @param id              Unique identifier (UUID string).
     * @param transactionType The type of transaction being logged.
     * @return A new TransactionLogEntry with status = Completed.
     */
    public static func initializeTransactionLog(
        id: String,
        transactionType: TransactionType
    ): TransactionLogEntry {
        return TransactionLogEntry(
            id,
            transactionType,
            getTimestamp(),
            TransactionStatus.Completed
        )
    }

    // -----------------------------------------------------------------------
    // setErrorTransactionLog — mark entry as failed
    // -----------------------------------------------------------------------

    /**
     * Update an entry to Failed status with an error message.
     *
     * Mirrors iOS TransactionLogUtils.setErrorTransactionLog(entry:error:).
     */
    public static func setErrorTransactionLog(
        entry: TransactionLogEntry,
        error: String
    ): Unit {
        entry.status = TransactionStatus.Failed
        entry.errorMessage = Some(error)
        Hilog.warn(0, "TransactionLog",
            "setError id=" + entry.id + " error=" + error)
    }

    // -----------------------------------------------------------------------
    // setPresentationRequestInfo
    // -----------------------------------------------------------------------

    /**
     * Attach presentation request information to a log entry.
     *
     * Mirrors iOS TransactionLogUtils.setCborTransactionLogRequestInfo for
     * the common case (docType + relyingParty + claims + nonce).
     */
    public static func setPresentationRequestInfo(
        entry: TransactionLogEntry,
        docType: String,
        relyingPartyId: ?String,
        requestedClaims: Array<String>,
        nonce: ?String,
        relyingPartyCertificateChain!: ?Array<Array<UInt8>> = None,
        relyingPartyIsVerified!: Bool = false
    ): Unit {
        entry.presentationData = Some(PresentationLogData(
            docType,
            relyingPartyId,
            requestedClaims,
            nonce,
            relyingPartyCertificateChain: relyingPartyCertificateChain,
            relyingPartyIsVerified: relyingPartyIsVerified
        ))
    }

    // -----------------------------------------------------------------------
    // setPresentationResponseInfo
    // -----------------------------------------------------------------------

    /**
     * Update an existing presentation log entry with the actually disclosed claims.
     *
     * Mirrors iOS TransactionLogUtils.setCborTransactionLogResponseInfo /
     * setTransactionLogResponseInfo.
     */
    public static func setPresentationResponseInfo(
        entry: TransactionLogEntry,
        disclosedClaims: Array<String>
    ): Unit {
        match (entry.presentationData) {
            case Some(pd) =>
                entry.presentationData = Some(PresentationLogData(
                    pd.docType,
                    pd.relyingPartyId,
                    disclosedClaims,
                    pd.requestNonce,
                    relyingPartyCertificateChain: pd.relyingPartyCertificateChain,
                    relyingPartyIsVerified: pd.relyingPartyIsVerified
                ))
            case None =>
                Hilog.warn(0, "TransactionLog",
                    "setPresentationResponseInfo: no presentation data on entry " + entry.id)
        }
    }

    // -----------------------------------------------------------------------
    // setIssuanceInfo
    // -----------------------------------------------------------------------

    /**
     * Attach issuance information to a log entry.
     */
    public static func setIssuanceInfo(
        entry: TransactionLogEntry,
        docType: String,
        issuerUrl: ?String,
        isDeferred: Bool
    ): Unit {
        entry.issuanceData = Some(IssuanceLogData(docType, issuerUrl, isDeferred))
    }

    // -----------------------------------------------------------------------
    // setDeletionInfo
    // -----------------------------------------------------------------------

    /**
     * Attach deletion information to a log entry.
     */
    public static func setDeletionInfo(
        entry: TransactionLogEntry,
        docType: String,
        documentId: String
    ): Unit {
        entry.deletionData = Some(DeletionLogData(docType, documentId))
    }

    // -----------------------------------------------------------------------
    // setSigningInfo
    // -----------------------------------------------------------------------

    /**
     * Attach signing information to a log entry.
     */
    public static func setSigningInfo(
        entry: TransactionLogEntry,
        algorithm: String,
        claimSetId: ?String
    ): Unit {
        entry.signingData = Some(SigningLogData(algorithm, claimSetId))
    }

    // -----------------------------------------------------------------------
    // getRelyingParty — extract relying party from a presentation entry
    // -----------------------------------------------------------------------

    /**
     * Extract the relying party identifier from a log entry.
     *
     * Returns None if the entry is not a presentation entry or the relying
     * party was not captured.
     *
     * Mirrors iOS TransactionLogUtils.getRelyingParty(_:).
     */
    public static func getRelyingParty(entry: TransactionLogEntry): ?String {
        match (entry.presentationData) {
            case Some(pd) => return pd.relyingPartyId
            case None => return None
        }
    }
}
