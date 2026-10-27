/*
 * storage_manager.cj
 *
 * EUDI Wallet Kit — document storage orchestration layer.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Services/StorageManager.swift
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.storage  (S-002)
 *
 * Role: StorageManager manages the wallet's in-memory document lists and
 * orchestrates load/delete/status against the wallet-storage DataStorageService.
 *
 * Upstream dependencies consumed (read-only):
 *   ohos_app_cangjie_eudi_cjwallet_storage.storage.docstore  → DataStorageService
 *   ohos_app_cangjie_eudi_cjwallet_storage.storage.types     → Document, DocumentStatus, StorageError
 *   ohos_app_cangjie_eudi_cjwallet_kit.wallet.models         → WalletError, DocPresentInfo
 *
 * Design decisions:
 *   - iOS async/await → synchronous with exceptions (DataStorageService is sync).
 *   - iOS @Published var → plain var fields (no reactive runtime in HAR service layer).
 *   - iOS DocClaimsModel → ?DocClaimsDecodable (interface from mdoc-data-model).
 *   - iOS hasData / docCount → computed via func (no ArkUI @State here).
 *   - R-103: HashMap.add/get used; no .put().
 *   - R-104: .get(key) returns ?V; contains() guard used before [key] subscript.
 *   - R-105: WalletError <: Exception, no message redeclaration.
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.storage

import std.collection.ArrayList
import std.collection.HashMap
import ohos_app_cangjie_eudi_cjwallet_storage.storage.docstore.DataStorageService
import ohos_app_cangjie_eudi_cjwallet_storage.storage.types.Document
import ohos_app_cangjie_eudi_cjwallet_storage.storage.types.DocumentStatus
import ohos_app_cangjie_eudi_cjwallet_storage.storage.types.StorageError
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.claims.DocClaimsDecodable
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.WalletError
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.DocPresentInfo

// ===========================================================================
// StorageManager
// iOS: public final class StorageManager: ObservableObject
// Manages the wallet's in-memory document index and delegates persistence to
// a DataStorageService instance.
// ===========================================================================

/**
 * Orchestrates wallet document storage: loading, deletion, and in-memory
 * lifecycle state for issued, deferred, and pending documents.
 *
 * Downstream callers (wk_facade / wk_issuance / wk_presentation) hold a
 * reference to this class and call its public methods to update or query the
 * document store.
 *
 * Thread-safety: callers must ensure sequential access (mirrors iOS actor
 * isolation contract via @MainActor annotations in the Swift original).
 */
public class StorageManager {

    // -----------------------------------------------------------------------
    // Properties
    // -----------------------------------------------------------------------

    /**
     * Backing persistence service.
     * Set at construction; can be replaced to swap storage backends.
     */
    public var storageService: DataStorageService

    /**
     * Decoded and in-memory representation of all issued documents.
     * Mirrors iOS @Published docModels: [DocClaimsModel].
     *
     * Kept as ArrayList<DocClaimsDecodable> so the service layer can hold a
     * heterogeneous list of decoded models without a concrete class dependency.
     */
    public var docModels: ArrayList<DocClaimsDecodable>

    /**
     * Raw storage-layer documents awaiting deferred issuance.
     * Mirrors iOS @Published deferredDocuments: [WalletStorage.Document].
     */
    public var deferredDocuments: ArrayList<Document>

    /**
     * Raw storage-layer documents in pending (OAuth redirect) state.
     * Mirrors iOS @Published pendingDocuments: [WalletStorage.Document].
     */
    public var pendingDocuments: ArrayList<Document>

    /**
     * Last error surfaced during a storage operation.
     * Consumers may inspect this after a call returns.
     * Mirrors iOS @Published uiError: WalletError?.
     */
    public var uiError: ?WalletError

    // -----------------------------------------------------------------------
    // Initialiser
    // -----------------------------------------------------------------------

    /**
     * Construct a StorageManager backed by the given storage service.
     *
     * @param storageService  the DataStorageService implementation to use.
     *
     * Mirrors iOS init(storageService:modelFactory:).
     * modelFactory is omitted at this layer; decoded models are produced by
     * the calling service (wk_facade) via DocClaimsDecodableRegistry.
     */
    public init(storageService: DataStorageService) {
        this.storageService = storageService
        this.docModels = ArrayList<DocClaimsDecodable>()
        this.deferredDocuments = ArrayList<Document>()
        this.pendingDocuments = ArrayList<Document>()
        this.uiError = None
    }

    // -----------------------------------------------------------------------
    // Computed state accessors
    // iOS: @Published hasData / docCount are derived from the list state.
    // -----------------------------------------------------------------------

    /**
     * Whether the wallet has any loaded data (issued OR deferred).
     * Mirrors iOS hasData computed from docModels / deferredDocuments.
     */
    public func hasData(): Bool {
        return !this.docModels.isEmpty() || !this.deferredDocuments.isEmpty()
    }

    /**
     * Count of issued documents currently loaded.
     * Mirrors iOS docCount == docModels.count.
     */
    public func docCount(): Int64 {
        return this.docModels.size
    }

    // -----------------------------------------------------------------------
    // Internal helpers — list refresh
    // -----------------------------------------------------------------------

    /**
     * Replace the in-memory list for the given status with raw storage documents.
     * Issued documents are kept as raw Document objects; callers that need
     * decoded claims must call the facade's decode layer.
     *
     * This mirrors iOS refreshDocModels(_:uiCulture:docStatus:).
     * Decoded-model conversion is deferred to wk_facade which has access to
     * DocClaimsDecodableRegistry; at this layer we only manage raw documents.
     *
     * For issued status the caller must supply the decoded models separately via
     * setDocModels; for deferred/pending we update the raw Document lists here.
     */
    func refreshRawDocuments(docs: ArrayList<Document>, docStatus: DocumentStatus): Unit {
        match (docStatus) {
            case DocumentStatus.Issued => ()
            case DocumentStatus.Deferred =>
                this.deferredDocuments = docs
            case DocumentStatus.Pending =>
                this.pendingDocuments = docs
        }
    }

    /**
     * Replace the in-memory issued-document models list.
     * Called by wk_facade after decoding raw documents into DocClaimsDecodable.
     */
    public func setDocModels(models: ArrayList<DocClaimsDecodable>): Unit {
        this.docModels = models
    }

    /**
     * Append a decoded document model to the issued list.
     * Mirrors iOS appendDocModel(_:uiCulture:) for the issued-status path.
     * Callers handle deferred/pending paths through appendRawDocument.
     */
    public func appendDocModel(model: DocClaimsDecodable): Unit {
        this.docModels.add(model)
    }

    /**
     * Append a raw Document to the deferred or pending list.
     * Mirrors iOS appendDocModel(_:uiCulture:) for non-issued statuses.
     *
     * @param doc  the storage-layer document to append.
     */
    public func appendRawDocument(doc: Document): Unit {
        match (doc.status) {
            case DocumentStatus.Deferred =>
                this.deferredDocuments.add(doc)
            case DocumentStatus.Pending =>
                this.pendingDocuments.add(doc)
            case DocumentStatus.Issued => ()
        }
    }

    // -----------------------------------------------------------------------
    // Public load operations
    // -----------------------------------------------------------------------

    /**
     * Load all documents with the given status from the persistence service.
     *
     * For Issued status this returns the raw documents; the caller (wk_facade)
     * must decode them into DocClaimsDecodable and then call setDocModels.
     * For Deferred/Pending the internal lists are updated automatically.
     *
     * Mirrors iOS loadDocuments(status:uiCulture:).
     *
     * @param status  which lifecycle bucket to load.
     * @return the raw documents loaded, or None if none exist.
     * @throws StorageError  on persistence failure.
     */
    public func loadDocuments(status: DocumentStatus): ?ArrayList<Document> {
        try {
            let result = this.storageService.loadDocuments(status)
            match (result) {
                case None =>
                    // An empty partition must still clear the in-memory list:
                    // after a deferred→issued conversion the Deferred bucket is
                    // empty, and skipping the refresh left a stale Pending row
                    // in the Documents list until an app relaunch.
                    this.refreshRawDocuments(ArrayList<Document>(), status)
                    return None
                case Some(docs) =>
                    let list = ArrayList<Document>()
                    var i: Int64 = 0
                    while (i < docs.size) {
                        list.add(docs[i])
                        i++
                    }
                    this.refreshRawDocuments(list, status)
                    return Some(list)
            }
        } catch (e: StorageError) {
            this.uiError = WalletError.withDescription(e.description)
            throw e
        }
    }

    /**
     * Load a single document by id and status from the persistence service.
     *
     * If the document is found and not already present in the corresponding
     * in-memory list, it is appended via appendRawDocument.
     *
     * Mirrors iOS loadDocument(id:uiCulture:status:).
     *
     * @param id      unique document identifier.
     * @param status  the lifecycle status of the document to load.
     * @return the raw document, or None if not found.
     * @throws StorageError  on persistence failure.
     */
    public func loadDocument(id: String, status: DocumentStatus): ?Document {
        try {
            let result = this.storageService.loadDocument(id, status)
            match (result) {
                case None => return None
                case Some(doc) =>
                    this.refreshRawDocumentIfAbsent(doc, status)
                    return Some(doc)
            }
        } catch (e: StorageError) {
            this.uiError = WalletError.withDescription(e.description)
            throw e
        }
    }

    /**
     * Append doc to the appropriate in-memory list if it is not already present.
     * Mirrors iOS refreshDocModel(_:uiCulture:docStatus:) conditional-append logic.
     */
    func refreshRawDocumentIfAbsent(doc: Document, docStatus: DocumentStatus): Unit {
        match (docStatus) {
            case DocumentStatus.Issued =>
                var found = false
                var i: Int64 = 0
                while (i < this.docModels.size) {
                    if (this.docModels[i].getId() == doc.id) {
                        found = true
                    }
                    i++
                }
                if (!found) {
                    this.appendRawDocument(doc)
                }
            case DocumentStatus.Deferred =>
                var found = false
                var i: Int64 = 0
                while (i < this.deferredDocuments.size) {
                    if (this.deferredDocuments[i].id == doc.id) {
                        found = true
                    }
                    i++
                }
                if (!found) {
                    this.deferredDocuments.add(doc)
                }
            case DocumentStatus.Pending =>
                var found = false
                var i: Int64 = 0
                while (i < this.pendingDocuments.size) {
                    if (this.pendingDocuments[i].id == doc.id) {
                        found = true
                    }
                    i++
                }
                if (!found) {
                    this.pendingDocuments.add(doc)
                }
        }
    }

    // -----------------------------------------------------------------------
    // Public delete operations
    // -----------------------------------------------------------------------

    /**
     * Delete a document by id and status from persistence and in-memory lists.
     *
     * Mirrors iOS deleteDocument(id:status:).
     *
     * @param id      unique document identifier.
     * @param status  the lifecycle status of the document to delete.
     * @throws WalletError   if no document with the given id is found in the list.
     * @throws StorageError  on persistence failure.
     */
    public func deleteDocument(id: String, status: DocumentStatus): Unit {
        // Delete from persistence FIRST, unconditionally. The in-memory model
        // cache (docModels/deferred/pending) is only populated when a caller
        // calls setDocModels after loadDocuments; consumers that keep their own
        // mirror (e.g. logic-core) never populate it, so requiring findIndex here
        // wrongly threw "Document to delete <id> not found" and the document was
        // never removed. We delete from storage regardless and then reconcile the
        // cache if the entry happens to be present.
        try {
            this.storageService.deleteDocument(id, status)
        } catch (e: StorageError) {
            this.uiError = WalletError.withDescription(e.description)
            throw e
        }
        match (this.findIndex(id, status)) {
            case Some(i) =>
                match (status) {
                    case DocumentStatus.Issued => this.docModels.remove(at: i)
                    case DocumentStatus.Deferred => this.deferredDocuments.remove(at: i)
                    case DocumentStatus.Pending => this.pendingDocuments.remove(at: i)
                }
            case None => ()
        }
    }

    /**
     * Delete all documents with the given status from persistence and memory.
     *
     * Mirrors iOS deleteDocuments(status:).
     *
     * @param status  the lifecycle status bucket to clear.
     * @throws StorageError  on persistence failure.
     */
    public func deleteDocuments(status: DocumentStatus): Unit {
        try {
            this.storageService.deleteDocuments(status)
            match (status) {
                case DocumentStatus.Issued =>
                    this.docModels = ArrayList<DocClaimsDecodable>()
                case DocumentStatus.Deferred =>
                    this.deferredDocuments = ArrayList<Document>()
                case DocumentStatus.Pending =>
                    this.pendingDocuments = ArrayList<Document>()
            }
        } catch (e: StorageError) {
            this.uiError = WalletError.withDescription(e.description)
            throw e
        }
    }

    /**
     * Remove a pending or deferred document by id.
     * If pending, removes from the in-memory list only.
     * If deferred, delegates to deleteDocument which also removes from storage.
     *
     * Mirrors iOS removePendingOrDeferredDoc(id:).
     *
     * @param id  the document identifier.
     * @throws StorageError  if the deferred delete fails.
     */
    public func removePendingOrDeferredDoc(id: String): Unit {
        var pendingIdx: ?Int64 = None
        var i: Int64 = 0
        while (i < this.pendingDocuments.size) {
            if (this.pendingDocuments[i].id == id) {
                pendingIdx = Some(i)
            }
            i++
        }
        match (pendingIdx) {
            case Some(idx) =>
                this.pendingDocuments.remove(at: idx)
            case None => ()
        }
        var deferredFound = false
        var j: Int64 = 0
        while (j < this.deferredDocuments.size) {
            if (this.deferredDocuments[j].id == id) {
                deferredFound = true
            }
            j++
        }
        if (deferredFound) {
            this.deleteDocument(id, DocumentStatus.Deferred)
        }
    }

    // -----------------------------------------------------------------------
    // Public query operations
    // -----------------------------------------------------------------------

    /**
     * Get the decoded document model by id from the issued list.
     *
     * Mirrors iOS getDocumentModel(id:) -> DocClaimsModel?.
     *
     * @param id  the document identifier.
     * @return the matching model, or None if not found.
     */
    public func getDocumentModel(id: String): ?DocClaimsDecodable {
        var i: Int64 = 0
        while (i < this.docModels.size) {
            if (this.docModels[i].getId() == id) {
                return Some(this.docModels[i])
            }
            i++
        }
        return None
    }

    /**
     * Get the decoded document model at a given index in the issued list.
     *
     * Mirrors iOS getDocumentModel(index:) -> DocClaimsModel?.
     *
     * @param index  zero-based index in docModels.
     * @return the model at that index, or None if out of bounds.
     */
    public func getDocumentModelAt(index: Int64): ?DocClaimsDecodable {
        if (index < 0 || index >= this.docModels.size) {
            return None
        }
        return Some(this.docModels[index])
    }

    /**
     * Get all issued document models matching a given docType string.
     *
     * Mirrors iOS getDocumentModels(docType:) -> [DocClaimsModel].
     *
     * @param docType  e.g. "org.iso.18013.5.1.mDL".
     * @return list of matching models; empty if none.
     */
    public func getDocumentModels(docType: String): ArrayList<DocClaimsDecodable> {
        let result = ArrayList<DocClaimsDecodable>()
        var i: Int64 = 0
        while (i < this.docModels.size) {
            if (this.docModels[i].getDocType() == docType) {
                result.add(this.docModels[i])
            }
            i++
        }
        return result
    }

    /**
     * Build a map from document id to DocPresentInfo for the issued documents.
     *
     * Only documents for which the caller supplies valid data are included;
     * this method constructs DocPresentInfo from the decoded model's fields.
     *
     * Mirrors iOS getDocIdsToPresentInfo(documents:) — simplified variant
     * without SecureArea key-batch lookup (that is in wk_support's domain).
     *
     * @return HashMap<String, DocPresentInfo> keyed by document id.
     */
    public func getDocIdsToPresentInfo(): HashMap<String, DocPresentInfo> {
        let result = HashMap<String, DocPresentInfo>()
        var i: Int64 = 0
        while (i < this.docModels.size) {
            let model = this.docModels[i]
            let info = DocPresentInfo(
                model.getDocType(),
                None,
                model.getDocDataFormat(),
                model.getDisplayName(),
                model.getDocClaims()
            )
            result.add(model.getId(), info)
            i++
        }
        return result
    }

    // -----------------------------------------------------------------------
    // Internal helpers — index lookup
    // -----------------------------------------------------------------------

    /**
     * Find the array index of a document by id in the appropriate list.
     *
     * Returns None if the id is not found.
     * R-104: no subscript on HashMap without contains guard; this uses while-loop.
     */
    func findIndex(id: String, status: DocumentStatus): ?Int64 {
        match (status) {
            case DocumentStatus.Issued =>
                var i: Int64 = 0
                while (i < this.docModels.size) {
                    if (this.docModels[i].getId() == id) {
                        return Some(i)
                    }
                    i++
                }
                return None
            case DocumentStatus.Deferred =>
                var i: Int64 = 0
                while (i < this.deferredDocuments.size) {
                    if (this.deferredDocuments[i].id == id) {
                        return Some(i)
                    }
                    i++
                }
                return None
            case DocumentStatus.Pending =>
                var i: Int64 = 0
                while (i < this.pendingDocuments.size) {
                    if (this.pendingDocuments[i].id == id) {
                        return Some(i)
                    }
                    i++
                }
                return None
        }
    }

    /**
     * Record an error in uiError.
     * Mirrors iOS setError(_:) @MainActor method.
     *
     * @param description  human-readable error description.
     */
    public func setError(description: String): Unit {
        this.uiError = WalletError.withDescription(description)
    }

    /**
     * Clear the last error state.
     */
    public func clearError(): Unit {
        this.uiError = None
    }
}
