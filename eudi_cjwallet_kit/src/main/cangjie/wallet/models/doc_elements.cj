/*
 * doc_elements.cj
 *
 * EUDI Wallet Kit — document element presentation models.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Models/DocElements.swift
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.models  (S-002)
 *
 * Upstream dependencies consumed (read-only):
 *   ohos_app_cangjie_eudi_cjmdoc_data_model → DocClaim, DocDataFormat
 *   ohos_app_cangjie_eudi_cjmdoc_transfer   → RequestItem
 *
 * Design decisions:
 *   - iOS MsoMdocElements / SdJwtElements are reference-type final classes (class, not struct).
 *   - iOS ObservableObject / @Published → replaced with plain mutable fields in Cangjie.
 *   - iOS OrderedCollections.OrderedSet → ArrayList (insertion-order preservation).
 *   - iOS IssuerSigned.extractMsoMdocElements / SignedSDJWT.extractSdJwtElements are
 *     iOS-framework extensions that depend on MdocDataModel18013 types not present at
 *     this layer; they are excluded and will be implemented in the presentation service.
 *   - DocPresentInfo is a value container; DocElements is the discriminated union.
 *   - RequestItems type alias: HashMap<String, HashMap<String, Array<RequestItem>>>
 *     (docId → namespace → [RequestItem]).  Mirrors iOS typealias RequestItems.
 *   - isValidAndSelected computed property: mirrors iOS ObservableObject pattern.
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.models

import std.collection.ArrayList
import std.collection.HashMap
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.claims.DocClaim
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.claims.DocDataFormat
import ohos_app_cangjie_eudi_cjmdoc_transfer.transfer.framing.RequestItem

// ===========================================================================
// RequestItems type alias
// iOS: public typealias RequestItems = [String: RequestItems]
// Mapped as: docId → (namespace → [RequestItem])
// Cangjie: public type RequestItems = HashMap<String, HashMap<String, Array<RequestItem>>>
// ===========================================================================

/**
 * Aggregated presentation request items keyed by document id then namespace.
 * Mirrors iOS RequestItems typealias.
 */
public type RequestItems = HashMap<String, HashMap<String, Array<RequestItem>>>

// ===========================================================================
// DocPresentInfo
// iOS: public struct DocPresentInfo: Sendable
// ===========================================================================

/**
 * Aggregated presentation context for a single document.
 *
 * docType       — ISO 18013-5 docType or vct string
 * secureAreaName — name of the secure area backing the document keys
 * docDataFormat  — credential encoding format (mso_mdoc or sd-jwt)
 * displayName   — localised document name
 * docClaims     — decoded claims from the credential
 */
public class DocPresentInfo {
    public let docType: String
    public let secureAreaName: ?String
    public let docDataFormat: DocDataFormat
    public let displayName: ?String
    public let docClaims: ArrayList<DocClaim>

    public init(docType: String, secureAreaName: ?String, docDataFormat: DocDataFormat,
                displayName: ?String, docClaims: ArrayList<DocClaim>) {
        this.docType = docType
        this.secureAreaName = secureAreaName
        this.docDataFormat = docDataFormat
        this.displayName = displayName
        this.docClaims = docClaims
    }
}

// ===========================================================================
// NameSpacedElements
// iOS: public final class NameSpacedElements: Identifiable
// ===========================================================================

/** A namespace and the elements it contains for presentation selection. */
public class NameSpacedElements {
    public let nameSpace: String
    public var elements: ArrayList<MsoMdocElement>

    public init(nameSpace: String, elements: ArrayList<MsoMdocElement>) {
        this.nameSpace = nameSpace
        this.elements = elements
    }

    public func id(): String { return this.nameSpace }
}

// ===========================================================================
// MsoMdocElement
// iOS: public final class MsoMdocElement: Identifiable, ObservableObject
// ===========================================================================

/**
 * A single element within an mso-mdoc namespace for presentation disclosure.
 *
 * isValid    — element is present in the credential (false = requested but absent)
 * isSelected — user has selected this element for disclosure
 */
public class MsoMdocElement {
    public let elementIdentifier: String
    public let isOptional: Bool
    public var intentToRetain: Bool
    public let stringValue: ?String
    public let docClaim: ?DocClaim
    public var isValid: Bool
    public var isSelected: Bool

    public init(elementIdentifier: String, isOptional: Bool, intentToRetain: Bool,
                stringValue: ?String, docClaim: ?DocClaim, isValid: Bool, isSelected: Bool) {
        this.elementIdentifier = elementIdentifier
        this.isOptional = isOptional
        this.intentToRetain = intentToRetain
        this.stringValue = stringValue
        this.docClaim = docClaim
        this.isValid = isValid
        this.isSelected = isSelected
    }

    /** True when the element is both valid (present) and selected by the user. */
    public func isValidAndSelected(): Bool { return this.isValid && this.isSelected }

    public func id(): String { return this.elementIdentifier }

    /** Convert to a RequestItem for inclusion in the presentation request. */
    public func requestItem(): RequestItem {
        return RequestItem([this.elementIdentifier], Some(this.intentToRetain), Some(this.isOptional))
    }
}

// ===========================================================================
// SdJwtElement
// iOS: public final class SdJwtElement: Identifiable, ObservableObject, Hashable
// ===========================================================================

/**
 * A single element within an SD-JWT VC for presentation disclosure.
 * Supports nested elements (for structured SD-JWT claims).
 */
public class SdJwtElement {
    public let elementPath: Array<String>
    public let isOptional: Bool
    public let intentToRetain: Bool
    public let stringValue: ?String
    public let docClaim: ?DocClaim
    public var isValid: Bool
    public var isSelected: Bool
    public var nestedElements: ?ArrayList<SdJwtElement>

    public init(elementPath: Array<String>, isOptional: Bool, intentToRetain: Bool,
                stringValue: ?String, docClaim: ?DocClaim, isValid: Bool, isSelected: Bool,
                nestedElements: ?ArrayList<SdJwtElement>) {
        this.elementPath = elementPath
        this.isOptional = isOptional
        this.intentToRetain = intentToRetain
        this.stringValue = stringValue
        this.docClaim = docClaim
        this.isValid = isValid
        this.isSelected = isSelected
        this.nestedElements = nestedElements
    }

    public func id(): String {
        return sdJwtJoinPath(this.elementPath, ".")
    }

    public func isValidAndSelected(): Bool { return this.isValid && this.isSelected }

    public func requestItem(): RequestItem {
        return RequestItem(this.elementPath, Some(this.intentToRetain), Some(this.isOptional))
    }

    /**
     * Returns this item's RequestItem plus all valid-and-selected nested items.
     * Mirrors iOS var selectedRequestItems: [RequestItem].
     */
    public func selectedRequestItems(): ArrayList<RequestItem> {
        let result = ArrayList<RequestItem>()
        result.add(this.requestItem())
        match (this.nestedElements) {
            case None => ()
            case Some(nested) =>
                var i: Int64 = 0
                while (i < nested.size) {
                    let n = nested[i]
                    if (n.isValidAndSelected()) {
                        let sub = n.selectedRequestItems()
                        var j: Int64 = 0
                        while (j < sub.size) {
                            result.add(sub[j])
                            j++
                        }
                    }
                    i++
                }
        }
        return result
    }
}

// ===========================================================================
// MsoMdocElements
// iOS: public final class MsoMdocElements: Identifiable, @unchecked Sendable
// ===========================================================================

/**
 * Collection of elements grouped by namespace for an mso-mdoc document.
 * Used during presentation to let the user select which elements to disclose.
 */
public class MsoMdocElements {
    public var docId: String
    public let docType: String
    public let displayName: ?String
    public var isValid: Bool
    public var nameSpacedElements: ArrayList<NameSpacedElements>

    public init(docId: String, docType: String, displayName: ?String,
                isValid: Bool, nameSpacedElements: ArrayList<NameSpacedElements>) {
        this.docId = docId
        this.docType = docType
        this.displayName = displayName
        this.isValid = isValid
        this.nameSpacedElements = nameSpacedElements
    }

    public func id(): String { return this.docId }

    /**
     * Build a dictionary of selected items grouped by namespace.
     * Mirrors iOS var selectedItemsDictionary: [String: [RequestItem]].
     */
    public func selectedItemsDictionary(): HashMap<String, Array<RequestItem>> {
        let result = HashMap<String, Array<RequestItem>>()
        var i: Int64 = 0
        while (i < this.nameSpacedElements.size) {
            let nse = this.nameSpacedElements[i]
            let selected = ArrayList<RequestItem>()
            var j: Int64 = 0
            while (j < nse.elements.size) {
                let elem = nse.elements[j]
                if (elem.isValidAndSelected()) {
                    selected.add(elem.requestItem())
                }
                j++
            }
            if (selected.size > 0) {
                result[nse.nameSpace] = selected.toArray()
            }
            i++
        }
        return result
    }

    /**
     * Mandatory element keys for known docTypes.
     * Mirrors iOS MsoMdocElements.getMandatoryElementKeys(docType:ns:).
     *
     * Note: IsoMdlModel / EuPidModel constants are defined in mdoc-data-model's
     * known_doctypes module. Returning empty array here; the service layer will
     * consult the mdoc_doctypes module for mandatory-element resolution.
     */
    public static func getMandatoryElementKeys(docType: String, ns: String): Array<String> {
        return []
    }
}

// ===========================================================================
// SdJwtElements
// iOS: public final class SdJwtElements: Identifiable, @unchecked Sendable
// ===========================================================================

/**
 * Collection of elements for an SD-JWT VC document for presentation selection.
 */
public class SdJwtElements {
    public var docId: String
    public let vct: String
    public let displayName: ?String
    public var isValid: Bool
    public var sdJwtElements: ArrayList<SdJwtElement>

    public init(docId: String, vct: String, displayName: ?String,
                isValid: Bool, sdJwtElements: ArrayList<SdJwtElement>) {
        this.docId = docId
        this.vct = vct
        this.displayName = displayName
        this.isValid = isValid
        this.sdJwtElements = sdJwtElements
    }

    public func id(): String { return this.docId }

    /**
     * Build a dictionary of selected items (namespace "" for SD-JWT).
     * Mirrors iOS var selectedItemsDictionary: [String: [RequestItem]].
     */
    public func selectedItemsDictionary(): HashMap<String, Array<RequestItem>> {
        let result = HashMap<String, Array<RequestItem>>()
        let selected = ArrayList<RequestItem>()
        var i: Int64 = 0
        while (i < this.sdJwtElements.size) {
            let elem = this.sdJwtElements[i]
            if (elem.isValidAndSelected()) {
                let subItems = elem.selectedRequestItems()
                var j: Int64 = 0
                while (j < subItems.size) {
                    selected.add(subItems[j])
                    j++
                }
            }
            i++
        }
        result[""] = selected.toArray()
        return result
    }
}

// ===========================================================================
// DocElements
// iOS: public enum DocElements: Identifiable, Sendable
// ===========================================================================

/**
 * Discriminated union of presentation element collections.
 * Either an mso-mdoc document or an SD-JWT VC document.
 */
public enum DocElements {
    | MsoMdoc(MsoMdocElements)
    | SdJwt(SdJwtElements)

    public func id(): String {
        match (this) {
            case MsoMdoc(m) => return m.id()
            case SdJwt(s)   => return s.id()
        }
    }

    public func asMsoMdoc(): ?MsoMdocElements {
        match (this) {
            case MsoMdoc(m) => return Some(m)
            case _ => return None
        }
    }

    public func asSdJwt(): ?SdJwtElements {
        match (this) {
            case SdJwt(s) => return Some(s)
            case _ => return None
        }
    }

    public func isMsoMdoc(): Bool {
        match (this) {
            case MsoMdoc(_) => return true
            case _ => return false
        }
    }

    public func isSdJwt(): Bool {
        match (this) {
            case SdJwt(_) => return true
            case _ => return false
        }
    }

    public func docTypeOrVct(): String {
        match (this) {
            case MsoMdoc(m) => return m.docType
            case SdJwt(s)   => return s.vct
        }
    }

    public func isValid(): Bool {
        match (this) {
            case MsoMdoc(m) => return m.isValid
            case SdJwt(s)   => return s.isValid
        }
    }

    public func docId(): String {
        match (this) {
            case MsoMdoc(m) => return m.docId
            case SdJwt(s)   => return s.docId
        }
    }

    public func selectedItemsDictionary(): HashMap<String, Array<RequestItem>> {
        match (this) {
            case MsoMdoc(m) => return m.selectedItemsDictionary()
            case SdJwt(s)   => return s.selectedItemsDictionary()
        }
    }
}

// ===========================================================================
// Array<DocElements> extension — items computed property
// iOS: extension Array where Element == DocElements { var items: RequestItems { ... } }
// ===========================================================================

/**
 * Aggregate selected items from a list of DocElements into a RequestItems map.
 * Mirrors iOS Array<DocElements>.items.
 * Key: docId → (namespace → [RequestItem]).
 */
public func docElementsToRequestItems(elements: ArrayList<DocElements>): RequestItems {
    let result = RequestItems()
    var i: Int64 = 0
    while (i < elements.size) {
        let elem = elements[i]
        result[elem.docId()] = elem.selectedItemsDictionary()
        i++
    }
    return result
}

// ===========================================================================
// Package-private helpers
// ===========================================================================

/** Join Array<String> with separator. S-018: no for-in Rune toString. */
func sdJwtJoinPath(parts: Array<String>, sep: String): String {
    if (parts.size == 0) {
        return ""
    }
    var result = parts[0]
    var i: Int64 = 1
    while (i < parts.size) {
        result = result + sep + parts[i]
        i++
    }
    return result
}
