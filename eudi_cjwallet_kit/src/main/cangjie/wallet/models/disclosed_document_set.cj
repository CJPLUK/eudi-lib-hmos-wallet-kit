/*
 * disclosed_document_set.cj
 *
 * EUDI Wallet Kit — documents disclosable for one presentation request,
 * paired with registration-policy warnings.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Models/DisclosedDocumentSet.swift  (v0.40.9)
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.models  (S-002)
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.models

/**
 * A set of documents that can be disclosed in response to a single
 * presentation request.
 *
 * When a verifier request is decoded, the wallet builds one instance per
 * request, containing the matching stored documents with the elements the
 * user can select to disclose, together with any policy warnings raised while
 * validating the request against the relying party's registration policy.
 *
 * Instances are published by PresentationSession.disclosedDocumentSets for
 * the UI to present the selectable items to the user.
 */
public class DisclosedDocumentSet {
    /** The requested elements of each matching document, grouped per document and format. */
    public let docElements: Array<DocElements>
    /**
     * Violations of the relying party's registration policy detected for this
     * request. The presentation can still proceed; these are surfaced to the
     * user as warnings.
     */
    public let warnings: ?Array<PresentationPolicyViolation>

    public init(docElements: Array<DocElements>, warnings: ?Array<PresentationPolicyViolation>) {
        this.docElements = docElements
        this.warnings = warnings
    }
}
