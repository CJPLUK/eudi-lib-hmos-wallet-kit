/*
 * issuer_response.cj
 *
 * EUDI Wallet Kit — result of an OpenID4VCI issuance operation.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Models/IssuerResponse.swift  (v0.40.9)
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.models  (S-002)
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.models

import kit.PerformanceAnalysisKit.Hilog
import std.collection.HashMap
import ohos_app_cangjie_eudi_cjwallet_storage.storage.types.Document

/**
 * Result of an OpenID4VCI issuance operation.
 *
 * Pairs the issued documents with the decoded issuer registration policy and
 * any violations produced by the WRP registration certificate (WRPRC) policy
 * when OpenId4VciConfiguration.validateRegistrationCertificate is enabled.
 */
public class IssuerResponse {
    /** The issued documents. They are already saved in storage. */
    public let documents: Array<Document>
    /**
     * Typed violations produced by the WRP registration certificate policy,
     * keyed by credential configuration identifier; the empty key holds
     * request-wide violations. None when registration certificate validation
     * is not enabled.
     */
    public let wrpIssuerWarnings: ?HashMap<String, Array<RegistrationPolicyViolation>>
    /**
     * The WRP registration policy decoded from the issuer registration
     * certificate (WRPRC), available when validateRegistrationCertificate is
     * enabled. Preserved even when validation fails (expiry, revocation,
     * trust) so the issuer identity can be inspected.
     */
    public let wrpIssuerPolicy: ?WrpRegistrationPolicy

    public init(
        documents: Array<Document>,
        wrpIssuerWarnings: ?HashMap<String, Array<RegistrationPolicyViolation>>,
        wrpIssuerPolicy!: ?WrpRegistrationPolicy = None
    ) {
        this.documents = documents
        this.wrpIssuerWarnings = wrpIssuerWarnings
        this.wrpIssuerPolicy = wrpIssuerPolicy
        match (wrpIssuerWarnings) {
            case Some(warns) =>
                if (warns.size > 0) {
                    for ((key, list) in warns) {
                        for (w in list) {
                            Hilog.info(0, "IssuerResponse",
                                "Issuer registration warning key=" + key +
                                " reason=" + w.reason.rawValue() + " msg=" + w.message)
                        }
                    }
                }
            case None => ()
        }
    }
}
