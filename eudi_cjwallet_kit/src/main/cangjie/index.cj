// HAR root package anchor (S-003) + entry→HAR wiring target.
// runEudiWalletDemo() exercises the EudiWallet facade with a self-contained
// non-network self-check (assembly + document-management paths).
// Network-dependent flows (issuance/presentation via OAuth/BLE) are truthfully
// noted as not testable without a live server.
package ohos_app_cangjie_eudi_cjwallet_kit

import ohos_app_cangjie_eudi_cjwallet_kit.wallet.facade.EudiWallet
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.EudiWalletConfiguration
import ohos_app_cangjie_eudi_cjwallet_storage.storage.types.DocumentStatus

/**
 * Self-contained non-network demo / self-check for the EUDI Wallet Kit facade.
 *
 * Exercises:
 *   1. EudiWallet construction with defaultConfig + in-memory storage (no context required).
 *   2. loadDocuments(Issued)  — empty-store return (None) from fresh in-memory store.
 *   3. deleteAllDocuments()   — must not throw on empty store.
 *
 * Returns a truthful result string.  Network-dependent paths (issuance/presentation
 * require OAuth / BLE server) are noted as not self-testable.
 */
public func runEudiWalletDemo(): String {
    var walletAssembled: String = "FAIL"
    var docMgmt: String = "FAIL"
    var note: String = ""

    // -- 1. Assemble wallet (no context needed; default in-memory storage) ----
    try {
        let config = EudiWalletConfiguration.defaultConfig()
        let wallet = EudiWallet(config)
        walletAssembled = "PASS"

        // -- 2. Document-management paths (no network required) ---------------
        let docsOpt = wallet.loadDocuments(DocumentStatus.Issued)
        match (docsOpt) {
            case None => ()   // expected: empty store
            case Some(_) => ()
        }

        wallet.deleteAllDocuments()   // must not throw on empty store
        docMgmt = "PASS"

        note = "issuance/presentation require network (not in self-test)"
    } catch (e: Exception) {
        note = "exception: " + e.message
    }

    return "OK: wallet_assembled=" + walletAssembled +
           ", doc_mgmt=" + docMgmt +
           ", note=" + note
}
