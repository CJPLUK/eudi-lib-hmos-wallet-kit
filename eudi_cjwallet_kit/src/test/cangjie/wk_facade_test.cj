/*
 * wk_facade_test.cj
 *
 * Unit tests for wallet-kit facade pure logic:
 *   - extensions.cj  (FlowTypeHelper, CredentialOptionsHelper, OfferedDocModelHelper,
 *                     DocumentHelper, WalletConfigHelper, EudiWalletExtensions)
 *   - eudi_wallet.cj (parseTransactionLog pure formatting; getDefaultCredentialOptions
 *                     throws IssuerNotRegistered for unknown issuer; addOpenId4VciConfiguration
 *                     wiring via WalletConfigHelper.buildWallet)
 *
 * Storage-bound helpers (loadedDocuments / countDocuments) are exercised against
 * the in-memory fallback storage that EudiWallet uses when no DataStorageService
 * is supplied — offline, deterministic (empty store).
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.facade

import std.unittest.*
import std.unittest.testmacro.*
import std.collection.ArrayList
import std.time.DateTime

import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.{
    EudiWalletConfiguration,
    OpenId4VciConfiguration,
    OfferedDocModel,
    DocTypeIdentifier,
    WalletError
}
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.{
    FlowType,
    TransactionLogEntry,
    TransactionType,
    TransactionStatus
}
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.CredentialPolicy
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.credential.Claim
// Document and its DocDataFormat both come from wallet-storage (a distinct
// DocDataFormat from the mdoc-data-model one).
import ohos_app_cangjie_eudi_cjwallet_storage.storage.types.{Document, DocumentStatus, DocDataFormat}

// Symbols under test (wallet.facade) — explicit import for entry package.
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.facade.{
    EudiWallet,
    EudiWalletExtensions,
    DocumentHelper,
    FlowTypeHelper,
    CredentialOptionsHelper,
    OfferedDocModelHelper,
    WalletConfigHelper
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mkOffered(docType: ?String, vct: ?String): OfferedDocModel {
    return OfferedDocModel(
        "cfg-id", docType, vct, None, None, "Disp",
        [], ArrayList<Claim>(), None,
        CredentialOptionsHelper.oneTimeUse(), None
    )
}

func mkDoc(docType: String, status: DocumentStatus, displayName: ?String): Document {
    let data: Array<UInt8> = [0x00u8]
    let noKeyInfo: ?Array<UInt8> = None
    let noMeta: ?Array<UInt8> = None
    let noModified: ?DateTime = None
    return Document("doc-id", docType, DocDataFormat.Cbor, data, noKeyInfo, 0,
        DateTime.now(), noModified, noMeta, displayName, status)
}

// Mutable flag holder so test closures don't capture mutable locals
// (Cangjie forbids capturing mutable variables in escaping lambdas).
class FlagBox {
    public var value: Bool = false
}

// ===========================================================================
// FlowTypeHelper
// ===========================================================================
@Test
class WkFacadeFlowTypeHelperUT {

    @TestCase
    func isBle(): Unit {
        @Expect(FlowTypeHelper.isBle(FlowType.Ble), true)
        @Expect(FlowTypeHelper.isBle(FlowType.OpenId4Vp(Array<UInt8>())), false)
    }

    @TestCase
    func isOpenId4Vp(): Unit {
        @Expect(FlowTypeHelper.isOpenId4Vp(FlowType.OpenId4Vp), true)
        @Expect(FlowTypeHelper.isOpenId4Vp(FlowType.Other), false)
    }

    @TestCase
    func labels(): Unit {
        @Expect(FlowTypeHelper.label(FlowType.Ble), "ble")
        @Expect(FlowTypeHelper.label(FlowType.OpenId4Vp(Array<UInt8>())), "openid4vp")
        @Expect(FlowTypeHelper.label(FlowType.Other), "other")
    }
}

// ===========================================================================
// CredentialOptionsHelper
// ===========================================================================
@Test
class WkFacadeCredentialOptionsHelperUT {

    @TestCase
    func oneTimeUseBatchSizeOne(): Unit {
        let o = CredentialOptionsHelper.oneTimeUse()
        @Expect(o.batchSize, 1)
        @Expect(o.credentialPolicy.rawValue(), "oneTimeUse")
    }

    @TestCase
    func rotateUseBatchSizeOne(): Unit {
        let o = CredentialOptionsHelper.rotateUse()
        @Expect(o.batchSize, 1)
        @Expect(o.credentialPolicy.rawValue(), "rotateUse")
    }

    @TestCase
    func oneTimeUseBatchCustomSize(): Unit {
        let o = CredentialOptionsHelper.oneTimeUseBatch(5)
        @Expect(o.batchSize, 5)
        @Expect(o.credentialPolicy.rawValue(), "oneTimeUse")
    }
}

// ===========================================================================
// OfferedDocModelHelper
// ===========================================================================
@Test
class WkFacadeOfferedDocModelHelperUT {

    func sampleModels(): ArrayList<OfferedDocModel> {
        let list = ArrayList<OfferedDocModel>()
        list.add(mkOffered(Some("org.iso.18013.5.1.mDL"), None))
        list.add(mkOffered(None, Some("urn:pid:1")))
        list.add(mkOffered(Some("org.iso.18013.5.1.mDL"), None))
        return list
    }

    @TestCase
    func filterByDocTypeMatchesMdoc(): Unit {
        let result = OfferedDocModelHelper.filterByDocType(sampleModels(), "org.iso.18013.5.1.mDL")
        @Expect(result.size, 2)
    }

    @TestCase
    func filterByDocTypeMatchesVct(): Unit {
        let result = OfferedDocModelHelper.filterByDocType(sampleModels(), "urn:pid:1")
        @Expect(result.size, 1)
    }

    @TestCase
    func filterByDocTypeNoMatch(): Unit {
        let result = OfferedDocModelHelper.filterByDocType(sampleModels(), "nonexistent")
        @Expect(result.size, 0)
    }

    @TestCase
    func selectAllReturnsAll(): Unit {
        let arr = OfferedDocModelHelper.selectAll(sampleModels())
        @Expect(arr.size, 3)
    }
}

// ===========================================================================
// DocumentHelper
// ===========================================================================
@Test
class WkFacadeDocumentHelperUT {

    @TestCase
    func isIssued(): Unit {
        let d = mkDoc("t", DocumentStatus.Issued, None)
        @Expect(DocumentHelper.isIssued(d), true)
        @Expect(DocumentHelper.isDeferred(d), false)
        @Expect(DocumentHelper.isPending(d), false)
    }

    @TestCase
    func isDeferred(): Unit {
        let d = mkDoc("t", DocumentStatus.Deferred, None)
        @Expect(DocumentHelper.isDeferred(d), true)
        @Expect(DocumentHelper.isIssued(d), false)
    }

    @TestCase
    func isPending(): Unit {
        let d = mkDoc("t", DocumentStatus.Pending, None)
        @Expect(DocumentHelper.isPending(d), true)
    }

    @TestCase
    func describeUsesDisplayNameWhenPresent(): Unit {
        let d = mkDoc("org.iso.18013.5.1.mDL", DocumentStatus.Issued, Some("My mDL"))
        let s = DocumentHelper.describe(d)
        @Expect(s.contains("name=My mDL"), true)
        @Expect(s.contains("status=issued"), true)
        @Expect(s.contains("type=org.iso.18013.5.1.mDL"), true)
    }

    @TestCase
    func describeFallsBackToDocType(): Unit {
        let d = mkDoc("org.iso.18013.5.1.mDL", DocumentStatus.Deferred, None)
        let s = DocumentHelper.describe(d)
        @Expect(s.contains("name=org.iso.18013.5.1.mDL"), true)
        @Expect(s.contains("status=deferred"), true)
    }
}

// ===========================================================================
// WalletConfigHelper
// ===========================================================================
@Test
class WkFacadeWalletConfigHelperUT {

    @TestCase
    func testConfigOverridesServiceName(): Unit {
        let cfg = WalletConfigHelper.testConfig("my-service")
        @Expect(cfg.serviceName, "my-service")
        @Expect(cfg.userAuthenticationRequired, false)
        match (cfg.uiCulture) {
            case Some(c) => @Expect(c, "en")
            case None => @Expect("none", "some")
        }
    }

    @TestCase
    func buildWalletRegistersVci(): Unit {
        let walletCfg = WalletConfigHelper.testConfig("svc")
        let vciCfg = OpenId4VciConfiguration.withIssuerURL(Some("https://issuer.example"))
        let wallet = WalletConfigHelper.buildWallet(walletCfg, vciCfg, "issuer-1")
        @Expect(wallet.eudiWalletConfig.serviceName, "svc")
        // The registered VCI service must now resolve by name (no throw),
        // proving addOpenId4VciConfiguration wired it in.
        var threw = false
        try {
            // resolveVciService is private; getDefaultCredentialOptions exercises it.
            // For a registered issuer it does NOT throw IssuerNotRegistered. It may
            // throw later (network metadata), so we only assert it is NOT the
            // IssuerNotRegistered code.
            let _ = wallet.getDefaultCredentialOptions("issuer-1", DocTypeIdentifier.MsoMdoc("org.iso.18013.5.1.mDL"))
        } catch (e: WalletError) {
            match (e.code) {
                case Some(c) => if (c.rawValue() == "issuerNotRegistered") { threw = true }
                case None => ()
            }
        } catch (_: Exception) {
            ()
        }
        @Expect(threw, false)
    }
}

// ===========================================================================
// EudiWalletExtensions (against in-memory empty store)
// ===========================================================================
@Test
class WkFacadeEudiWalletExtensionsUT {

    @TestCase
    func loadedDocumentsEmptyStore(): Unit {
        let wallet = EudiWallet(EudiWalletConfiguration.defaultConfig())
        let docs = EudiWalletExtensions.loadedDocuments(wallet, "org.iso.18013.5.1.mDL")
        @Expect(docs.size, 0)
    }

    @TestCase
    func countDocumentsEmptyStore(): Unit {
        let wallet = EudiWallet(EudiWalletConfiguration.defaultConfig())
        @Expect(EudiWalletExtensions.countDocuments(wallet, "any"), 0)
    }

    @TestCase
    func authorizedActionRunsWhenAuthNotRequired(): Unit {
        let wallet = EudiWallet(EudiWalletConfiguration.defaultConfig())
        let flag = FlagBox()
        EudiWalletExtensions.authorizedAction(wallet, { => flag.value = true }, false, "reason")
        @Expect(flag.value, true)
    }

    @TestCase
    func authorizedActionDisabledRunsAction(): Unit {
        let wallet = EudiWallet(EudiWalletConfiguration.defaultConfig())
        let flag = FlagBox()
        EudiWalletExtensions.authorizedAction(wallet, { => flag.value = true }, true, "reason")
        @Expect(flag.value, true)
    }
}

// ===========================================================================
// EudiWallet pure-logic methods
// ===========================================================================
@Test
class WkFacadeEudiWalletPureUT {

    @TestCase
    func parseTransactionLogFormats(): Unit {
        let wallet = EudiWallet(EudiWalletConfiguration.defaultConfig())
        let entry = TransactionLogEntry("id-1", TransactionType.Issuance, "2026-06-19T10:00:00Z", TransactionStatus.Completed)
        let s = wallet.parseTransactionLog(entry)
        @Expect(s, "issuance at 2026-06-19T10:00:00Z status=completed")
    }

    @TestCase
    func parseTransactionLogPresentationFailed(): Unit {
        let wallet = EudiWallet(EudiWalletConfiguration.defaultConfig())
        let entry = TransactionLogEntry("id-2", TransactionType.PresentationBle, "2026-06-19T11:00:00Z", TransactionStatus.Failed)
        let s = wallet.parseTransactionLog(entry)
        @Expect(s, "presentation_ble at 2026-06-19T11:00:00Z status=failed")
    }

    @TestCase
    func getDefaultCredentialOptionsThrowsForUnregisteredIssuer(): Unit {
        let wallet = EudiWallet(EudiWalletConfiguration.defaultConfig())
        var caught = false
        try {
            let _ = wallet.getDefaultCredentialOptions("unknown-issuer", DocTypeIdentifier.MsoMdoc("t"))
        } catch (e: WalletError) {
            match (e.code) {
                case Some(c) => if (c.rawValue() == "issuerNotRegistered") { caught = true }
                case None => ()
            }
        } catch (_: Exception) {
            ()
        }
        @Expect(caught, true)
    }
}
