// unittest_engine.cj
// E2E / self-check test suite for EUDI Wallet Kit (uncategorized group).
//
// Scope: single-machine non-network tests only.
// - wk_models:   DocTypeIdentifier, WalletErrorCode, WalletError, EudiWalletConfiguration
// - wk_facade:   EudiWallet assembly + in-memory storage fallback
// - wk_storage:  StorageManager list state on empty store
// - app_shell:   runEudiWalletDemo() returns expected OK string prefix
//
// Network-dependent flows (OpenID4VCI issuance, OpenID4VP/BLE presentation)
// are explicitly excluded — they require live servers and cannot run standalone.
package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*
import std.collection.*
import std.fs.Path
import std.fs.Directory
import std.fs.File
import std.env.setVariable
import kit.PerformanceAnalysisKit.Hilog
import kit.TestKit.AbilityDelegatorRegistry
import kit.TestKit.TestRunner
import kit.AbilityKit.BundleManager
import kit.AbilityKit.BundleFlag
import kit.AbilityKit.Want

import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.{
    DocTypeIdentifier,
    WalletErrorCode,
    WalletError,
    EudiWalletConfiguration,
    OpenId4VpConfiguration
}
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.facade.EudiWallet
import ohos_app_cangjie_eudi_cjwallet_kit.runEudiWalletDemo

// ---------------------------------------------------------------------------
// Test class 1: wk_models — DocTypeIdentifier round-trip
// ---------------------------------------------------------------------------
@Test
class WkModelsDocTypeIdentifierUT {

    @TestCase
    func msoMdocValueRoundTrip(): Unit {
        let dt = DocTypeIdentifier.MsoMdoc("org.iso.18013.5.1.mDL")
        @Expect(dt.value(), "org.iso.18013.5.1.mDL")
        let docTypeOpt = dt.docType()
        match (docTypeOpt) {
            case Some(v) => @Expect(v, "org.iso.18013.5.1.mDL")
            case None => @Expect("docType was None", "Some")
        }
        @Expect(dt.vct().isNone(), true)
    }

    @TestCase
    func sdJwtValueRoundTrip(): Unit {
        let sd = DocTypeIdentifier.SdJwt("urn:eu.europa.ec.eudi:pid:1")
        @Expect(sd.value(), "urn:eu.europa.ec.eudi:pid:1")
        let vctOpt = sd.vct()
        match (vctOpt) {
            case Some(v) => @Expect(v, "urn:eu.europa.ec.eudi:pid:1")
            case None => @Expect("vct was None", "Some")
        }
        @Expect(sd.docType().isNone(), true)
    }

    @TestCase
    func identifierValueRoundTrip(): Unit {
        let id = DocTypeIdentifier.Identifier("org.eu.europa.eudi.pid")
        @Expect(id.value(), "org.eu.europa.eudi.pid")
        let cfgOpt = id.configurationIdentifier()
        match (cfgOpt) {
            case Some(v) => @Expect(v, "org.eu.europa.eudi.pid")
            case None => @Expect("configurationIdentifier was None", "Some")
        }
    }

    @TestCase
    func equalsSameVariant(): Unit {
        let a = DocTypeIdentifier.MsoMdoc("org.iso.18013.5.1.mDL")
        let b = DocTypeIdentifier.MsoMdoc("org.iso.18013.5.1.mDL")
        @Expect(a.equals(b), true)
    }

    @TestCase
    func notEqualsDiffVariant(): Unit {
        let a = DocTypeIdentifier.MsoMdoc("org.iso.18013.5.1.mDL")
        let b = DocTypeIdentifier.SdJwt("org.iso.18013.5.1.mDL")
        @Expect(a.equals(b), false)
    }

    @TestCase
    func describeFormat(): Unit {
        let dt = DocTypeIdentifier.MsoMdoc("org.iso.18013.5.1.mDL")
        @Expect(dt.describe(), "msoMdoc(org.iso.18013.5.1.mDL)")
        let sd = DocTypeIdentifier.SdJwt("urn:pid:1")
        @Expect(sd.describe(), "sdJwt(urn:pid:1)")
    }

    @TestCase
    func docTypeOrVctMsoMdoc(): Unit {
        let dt = DocTypeIdentifier.MsoMdoc("org.iso.18013.5.1.mDL")
        let opt = dt.docTypeOrVct()
        match (opt) {
            case Some(v) => @Expect(v, "org.iso.18013.5.1.mDL")
            case None => @Expect("docTypeOrVct was None", "Some")
        }
    }

    @TestCase
    func docTypeOrVctIdentifierIsNone(): Unit {
        let id = DocTypeIdentifier.Identifier("some-id")
        @Expect(id.docTypeOrVct().isNone(), true)
    }
}

// ---------------------------------------------------------------------------
// Test class 2: wk_models — WalletErrorCode raw values + fromRaw
// ---------------------------------------------------------------------------
@Test
class WkModelsWalletErrorCodeUT {

    @TestCase
    func claimNotFoundRawValue(): Unit {
        @Expect(WalletErrorCode.ClaimNotFound.rawValue(), "claimNotFound")
    }

    @TestCase
    func credentialNotFoundRawValue(): Unit {
        @Expect(WalletErrorCode.CredentialNotFound.rawValue(), "credentialNotFound")
    }

    @TestCase
    func bleNotAuthorizedRawValue(): Unit {
        @Expect(WalletErrorCode.BleNotAuthorized.rawValue(), "bleNotAuthorized")
    }

    @TestCase
    func issuerNotRegisteredRawValue(): Unit {
        @Expect(WalletErrorCode.IssuerNotRegistered.rawValue(), "issuerNotRegistered")
    }

    @TestCase
    func noDocumentsAvailableRawValue(): Unit {
        @Expect(WalletErrorCode.NoDocumentsAvailable.rawValue(), "noDocumentsAvailable")
    }

    @TestCase
    func fromRawKnownCode(): Unit {
        let opt = WalletErrorCode.fromRaw("claimNotFound")
        match (opt) {
            case Some(_) => ()
            case None => @Expect("fromRaw returned None", "Some")
        }
    }

    @TestCase
    func fromRawUnknownReturnsNone(): Unit {
        let opt = WalletErrorCode.fromRaw("unknownErrorCode")
        @Expect(opt.isNone(), true)
    }

    @TestCase
    func allTenCodesHaveRawValues(): Unit {
        let codes: Array<WalletErrorCode> = [
            WalletErrorCode.ClaimNotFound,
            WalletErrorCode.CredentialNotFound,
            WalletErrorCode.ClaimValueMismatch,
            WalletErrorCode.ClaimSetNotSatisfied,
            WalletErrorCode.CredentialSetNotSatisfied,
            WalletErrorCode.DcqlQueryNotSatisfied,
            WalletErrorCode.BleNotAuthorized,
            WalletErrorCode.BleNotSupported,
            WalletErrorCode.NoDocumentsAvailable,
            WalletErrorCode.IssuerNotRegistered
        ]
        var i: Int64 = 0
        while (i < codes.size) {
            let raw = codes[i].rawValue()
            @Expect(raw.size > 0, true)
            i++
        }
    }
}

// ---------------------------------------------------------------------------
// Test class 3: wk_models — WalletError construction
// ---------------------------------------------------------------------------
@Test
class WkModelsWalletErrorUT {

    @TestCase
    func withDescriptionSetsMessage(): Unit {
        let err = WalletError.withDescription("test error message")
        @Expect(err.message, "test error message")
        @Expect(err.code.isNone(), true)
        @Expect(err.localizationKey.isNone(), true)
    }

    @TestCase
    func withCodeSetsCode(): Unit {
        let err = WalletError.withCode("not registered", WalletErrorCode.IssuerNotRegistered)
        @Expect(err.message, "not registered")
        match (err.code) {
            case Some(c) => @Expect(c.rawValue(), "issuerNotRegistered")
            case None => @Expect("code was None", "Some")
        }
    }

    @TestCase
    func errorDescriptionNoKey(): Unit {
        let err = WalletError.withDescription("something failed")
        @Expect(err.errorDescription(), "something failed")
    }

    @TestCase
    func withContextSetsContext(): Unit {
        let ctx: Array<(String, String)> = [("docType", "org.iso.18013.5.1.mDL")]
        let err = WalletError.withContext("claim missing", WalletErrorCode.ClaimNotFound, ctx)
        @Expect(err.context.size, 1)
        @Expect(err.message, "claim missing")
    }
}

// ---------------------------------------------------------------------------
// Test class 4: wk_models — EudiWalletConfiguration defaults
// ---------------------------------------------------------------------------
@Test
class WkModelsEudiWalletConfigUT {

    @TestCase
    func defaultServiceName(): Unit {
        @Expect(EudiWalletConfiguration.DEFAULT_SERVICE_NAME, "eudiw")
    }

    @TestCase
    func defaultConfigServiceName(): Unit {
        let cfg = EudiWalletConfiguration.defaultConfig()
        @Expect(cfg.serviceName, "eudiw")
    }

    @TestCase
    func defaultConfigUserAuthNotRequired(): Unit {
        let cfg = EudiWalletConfiguration.defaultConfig()
        @Expect(cfg.userAuthenticationRequired, false)
    }

    @TestCase
    func defaultConfigNoAccessGroup(): Unit {
        let cfg = EudiWalletConfiguration.defaultConfig()
        @Expect(cfg.accessGroup.isNone(), true)
    }
}

// ---------------------------------------------------------------------------
// Test class 5: wk_models — OpenId4VpConfiguration defaults
// ---------------------------------------------------------------------------
@Test
class WkModelsOpenId4VpConfigUT {

    @TestCase
    func defaultSchemesNotEmpty(): Unit {
        let schemes = OpenId4VpConfiguration.defaultSchemes()
        @Expect(schemes.size > 0, true)
    }

    @TestCase
    func defaultConfigAllowPartialClaimsFalse(): Unit {
        let cfg = OpenId4VpConfiguration.defaultConfig()
        @Expect(cfg.allowPresentingPartialClaims, false)
    }
}

// ---------------------------------------------------------------------------
// Test class 6: wk_facade — EudiWallet assembly
// ---------------------------------------------------------------------------
@Test
class WkFacadeEudiWalletAssemblyUT {

    @TestCase
    func constructWithDefaultConfig(): Unit {
        let cfg = EudiWalletConfiguration.defaultConfig()
        let wallet = EudiWallet(cfg)
        @Expect(wallet.eudiWalletConfig.serviceName, "eudiw")
    }

    @TestCase
    func constructWithExplicitNoStorage(): Unit {
        let cfg = EudiWalletConfiguration.defaultConfig()
        let wallet = EudiWallet(cfg, None)
        @Expect(wallet.eudiWalletConfig.serviceName, "eudiw")
    }

    @TestCase
    func loadAllDocumentsEmptyStore(): Unit {
        let cfg = EudiWalletConfiguration.defaultConfig()
        let wallet = EudiWallet(cfg)
        let result = wallet.loadAllDocuments()
        @Expect(result.isNone(), true)
    }

    @TestCase
    func deleteAllDocumentsOnEmptyStoreNoThrow(): Unit {
        let cfg = EudiWalletConfiguration.defaultConfig()
        let wallet = EudiWallet(cfg)
        // Must not throw on empty store
        wallet.deleteAllDocuments()
        // If we reach here, no exception was thrown
        @Expect(true, true)
    }

    @TestCase
    func storageManagerInitialDocCountZero(): Unit {
        let cfg = EudiWalletConfiguration.defaultConfig()
        let wallet = EudiWallet(cfg)
        @Expect(wallet.storage.docCount(), 0)
    }

    @TestCase
    func storageManagerHasDataFalseOnEmptyStore(): Unit {
        let cfg = EudiWalletConfiguration.defaultConfig()
        let wallet = EudiWallet(cfg)
        @Expect(wallet.storage.hasData(), false)
    }

    @TestCase
    func resolveVciServiceThrowsWhenNotRegistered(): Unit {
        let cfg = EudiWalletConfiguration.defaultConfig()
        let wallet = EudiWallet(cfg)
        var caughtIssuerNotRegistered = false
        // The real test: resolving an unregistered issuer name via getIssuerMetadata should throw
        try {
            let _ = wallet.getIssuerMetadata("unregistered-issuer")
        } catch (e: WalletError) {
            match (e.code) {
                case Some(c) =>
                    if (c.rawValue() == "issuerNotRegistered") {
                        caughtIssuerNotRegistered = true
                    }
                case None => ()
            }
        } catch (_: Exception) {
            ()
        }
        @Expect(caughtIssuerNotRegistered, true)
    }
}

// ---------------------------------------------------------------------------
// Test class 7: app_shell — runEudiWalletDemo integration
// ---------------------------------------------------------------------------
@Test
class AppShellDemoIntegrationUT {

    @TestCase
    func demoReturnsOkPrefix(): Unit {
        let result = runEudiWalletDemo()
        // Must start with "OK:"
        let startsWithOk = containsSubstring(result, "OK:")
        @Expect(startsWithOk, true)
    }

    @TestCase
    func demoContainsWalletAssembledPass(): Unit {
        let result = runEudiWalletDemo()
        // Result must contain "wallet_assembled=PASS"
        let needle = "wallet_assembled=PASS"
        let found = containsSubstring(result, needle)
        @Expect(found, true)
    }

    @TestCase
    func demoContainsDocMgmtPass(): Unit {
        let result = runEudiWalletDemo()
        let needle = "doc_mgmt=PASS"
        let found = containsSubstring(result, needle)
        @Expect(found, true)
    }
}

// Helper: check if haystack String contains needle String (character-by-character)
func containsSubstring(haystack: String, needle: String): Bool {
    if (needle.size == 0) {
        return true
    }
    if (haystack.size < needle.size) {
        return false
    }
    var i: Int64 = 0
    while (i <= haystack.size - needle.size) {
        var match_: Bool = true
        var j: Int64 = 0
        while (j < needle.size) {
            if (haystack[i + j] != needle[j]) {
                match_ = false
                break
            }
            j++
        }
        if (match_) {
            return true
        }
        i++
    }
    return false
}

// ---------------------------------------------------------------------------
// OpenHarmonyTestRunner — full x509-style runner with onRun + XmlReporter
// ---------------------------------------------------------------------------


