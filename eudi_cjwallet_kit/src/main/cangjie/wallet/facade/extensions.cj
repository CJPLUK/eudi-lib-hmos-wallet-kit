/*
 * extensions.cj
 *
 * EUDI Wallet Kit — helper functions and type extensions for the facade.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Extensions.swift  (618 lines)
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.facade  (S-002)
 *
 * iOS Extensions.swift contains Swift protocol extensions on EudiWallet,
 * WalletStorage types, and various models.  In Cangjie there are no extension
 * methods on external types; instead this file provides:
 *   - Top-level helper functions that parallel the iOS extension logic.
 *   - EudiWalletExtensions class with static helpers (mirrors iOS extension methods).
 *   - CredentialOptionsHelper and DocumentHelper with convenience factories.
 *
 * Design decisions:
 *   - iOS extension on WalletStorage.Document → static func on DocumentHelper class.
 *   - iOS extension on EudiWallet (authorizedAction) → EudiWalletExtensions.authorizedAction.
 *   - iOS extension on DocClaims → DocClaimsHelper static funcs.
 *   - No UIKit dependency (iOS-only); HarmonyOS callers use system biometric APIs directly.
 *
 * Syntax rules observed:
 *   S-002: package matches directory path
 *   R-101..R-111: see syntax_error.md
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.facade

import kit.PerformanceAnalysisKit.Hilog

import std.collection.ArrayList
import std.collection.HashMap

import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.{
    WalletError,
    WalletErrorCode,
    DocTypeIdentifier,
    OfferedDocModel,
    EudiWalletConfiguration,
    OpenId4VciConfiguration,
    OpenId4VpConfiguration
}

import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.{
    CredentialOptions,
    CredentialPolicy,
    KeyOptions
}
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.storage.StorageManager
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.support.{FlowType, WalletLogger, FileLogging}

import ohos_app_cangjie_eudi_cjwallet_storage.storage.types.{Document, DocumentStatus}

// ===========================================================================
// EudiWalletExtensions
// iOS: extension EudiWallet { authorizedAction, getDocumentInfos, … }
// Cangjie: static helpers on this class
// ===========================================================================

/**
 * Static helper functions extending EudiWallet behaviour.
 *
 * Mirrors iOS extension methods on EudiWallet in Extensions.swift.
 * Since Cangjie does not support extension methods on existing classes,
 * these are provided as static functions that accept an EudiWallet instance.
 */
public class EudiWalletExtensions {

    private init() {}

    /**
     * Perform an action after user authorization (biometric or passcode).
     *
     * Mirrors iOS EudiWallet.authorizedAction(action:disabled:dismiss:localizedReason:).
     *
     * On HarmonyOS, biometric authentication is handled via UserIAM kit at the
     * application layer; this helper is a no-op delegate that executes the action
     * directly when userAuthenticationRequired is false, or logs a warning and
     * executes when required but not yet integrated with UserIAM.
     *
     * @param wallet             The EudiWallet instance.
     * @param action             Closure to execute after authorization.
     * @param disabled           Skip auth when true (testing / development mode).
     * @param localizedReason    Reason shown to the user for authentication.
     */
    public static func authorizedAction(
        wallet: EudiWallet,
        action: () -> Unit,
        disabled: Bool,
        localizedReason: String
    ): Unit {
        if (disabled || !wallet.eudiWalletConfig.userAuthenticationRequired) {
            action()
            return
        }
        Hilog.warn(0, "EudiWalletExtensions",
            "authorizedAction: userAuthenticationRequired=true — " +
            "integrate with HarmonyOS UserIAM kit for production use. " +
            "Reason: " + localizedReason)
        action()
    }

    /**
     * Load documents of a specific type from storage.
     *
     * Mirrors iOS EudiWallet extension that filters loadedDocuments by docType.
     *
     * @param wallet   The EudiWallet instance.
     * @param docType  ISO 18013-5 docType or vct string to filter by.
     * @return Matching documents, or empty list if none.
     */
    public static func loadedDocuments(wallet: EudiWallet, docType: String): ArrayList<Document> {
        let result = ArrayList<Document>()
        let allOpt = wallet.loadDocuments(DocumentStatus.Issued)
        match (allOpt) {
            case Some(docs) =>
                var i: Int64 = 0
                while (i < docs.size) {
                    if (docs[i].docType == docType) {
                        result.add(docs[i])
                    }
                    i++
                }
            case None => ()
        }
        return result
    }

    /**
     * Count how many documents of a given type are in the wallet.
     *
     * Mirrors iOS EudiWallet.count(of:) extension.
     *
     * @param wallet   The EudiWallet instance.
     * @param docType  Document type string.
     * @return Count of matching issued documents.
     */
    public static func countDocuments(wallet: EudiWallet, docType: String): Int64 {
        return loadedDocuments(wallet, docType).size
    }
}

// ===========================================================================
// DocumentHelper
// iOS: extension WalletStorage.Document (in Extensions.swift)
// Cangjie: static helpers on DocumentHelper class
// ===========================================================================

/**
 * Helpers for working with wallet storage Document objects.
 *
 * Mirrors iOS extension methods on WalletStorage.Document in Extensions.swift.
 */
public class DocumentHelper {

    private init() {}

    /**
     * Return true if the document has issued status.
     * Mirrors iOS Document.isIssued computed property.
     */
    public static func isIssued(doc: Document): Bool {
        match (doc.status) {
            case DocumentStatus.Issued => return true
            case _ => return false
        }
    }

    /**
     * Return true if the document has deferred status.
     * Mirrors iOS Document.isDeferred computed property.
     */
    public static func isDeferred(doc: Document): Bool {
        match (doc.status) {
            case DocumentStatus.Deferred => return true
            case _ => return false
        }
    }

    /**
     * Return true if the document has pending status.
     * Mirrors iOS Document.isPending computed property.
     */
    public static func isPending(doc: Document): Bool {
        match (doc.status) {
            case DocumentStatus.Pending => return true
            case _ => return false
        }
    }

    /**
     * Return a human-readable description of a document.
     * Mirrors iOS Document.description.
     *
     * @param doc  The document.
     * @return Formatted description string.
     */
    public static func describe(doc: Document): String {
        let statusStr: String = match (doc.status) {
            case DocumentStatus.Issued   => "issued"
            case DocumentStatus.Deferred => "deferred"
            case DocumentStatus.Pending  => "pending"
        }
        let name: String = match (doc.displayName) {
            case Some(n) => n
            case None    => doc.docType
        }
        return "Document[id=" + doc.id + " type=" + doc.docType + " name=" + name + " status=" + statusStr + "]"
    }
}

// ===========================================================================
// FlowTypeHelper
// iOS: extension FlowType (in Enumerations.swift / Extensions.swift)
// ===========================================================================

/**
 * Helpers for FlowType discrimination.
 * Mirrors iOS FlowType switch logic used in EudiWallet.beginPresentation.
 */
public class FlowTypeHelper {

    private init() {}

    /**
     * Return true if this is a BLE proximity flow.
     */
    public static func isBle(flow: FlowType): Bool {
        match (flow) {
            case FlowType.Ble => return true
            case _ => return false
        }
    }

    /**
     * Return true if this is an OpenID4VP remote flow.
     */
    public static func isOpenId4Vp(flow: FlowType): Bool {
        match (flow) {
            case FlowType.OpenId4Vp(_) => return true
            case _ => return false
        }
    }

    /**
     * Human-readable label for a FlowType.
     * Mirrors iOS FlowType description in Extensions.swift.
     */
    public static func label(flow: FlowType): String {
        match (flow) {
            case FlowType.Ble       => return "ble"
            case FlowType.OpenId4Vp(_) => return "openid4vp"
            case FlowType.Other     => return "other"
        }
    }
}

// ===========================================================================
// CredentialOptionsHelper
// iOS: extension CredentialOptions (in Extensions.swift)
// ===========================================================================

/**
 * Convenience factories for CredentialOptions.
 * Mirrors iOS CredentialOptions extensions / static factories.
 */
public class CredentialOptionsHelper {

    private init() {}

    /**
     * One-time-use policy with batch size 1.
     * Mirrors iOS CredentialOptions.oneTimeUse.
     */
    public static func oneTimeUse(): CredentialOptions {
        return CredentialOptions(CredentialPolicy.OneTimeUse, 1)
    }

    /**
     * Rotate-use (reusable) policy with batch size 1.
     * Mirrors iOS CredentialOptions.rotateUse.
     */
    public static func rotateUse(): CredentialOptions {
        return CredentialOptions(CredentialPolicy.RotateUse, 1)
    }

    /**
     * One-time-use policy with the given batch size.
     *
     * @param batchSize  Number of credentials to issue in the batch.
     */
    public static func oneTimeUseBatch(batchSize: Int64): CredentialOptions {
        return CredentialOptions(CredentialPolicy.OneTimeUse, batchSize)
    }
}

// ===========================================================================
// OfferedDocModelHelper
// iOS: extension OfferedDocModel (in Extensions.swift)
// ===========================================================================

/**
 * Helpers for OfferedDocModel filtering and selection.
 * Mirrors iOS extension methods on OfferedDocModel in Extensions.swift.
 */
public class OfferedDocModelHelper {

    private init() {}

    /**
     * Filter an offered issuance model's doc models by document type.
     *
     * Mirrors iOS [OfferedDocModel].filter(docType:).
     *
     * @param models   Source list of OfferedDocModel.
     * @param docType  docType (msoMdoc) or vct (sdJwt) string to match.
     * @return Matching offered doc models.
     */
    public static func filterByDocType(
        models: ArrayList<OfferedDocModel>,
        docType: String
    ): ArrayList<OfferedDocModel> {
        let result = ArrayList<OfferedDocModel>()
        var i: Int64 = 0
        while (i < models.size) {
            let m = models[i]
            let matched: Bool = match (m.docType) {
                case Some(dt) => dt == docType
                case None =>
                    match (m.vct) {
                        case Some(v) => v == docType
                        case None => false
                    }
            }
            if (matched) {
                result.add(m)
            }
            i++
        }
        return result
    }

    /**
     * Select all offered doc models (convenience: select all for issuing).
     *
     * Mirrors iOS OfferedIssuanceModel.docModels.
     *
     * @param models  Source offered doc models.
     * @return All models as an Array.
     */
    public static func selectAll(models: ArrayList<OfferedDocModel>): Array<OfferedDocModel> {
        return models.toArray()
    }
}

// ===========================================================================
// WalletConfigHelper
// iOS: convenience extensions on EudiWalletConfiguration
// ===========================================================================

/**
 * Convenience builders for wallet configuration.
 * Mirrors iOS EudiWalletConfiguration extensions in Extensions.swift.
 */
public class WalletConfigHelper {

    private init() {}

    /**
     * Build a minimal EudiWalletConfiguration for testing.
     *
     * Uses EudiWalletConfiguration.defaultConfig() and overrides the service name.
     * Default: deviceAuth=DeviceSignature, bleTransferMode=Server, userAuth=false.
     *
     * @param serviceName  Service name for the wallet key store.
     * @return EudiWalletConfiguration with test-friendly defaults.
     */
    public static func testConfig(serviceName: String): EudiWalletConfiguration {
        // Use the default factory which already sets DeviceSignature + Server + false
        // and override only the service name.
        let def = EudiWalletConfiguration.defaultConfig()
        return EudiWalletConfiguration(
            serviceName,
            def.accessGroup,
            def.userAuthenticationRequired,
            def.trustedReaderRootCertificates,
            def.deviceAuthMethod,
            Some("en"),
            def.logFileName,
            def.bleTransferMode
        )
    }

    /**
     * Build a complete EudiWallet with a VCI configuration registered.
     *
     * @param walletConfig  Top-level wallet configuration.
     * @param vciConfig     OpenID4VCI configuration to pre-register.
     * @param issuerName    Name to register the VCI configuration under.
     * @return A ready-to-use EudiWallet with VCI registered.
     */
    public static func buildWallet(
        walletConfig: EudiWalletConfiguration,
        vciConfig: OpenId4VciConfiguration,
        issuerName: String
    ): EudiWallet {
        let wallet = EudiWallet(walletConfig)
        wallet.addOpenId4VciConfiguration(issuerName, vciConfig)
        return wallet
    }
}
