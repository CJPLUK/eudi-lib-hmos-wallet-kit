/*
 * config.cj
 *
 * EUDI Wallet Kit — configuration data models.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Models/EudiWalletConfiguration.swift
 *   Sources/EudiWalletKit/Models/OpenId4VCIConfiguration.swift
 *   Sources/EudiWalletKit/Models/OpenId4VpConfiguration.swift
 *   Sources/EudiWalletKit/Models/KeyAttestationConfiguration.swift
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.models  (S-002)
 *
 * Upstream dependencies consumed (read-only):
 *   ohos_app_cangjie_eudi_cjmdoc_transfer   → BleTransferMode
 *   ohos_app_cangjie_eudi_cjmdoc_security   → DeviceAuthMethod
 *   ohos_app_cangjie_eudi_cjopenid4vp_vci   → AuthorizeIssuanceConfig, IssuerMetadataPolicy
 *   ohos_app_cangjie_eudi_cjmdoc_data_model → KeyOptions, CredentialOptions
 *
 * Notes:
 *   - R-101: init params use positional style; named-param style needs `!` prefix
 *     in the declaration (not used here to keep compat with direct instantiation).
 *   - Swift struct → Cangjie class (no value-type semantics needed for config objects).
 *   - @Copyable / Swift `Copyable` macro → no equivalent needed in Cangjie.
 *   - iOS WalletAttestationsProvider protocol → interface WalletAttestationsProvider.
 *   - iOS KeyAttestationConfiguration holds `any WalletAttestationsProvider`
 *     → Cangjie: interface field `provider: WalletAttestationsProvider`.
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.models

import ohos_app_cangjie_eudi_cjmdoc_transfer.transfer.framing.BleTransferMode
import ohos_app_cangjie_eudi_cjmdoc_security.security.device_auth.DeviceAuthMethod
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.config.AuthorizeIssuanceConfig
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.config.IssuerMetadataPolicy
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.KeyOptions
import ohos_app_cangjie_eudi_cjetsi_1196x2.etsi_trust.TrustConfiguration

// ===========================================================================
// WalletAttestationsProvider (interface)
// iOS: public protocol WalletAttestationsProvider: Sendable
// ===========================================================================

/**
 * Provider interface for wallet attestation JWTs.
 * Downstream implementations supply a device/software attestation and a
 * keys-attestation JWT required by the OpenID4VCI client attestation flow.
 */
public interface WalletAttestationsProvider {
    /**
     * Return a signed wallet attestation JWT for the given signing key.
     * iOS: func getWalletAttestation(signingKey: SigningKeyProxy) async throws -> String
     * Cangjie: synchronous (async-await not available at this layer).
     */
    func getWalletAttestation(signingKeyId: String): String

    /**
     * Return a signed keys-attestation JWT covering the supplied public keys.
     * iOS: func getKeysAttestation(keys: [any JWK], nonce: String?) async throws -> String
     */
    func getKeysAttestation(publicKeyBytes: Array<Array<UInt8>>, nonce: ?String): String
}

// ===========================================================================
// KeyAttestationConfiguration
// iOS: @Copyable public struct KeyAttestationConfiguration: Sendable
// ===========================================================================

/**
 * Configuration for key attestation in the OpenID4VCI client-attestation flow.
 *
 * walletAttestationsProvider — produces wallet/keys attestation JWTs
 * popKeyOptions              — optional key options for the PoP key pair
 * popKeyDuration             — optional lifetime (seconds) for the PoP JWT
 */
public class KeyAttestationConfiguration {
    public let walletAttestationsProvider: WalletAttestationsProvider
    public let popKeyOptions: ?KeyOptions
    public let popKeyDurationSeconds: ?Float64

    public init(walletAttestationsProvider: WalletAttestationsProvider,
                popKeyOptions: ?KeyOptions,
                popKeyDurationSeconds: ?Float64) {
        this.walletAttestationsProvider = walletAttestationsProvider
        this.popKeyOptions = popKeyOptions
        this.popKeyDurationSeconds = popKeyDurationSeconds
    }
}

// ===========================================================================
// ClientIdScheme
// iOS: public enum ClientIdScheme: Sendable  (in OpenId4VpConfiguration.swift)
// ===========================================================================

/**
 * Client identifier scheme for verifier authentication during OpenID4VP flows.
 *
 * Cangjie enum variant names use CamelCase to avoid keyword collision and
 * match idiomatic Cangjie (R-102: no static let in enum body).
 */
public enum ClientIdScheme {
    /**
     * Pre-registered verifier whitelist.
     * Each entry is a tuple (clientId, legalName, verifierApiUri).
     */
    | Preregistered(Array<(String, String, String)>)
    /** X.509 SAN DNS validation. */
    | X509SanDns
    /** X.509 certificate hash validation. */
    | X509Hash
    /** Redirect URI validation. */
    | RedirectUri
}

// ===========================================================================
// OpenId4VpConfiguration
// iOS: @Copyable public struct OpenId4VpConfiguration: Sendable
// ===========================================================================

/**
 * Configuration for the OpenID4VP (Verifiable Presentations) protocol.
 *
 * clientIdSchemes            — accepted verifier authentication methods
 * allowPresentingPartialClaims — skip missing claims instead of failing DCQL
 */
public class OpenId4VpConfiguration {
    public let clientIdSchemes: Array<ClientIdScheme>
    public let allowPresentingPartialClaims: Bool
    /**
     * Whether to validate the WRP registration certificate (WRPRC) delivered
     * in the request's `verifier_info` (remote) or in the DeviceRequest
     * requestInfo `euWrprc` entries (proximity). Defaults to false; when
     * disabled the presentation flow behaves exactly as before.
     * Mirrors iOS OpenId4VpConfiguration.validateRegistrationCertificate.
     */
    public let validateRegistrationCertificate: Bool

    /** Default client-id schemes matching iOS defaults (.x509SanDns, .x509Hash, .redirectUri). */
    public static func defaultSchemes(): Array<ClientIdScheme> {
        return [ClientIdScheme.X509SanDns, ClientIdScheme.X509Hash, ClientIdScheme.RedirectUri]
    }

    /** Default configuration (mirrors iOS public init()). */
    public static func defaultConfig(): OpenId4VpConfiguration {
        return OpenId4VpConfiguration(OpenId4VpConfiguration.defaultSchemes(), false)
    }

    public init(clientIdSchemes: Array<ClientIdScheme>,
                allowPresentingPartialClaims: Bool,
                validateRegistrationCertificate!: Bool = false) {
        this.clientIdSchemes = clientIdSchemes
        this.allowPresentingPartialClaims = allowPresentingPartialClaims
        this.validateRegistrationCertificate = validateRegistrationCertificate
    }
}

// ===========================================================================
// OpenId4VciConfiguration
// iOS: @Copyable public struct OpenId4VciConfiguration: Sendable
// ===========================================================================

/**
 * Configuration for the OpenID4VCI (Credential Issuance) protocol.
 *
 * Fields map 1-to-1 to iOS OpenId4VciConfiguration.
 * Complex iOS-only methods (makePoPConstructor, toOpenId4VCIConfig, etc.) that
 * depend on JOSESwift/iOS Security.framework are omitted — they are implemented
 * in the issuance service layer, not in the configuration value type.
 */
public class OpenId4VciConfiguration {
    /** URL of the credential issuer (nil means unset). */
    public let credentialIssuerURL: ?String
    /** OAuth2 client identifier. Defaults to "eudiw-abca". */
    public let clientId: String
    /** Key attestation configuration (optional). */
    public let keyAttestationsConfig: ?KeyAttestationConfiguration
    /** Redirect URI for the authorization flow completion. */
    public let authFlowRedirectionURI: String
    /** Authorization issuance policy. */
    public let authorizeIssuanceConfig: AuthorizeIssuanceConfig
    /** Whether PAR (Pushed Authorization Request) is required. */
    public let requirePAR: Bool
    /** Whether DPoP (Demonstrating Proof-of-Possession) is required. */
    public let requireDpop: Bool
    /** Policy for signed issuer metadata handling. */
    public let issuerMetadataPolicy: IssuerMetadataPolicy
    /** Whether user authentication is required for credential issuance. */
    public let userAuthenticationRequired: Bool
    /** Key options for DPoP key generation (optional). */
    public let dpopKeyOptions: ?KeyOptions
    /**
     * Whether to validate the WRP registration certificate (WRPRC) delivered
     * in the issuer metadata `issuer_info`. Requires issuerMetadataPolicy to
     * be RequireSigned, since WRPRC enforcement needs a cryptographically
     * bound issuer metadata signer to supply the WRPAC. Defaults to false;
     * when disabled the issuance flow behaves exactly as before.
     * Mirrors iOS OpenId4VciConfiguration.validateRegistrationCertificate.
     */
    public let validateRegistrationCertificate: Bool
    /**
     * Whether resolved issuer metadata may be cached per issuer URL.
     * false forces a fresh metadata fetch on every call (needed when
     * registration certificates or trust policies may change between runs).
     */
    public let cacheIssuerMetadata: Bool

    /** Default redirect URI (matches iOS "eudi-openid4ci://authorize"). */
    public static let DEFAULT_REDIRECT_URI: String = "eudi-openid4ci://authorize"
    /** Default client id (matches iOS "eudiw-abca"). */
    public static let DEFAULT_CLIENT_ID: String = "eudiw-abca"

    public init(credentialIssuerURL: ?String,
                clientId: String,
                keyAttestationsConfig: ?KeyAttestationConfiguration,
                authFlowRedirectionURI: String,
                authorizeIssuanceConfig: AuthorizeIssuanceConfig,
                requirePAR: Bool,
                requireDpop: Bool,
                issuerMetadataPolicy: IssuerMetadataPolicy,
                userAuthenticationRequired: Bool,
                dpopKeyOptions: ?KeyOptions,
                validateRegistrationCertificate!: Bool = false,
                cacheIssuerMetadata!: Bool = true) {
        this.credentialIssuerURL = credentialIssuerURL
        this.clientId = clientId
        this.keyAttestationsConfig = keyAttestationsConfig
        this.authFlowRedirectionURI = authFlowRedirectionURI
        this.authorizeIssuanceConfig = authorizeIssuanceConfig
        this.requirePAR = requirePAR
        this.requireDpop = requireDpop
        this.issuerMetadataPolicy = issuerMetadataPolicy
        this.userAuthenticationRequired = userAuthenticationRequired
        this.dpopKeyOptions = dpopKeyOptions
        this.validateRegistrationCertificate = validateRegistrationCertificate
        this.cacheIssuerMetadata = cacheIssuerMetadata
    }

    /**
     * Convenience factory with iOS-aligned defaults.
     * iOS init defaults: clientId="eudiw-abca", requirePAR=true, requireDpop=true,
     * issuerMetadataPolicy=.ignoreSigned, userAuthenticationRequired=false.
     */
    public static func withIssuerURL(credentialIssuerURL: ?String): OpenId4VciConfiguration {
        return OpenId4VciConfiguration(
            credentialIssuerURL,
            OpenId4VciConfiguration.DEFAULT_CLIENT_ID,
            None,
            OpenId4VciConfiguration.DEFAULT_REDIRECT_URI,
            AuthorizeIssuanceConfig.FavorScopes,
            true,
            true,
            IssuerMetadataPolicy.IgnoreSigned,
            false,
            None
        )
    }
}

// ===========================================================================
// EudiWalletConfiguration
// iOS: public struct EudiWalletConfiguration: Sendable
// ===========================================================================

/**
 * Top-level configuration for the EudiWallet instance.
 *
 * serviceName                    — keychain/key-store service name
 * accessGroup                    — key-store access group (optional, iOS-only concept;
 *                                  kept for API parity, unused on HarmonyOS)
 * userAuthenticationRequired     — biometric/passcode gate before sending data
 * trustedReaderRootCertificates  — DER-encoded X.509 root certificates for reader auth
 * trustConfiguration             — iOS TrustConfiguration; when set, reader anchors
 *                                  come from accessTrustManager instead of the static list
 * deviceAuthMethod               — MAC or signature authentication method
 * uiCulture                      — 2-letter BCP-47 language code for display name locale
 * logFileName                    — optional log file name
 * bleTransferMode                — BLE role: Server / Client / Both
 */
public class EudiWalletConfiguration {
    public let serviceName: String
    public let accessGroup: ?String
    public let userAuthenticationRequired: Bool
    public let trustedReaderRootCertificates: ?Array<Array<UInt8>>
    public let trustConfiguration: ?TrustConfiguration
    public let deviceAuthMethod: DeviceAuthMethod
    public let uiCulture: ?String
    public let logFileName: ?String
    public let bleTransferMode: BleTransferMode

    /** Default service name matching iOS defaultServiceName = "eudiw". */
    public static let DEFAULT_SERVICE_NAME: String = "eudiw"

    public init(serviceName: String,
                accessGroup: ?String,
                userAuthenticationRequired: Bool,
                trustedReaderRootCertificates: ?Array<Array<UInt8>>,
                deviceAuthMethod: DeviceAuthMethod,
                uiCulture: ?String,
                logFileName: ?String,
                bleTransferMode: BleTransferMode,
                trustConfiguration!: ?TrustConfiguration = None) {
        this.serviceName = serviceName
        this.accessGroup = accessGroup
        this.userAuthenticationRequired = userAuthenticationRequired
        this.trustedReaderRootCertificates = trustedReaderRootCertificates
        this.deviceAuthMethod = deviceAuthMethod
        this.uiCulture = uiCulture
        this.logFileName = logFileName
        this.bleTransferMode = bleTransferMode
        this.trustConfiguration = trustConfiguration
    }

    /**
     * Reader trust anchors: LoTE/WRPAC via TrustConfiguration when present,
     * otherwise the static trustedReaderRootCertificates list.
     */
    public func readerTrustAnchorsDer(): ?Array<Array<UInt8>> {
        match (this.trustConfiguration) {
            case Some(cfg) =>
                let ders = cfg.accessTrustManager.trustAnchorsDer()
                if (ders.size == 0) {
                    return this.trustedReaderRootCertificates
                }
                Some(ders)
            case None => this.trustedReaderRootCertificates
        }
    }

    /**
     * Convenience factory with iOS-aligned defaults.
     * iOS defaults: serviceName="eudiw", userAuthenticationRequired=false,
     * deviceAuthMethod=.deviceSignature, bleTransferMode=.server
     */
    public static func defaultConfig(): EudiWalletConfiguration {
        return EudiWalletConfiguration(
            EudiWalletConfiguration.DEFAULT_SERVICE_NAME,
            None,
            false,
            None,
            DeviceAuthMethod.DeviceSignature,
            None,
            None,
            BleTransferMode.Server
        )
    }
}
