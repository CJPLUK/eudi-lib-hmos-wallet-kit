/*
 * wk_facade_network_test.cj
 *
 * REAL-NETWORK integration tests for the wallet-kit EudiWallet facade.
 *
 * Unlike the offline suites (wk_facade_test.cj etc.), these cases drive the
 * facade's real network path:
 *
 *   EudiWallet(EudiWalletConfiguration)
 *     -> addOpenId4VciConfiguration(name, OpenId4VciConfiguration.withIssuerURL(...))
 *     -> getIssuerMetadata(name)
 *        -> OpenId4VciService.getIssuerMetadata()
 *           -> CredentialIssuerMetadataResolver().resolve(...)
 *              -> HttpFetcher (TLS, openid4vp-vci third_party)
 *              -> GET https://issuer.eudiw.dev/.well-known/openid-credential-issuer
 *
 * Requires: device with network access to issuer.eudiw.dev and
 * ohos.permission.INTERNET (already granted in entry module.json5).
 *
 * Robustness: each network case retries up to 3 times to absorb transient
 * connectivity jitter; only a clean parse + field assertion counts as success.
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.facade

import std.unittest.*
import std.unittest.testmacro.*

import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.{
    EudiWalletConfiguration,
    OpenId4VciConfiguration
}
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.facade.EudiWallet

// The metadata object returned (typed Any at the facade boundary) is a
// CredentialIssuerMetadata from openid4vp-vci.
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.issuer.CredentialIssuerMetadata

// ---------------------------------------------------------------------------
// Constants — real reachable EUDI reference issuer.
// ---------------------------------------------------------------------------

let EUDIW_ISSUER_URL = "https://issuer.eudiw.dev"
let EUDIW_ISSUER_NAME = "eudiw-dev"
// A credential configuration id known to be advertised by issuer.eudiw.dev.
let EXPECTED_CONFIG_ID = "eu.europa.ec.eudi.cor_mdoc"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Build a wallet assembled exactly like production but with the in-memory
// storage fallback (no real RDB/HUKS needed), and register the eudiw.dev VCI
// configuration so getIssuerMetadata routes to the live issuer.
func buildNetworkWallet(): EudiWallet {
    let cfg = EudiWalletConfiguration.defaultConfig()
    let wallet = EudiWallet(cfg)
    let vci = OpenId4VciConfiguration.withIssuerURL(EUDIW_ISSUER_URL)
    wallet.addOpenId4VciConfiguration(EUDIW_ISSUER_NAME, vci)
    return wallet
}

// Drive the facade network path with retry; cast the Any result back to the
// concrete metadata type. Throws the last error if all attempts fail.
func fetchMetadataWithRetry(wallet: EudiWallet, issuerName: String): CredentialIssuerMetadata {
    var attempt = 0
    var lastErr: ?Exception = None
    while (attempt < 3) {
        attempt++
        try {
            let any = wallet.getIssuerMetadata(issuerName)
            match (any as CredentialIssuerMetadata) {
                case Some(m) => return m
                case None => throw Exception("getIssuerMetadata: result not a CredentialIssuerMetadata")
            }
        } catch (e: Exception) {
            lastErr = e
        }
    }
    match (lastErr) {
        case Some(e) => throw e
        case None => throw Exception("getIssuerMetadata: no result after 3 attempts")
    }
}

// ---------------------------------------------------------------------------
// Test class: real network via EudiWallet facade
// ---------------------------------------------------------------------------

@Test
class WkFacadeNetworkUT {

    // Facade -> resolver -> HTTPS GET; assert the issuer identity round-trips.
    @TestCase
    func getIssuerMetadataReturnsCorrectIssuerIdentifier(): Unit {
        let wallet = buildNetworkWallet()
        let meta = fetchMetadataWithRetry(wallet, EUDIW_ISSUER_NAME)
        // credential_issuer in the live document must echo the issuer URL.
        @Expect(meta.credentialIssuerIdentifier.absoluteString(), EUDIW_ISSUER_URL)
    }

    // Live document advertises batch_size = 100; assert it parses through.
    @TestCase
    func getIssuerMetadataBatchSizeIs100(): Unit {
        let wallet = buildNetworkWallet()
        let meta = fetchMetadataWithRetry(wallet, EUDIW_ISSUER_NAME)
        // batch_credential_issuance must be present on eudiw.dev with batchSize 100.
        var batchSize: Int64 = -1
        match (meta.batchCredentialIssuance) {
            case Some(b) => batchSize = b.batchSize
            case None => ()
        }
        @Expect(batchSize, 100)
    }

    // The supported credential configurations must include the known mdoc id.
    @TestCase
    func getIssuerMetadataAdvertisesExpectedConfig(): Unit {
        let wallet = buildNetworkWallet()
        let meta = fetchMetadataWithRetry(wallet, EUDIW_ISSUER_NAME)
        @Expect(meta.credentialConfigurationsRaw.contains(EXPECTED_CONFIG_ID), true)
    }

    // Resolution must yield a non-empty HTTPS credential endpoint within the
    // eudiw.dev domain. (Live metadata points it at the dedicated backend host
    // https://backend.issuer.eudiw.dev/credential, not the issuer host itself.)
    @TestCase
    func getIssuerMetadataHasCredentialEndpointOnEudiwDomain(): Unit {
        let wallet = buildNetworkWallet()
        let meta = fetchMetadataWithRetry(wallet, EUDIW_ISSUER_NAME)
        let ep = meta.credentialEndpoint.absoluteString()
        @Expect(ep.isEmpty(), false)
        @Expect(ep.startsWith("https://"), true)
        @Expect(ep.contains("issuer.eudiw.dev/credential"), true)
    }

    // Lookup by raw issuer URL (not the registered label) must also route to
    // the same live service via the facade's URL-fallback resolution.
    @TestCase
    func getIssuerMetadataByUrlLookup(): Unit {
        let wallet = buildNetworkWallet()
        let meta = fetchMetadataWithRetry(wallet, EUDIW_ISSUER_URL)
        @Expect(meta.credentialIssuerIdentifier.absoluteString(), EUDIW_ISSUER_URL)
    }
}
