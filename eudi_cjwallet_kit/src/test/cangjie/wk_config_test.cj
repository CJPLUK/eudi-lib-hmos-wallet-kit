/*
 * wk_config_test.cj
 *
 * Unit tests for wallet-kit config.cj pure logic:
 *   - ClientIdScheme variants
 *   - OpenId4VciConfiguration.withIssuerURL + defaults + fields
 *   - KeyAttestationConfiguration via a test WalletAttestationsProvider impl
 *   - OpenId4VpConfiguration default schemes content
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.models

import std.unittest.*
import std.unittest.testmacro.*

import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.config.AuthorizeIssuanceConfig
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.config.IssuerMetadataPolicy

// Symbols under test (wallet.models) — explicit import for entry package.
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.{
    WalletAttestationsProvider,
    KeyAttestationConfiguration,
    ClientIdScheme,
    OpenId4VciConfiguration,
    OpenId4VpConfiguration
}

// A minimal test implementation of the WalletAttestationsProvider interface.
class TestAttestationsProvider <: WalletAttestationsProvider {
    public func getWalletAttestation(signingKeyId: String): String {
        return "wallet-attestation-for:" + signingKeyId
    }
    public func getKeysAttestation(publicKeyBytes: Array<Array<UInt8>>, nonce: ?String): String {
        let count = publicKeyBytes.size
        let n: String = match (nonce) {
            case Some(v) => v
            case None => "no-nonce"
        }
        return "keys-attestation:count=" + count.toString() + ":nonce=" + n
    }
}

// ===========================================================================
// ClientIdScheme
// ===========================================================================
@Test
class WkConfigClientIdSchemeUT {

    @TestCase
    func preregisteredCarriesEntries(): Unit {
        let entries: Array<(String, String, String)> = [("client-1", "Acme", "https://api.acme")]
        let scheme = ClientIdScheme.Preregistered(entries)
        match (scheme) {
            case ClientIdScheme.Preregistered(list) =>
                @Expect(list.size, 1)
                let (cid, name, uri) = list[0]
                @Expect(cid, "client-1")
                @Expect(name, "Acme")
                @Expect(uri, "https://api.acme")
            case _ => @Expect("wrong-variant", "Preregistered")
        }
    }

    @TestCase
    func defaultSchemesAreX509AndRedirect(): Unit {
        let schemes = OpenId4VpConfiguration.defaultSchemes()
        @Expect(schemes.size, 3)
        // Order per source: X509SanDns, X509Hash, RedirectUri
        var sawSanDns = false
        var sawHash = false
        var sawRedirect = false
        var i: Int64 = 0
        while (i < schemes.size) {
            match (schemes[i]) {
                case ClientIdScheme.X509SanDns => sawSanDns = true
                case ClientIdScheme.X509Hash => sawHash = true
                case ClientIdScheme.RedirectUri => sawRedirect = true
                case _ => ()
            }
            i++
        }
        @Expect(sawSanDns, true)
        @Expect(sawHash, true)
        @Expect(sawRedirect, true)
    }
}

// ===========================================================================
// OpenId4VciConfiguration
// ===========================================================================
@Test
class WkConfigOpenId4VciConfigUT {

    @TestCase
    func defaultRedirectAndClientIdConstants(): Unit {
        @Expect(OpenId4VciConfiguration.DEFAULT_REDIRECT_URI, "eudi-openid4ci://authorize")
        @Expect(OpenId4VciConfiguration.DEFAULT_CLIENT_ID, "eudiw-abca")
    }

    @TestCase
    func withIssuerUrlAppliesIosDefaults(): Unit {
        let cfg = OpenId4VciConfiguration.withIssuerURL(Some("https://issuer.example"))
        @Expect(cfg.clientId, "eudiw-abca")
        @Expect(cfg.authFlowRedirectionURI, "eudi-openid4ci://authorize")
        @Expect(cfg.requirePAR, true)
        @Expect(cfg.requireDpop, true)
        @Expect(cfg.userAuthenticationRequired, false)
        @Expect(cfg.keyAttestationsConfig.isNone(), true)
        @Expect(cfg.dpopKeyOptions.isNone(), true)
        match (cfg.credentialIssuerURL) {
            case Some(u) => @Expect(u, "https://issuer.example")
            case None => @Expect("none", "some")
        }
    }

    @TestCase
    func withIssuerUrlNoneIsAccepted(): Unit {
        let cfg = OpenId4VciConfiguration.withIssuerURL(None)
        @Expect(cfg.credentialIssuerURL.isNone(), true)
    }

    @TestCase
    func withIssuerUrlMetadataPolicyAndIssuanceConfig(): Unit {
        let cfg = OpenId4VciConfiguration.withIssuerURL(Some("https://x"))
        match (cfg.issuerMetadataPolicy) {
            case IssuerMetadataPolicy.IgnoreSigned => @Expect(true, true)
            case _ => @Expect("wrong-policy", "IgnoreSigned")
        }
        match (cfg.authorizeIssuanceConfig) {
            case AuthorizeIssuanceConfig.FavorScopes => @Expect(true, true)
            case _ => @Expect("wrong-config", "FavorScopes")
        }
    }
}

// ===========================================================================
// KeyAttestationConfiguration + WalletAttestationsProvider
// ===========================================================================
@Test
class WkConfigKeyAttestationUT {

    @TestCase
    func providerProducesAttestations(): Unit {
        let provider = TestAttestationsProvider()
        @Expect(provider.getWalletAttestation("key-1"), "wallet-attestation-for:key-1")
        let keys: Array<Array<UInt8>> = [[0x01u8], [0x02u8]]
        @Expect(provider.getKeysAttestation(keys, Some("nonce-9")), "keys-attestation:count=2:nonce=nonce-9")
        @Expect(provider.getKeysAttestation(keys, None), "keys-attestation:count=2:nonce=no-nonce")
    }

    @TestCase
    func keyAttestationConfigHoldsProvider(): Unit {
        let provider = TestAttestationsProvider()
        let cfg = KeyAttestationConfiguration(provider, None, Some(300.0))
        @Expect(cfg.popKeyOptions.isNone(), true)
        match (cfg.popKeyDurationSeconds) {
            case Some(d) => @Expect(d, 300.0)
            case None => @Expect("none", "some")
        }
        // provider must be the same one we passed
        @Expect(cfg.walletAttestationsProvider.getWalletAttestation("z"), "wallet-attestation-for:z")
    }
}
