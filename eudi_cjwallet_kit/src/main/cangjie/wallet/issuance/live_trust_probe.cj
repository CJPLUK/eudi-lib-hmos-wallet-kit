package ohos_app_cangjie_eudi_cjwallet_kit.wallet.issuance

import kit.PerformanceAnalysisKit.Hilog
import ohos_app_cangjie_eudi_cjetsi_1196x2.etsi_trust.TrustConfiguration
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.WalletError
import ohos_app_cangjie_eudi_cjjose.jose.EcPublicKey
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.CoreCryptoProvider

let probeIssuerUrl: String = "https://probe.issuer.test"
let probeKid: String = "probe-jwks"

/**
 * Drive the iOS no-x5c path on device: sign an SD-JWT with kid and no x5c,
 * inject jwt-vc-issuer JWKS, then `applySdJwtIssuerTrustFetched`.
 * DEMO issuers always send x5c and do not host jwt-vc-issuer; this is the
 * reachable substitute without a special credential.
 */
public func probeSdJwtJwksPath(cfg: TrustConfiguration): Unit {
    let crypto = CoreCryptoProvider()
    let priv = crypto.ecdsa.generate()
    let pub = crypto.ecdsa.publicKeyOf(priv)
    let ec = EcPublicKey.fromHuksUncompressed(pub.getRawBytes())
    let header = "{\"alg\":\"ES256\",\"kid\":\"${probeKid}\"}"
    let payload = "{\"iss\":\"${probeIssuerUrl}\",\"_sd_alg\":\"sha-256\"}".toArray()
    let compact = crypto.jws.signEs256(header, payload, priv) + "~"
    let jwkJson = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"${probeKid}\",\"x\":\"${ec.x}\",\"y\":\"${ec.y}\"}"
    let metadata = "{\"issuer\":\"${probeIssuerUrl}\",\"jwks\":{\"keys\":[${jwkJson}]}}"
    applySdJwtIssuerTrustFetched(
        cfg,
        compact,
        probeIssuerUrl,
        "eu.europa.ec.eudi.probe.sd_jwt",
        { url: String =>
            if (url.contains("jwt-vc-issuer")) {
                metadata
            } else {
                throw WalletError.withDescription("unexpected JWKS fetch ${url}")
            }
        }
    )
    Hilog.info(0, "OpenId4VciService", "SDJWT-JWKS probe ok kid=${probeKid} issuer=${probeIssuerUrl}")
}
