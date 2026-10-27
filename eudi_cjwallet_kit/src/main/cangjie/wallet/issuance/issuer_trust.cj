package ohos_app_cangjie_eudi_cjwallet_kit.wallet.issuance

import kit.PerformanceAnalysisKit.Hilog
import std.collection.ArrayList
import stdx.encoding.base64.*
import stdx.encoding.json.{JsonObject, JsonString, JsonArray, JsonValue}
import eudi_lib_core_crypto.Base64Url
import ohos_app_cangjie_eudi_cjetsi_1196x2.etsi_trust.{
    TrustConfiguration, TrustPolicyDecision, decideTrustPolicy
}
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.{WalletError, WalletErrorCode}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.network.HttpFetcher
import ohos_app_cangjie_eudi_cjjose.jose.EcPublicKey
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.ECDSAPublicKey as SeamEcdsaPublicKey
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.seam.CoreCryptoProvider
import ohos_app_cangjie_eudi_cjsdjwt.sdjwt.verifier.SdJwtVerifier

/**
 * iOS OpenId4VciService issuer-chain check: set issuerTrustManager.docType,
 * validateCertTrustPath, then Warning logs / Enforce throws `.trustError`.
 */
func applyIssuerChainTrust(
    cfg: TrustConfiguration,
    docType: String,
    chain: Array<Array<UInt8>>,
    untrustedMessage: String
): Unit {
    cfg.issuerTrustManager.docType = Some(docType)
    let (trusted, reason) = if (chain.size == 0) {
        (false, Some("No issuer certificates provided in x5chain"))
    } else {
        cfg.issuerTrustManager.validateCertTrustPath(chain)
    }
    match (decideTrustPolicy(trusted, reason, cfg.policyFor(docType), untrustedMessage)) {
        case TrustPolicyDecision.Pass => ()
        case TrustPolicyDecision.Warn(msg) =>
            Hilog.warn(0, "OpenId4VciService", msg)
        case TrustPolicyDecision.Fail(msg) =>
            throw WalletError.withCode(msg, WalletErrorCode.TrustError)
    }
}

/**
 * Compact SD-JWT / JWT `x5c` header → DER chain. None if the header has no x5c.
 * Throws when x5c is present but an entry is not valid standard base64 (iOS).
 */
func extractSdJwtX5cDer(serialized: String): ?Array<Array<UInt8>> {
    let compact = sdJwtCompactIssuance(serialized)
    let parts = compact.split(".")
    if (parts.size < 1) {
        return None
    }
    let headerBytes = Base64Url.decode(parts[0])
    let headerStr = String.fromUtf8(headerBytes)
    var parsed: JsonValue
    try {
        parsed = JsonValue.fromStr(headerStr)
    } catch (_: Exception) {
        return None
    }
    match (parsed) {
        case obj: JsonObject =>
            match (obj.get("x5c")) {
                case Some(arr: JsonArray) =>
                    let items = arr.getItems()
                    if (items.size == 0) {
                        return None
                    }
                    let ders = ArrayList<Array<UInt8>>()
                    for (item in items) {
                        match (item) {
                            case s: JsonString =>
                                match (fromBase64String(s.getValue())) {
                                    case Some(der) => ders.add(der)
                                    case None =>
                                        throw WalletError.withDescription(
                                            "Invalid base64 encoding in SD-JWT x5c certificate chain"
                                        )
                                }
                            case _ =>
                                throw WalletError.withDescription(
                                    "Invalid base64 encoding in SD-JWT x5c certificate chain"
                                )
                        }
                    }
                    if (ders.size != items.size) {
                        throw WalletError.withDescription(
                            "Invalid base64 encoding in SD-JWT x5c certificate chain"
                        )
                    }
                    Some(ders.toArray())
                case _ => None
            }
        case _ => None
    }
}

func sdJwtCompactIssuance(serialized: String): String {
    let parts = serialized.split("~")
    if (parts.size == 0) {
        return serialized
    }
    parts[0]
}

func extractSdJwtHeaderString(serialized: String, key: String): ?String {
    let compact = sdJwtCompactIssuance(serialized)
    let parts = compact.split(".")
    if (parts.size < 1) {
        return None
    }
    let headerBytes = Base64Url.decode(parts[0])
    let headerStr = String.fromUtf8(headerBytes)
    var parsed: JsonValue
    try {
        parsed = JsonValue.fromStr(headerStr)
    } catch (_: Exception) {
        return None
    }
    match (parsed) {
        case obj: JsonObject => jsonObjectString(obj, key)
        case _ => None
    }
}

func jsonObjectString(obj: JsonObject, key: String): ?String {
    match (obj.get(key)) {
        case Some(s: JsonString) => Some(s.getValue())
        case _ => None
    }
}

func stripTrailingSlash(url: String): String {
    if (url.endsWith("/") && url.size > 1) {
        let bytes = url.toArray()
        return String.fromUtf8(bytes[0..(bytes.size - 1)])
    }
    url
}

/**
 * iOS `SdJwtVcIssuerMetaDataFetcher.issuerMetadataUrl`:
 * prepend `/.well-known/jwt-vc-issuer` to the issuer path.
 */
func jwtVcIssuerMetadataUrl(issuerUrl: String): String {
    let wellKnownPath = "/.well-known/jwt-vc-issuer"
    let base = stripTrailingSlash(issuerUrl)
    let schemeEnd = jwtVcFindSchemeEnd(base)
    let pathStart = jwtVcFindPathStart(base, schemeEnd)
    let bBase = base.toArray()
    if (pathStart >= bBase.size) {
        return base + wellKnownPath
    }
    let pathPart = String.fromUtf8(bBase[pathStart..bBase.size])
    if (pathPart == "" || pathPart == "/") {
        return base + wellKnownPath
    }
    let authority = String.fromUtf8(bBase[0..pathStart])
    authority + wellKnownPath + pathPart
}

func jwtVcFindSchemeEnd(url: String): Int64 {
    let bytes = url.toArray()
    var i: Int64 = 0
    while (i < bytes.size) {
        if (bytes[i] == 58u8) {
            if (i + 2 < bytes.size && bytes[i + 1] == 47u8 && bytes[i + 2] == 47u8) {
                return i + 3
            }
        }
        i += 1
    }
    0
}

func jwtVcFindPathStart(url: String, afterScheme: Int64): Int64 {
    let bytes = url.toArray()
    var i = afterScheme
    while (i < bytes.size) {
        if (bytes[i] == 47u8) {
            return i
        }
        i += 1
    }
    bytes.size
}

/**
 * Parse `/.well-known/jwt-vc-issuer` JSON. Returns the JWKS object JSON
 * (`{"keys":[...]}`). Throws on issuer mismatch or xor(jwks, jwks_uri).
 */
func parseJwtVcIssuerJwksJson(metadataJson: String, expectedIssuer: String): String {
    var parsed: JsonValue
    try {
        parsed = JsonValue.fromStr(metadataJson)
    } catch (_: Exception) {
        throw WalletError.withDescription("Issuer metadata must contain exactly one of jwks or jwks_uri")
    }
    let obj = match (parsed) {
        case o: JsonObject => o
        case _ => throw WalletError.withDescription("Issuer metadata must contain exactly one of jwks or jwks_uri")
    }
    let issuer = match (jsonObjectString(obj, "issuer")) {
        case Some(s) => s
        case None => throw WalletError.withDescription("Issuer mismatch in metadata")
    }
    if (stripTrailingSlash(issuer) != stripTrailingSlash(expectedIssuer)) {
        throw WalletError.withDescription("Issuer mismatch in metadata")
    }
    let jwksVal = obj.get("jwks")
    let jwksUriVal = obj.get("jwks_uri")
    let hasJwks = match (jwksVal) {
        case Some(_: JsonObject) => true
        case _ => false
    }
    let jwksUri: ?String = match (jwksUriVal) {
        case Some(s: JsonString) => Some(s.getValue())
        case _ => None
    }
    let hasUri = match (jwksUri) {
        case Some(u) => !u.isEmpty()
        case None => false
    }
    if (hasJwks == hasUri) {
        throw WalletError.withDescription("Issuer metadata must contain exactly one of jwks or jwks_uri")
    }
    if (hasJwks) {
        return metadataJson
    }
    match (jwksUri) {
        case Some(uri) => "URI:" + uri
        case None => throw WalletError.withDescription("Issuer metadata must contain exactly one of jwks or jwks_uri")
    }
}

func findJwkObjectByKid(jwksJson: String, kid: String): ?JsonObject {
    var parsed: JsonValue
    try {
        parsed = JsonValue.fromStr(jwksJson)
    } catch (_: Exception) {
        return None
    }
    let keysArr: JsonArray = match (parsed) {
        case obj: JsonObject =>
            match (obj.get("keys")) {
                case Some(arr: JsonArray) => arr
                case _ =>
                    match (obj.get("jwks")) {
                        case Some(jwksObj: JsonObject) =>
                            match (jwksObj.get("keys")) {
                                case Some(arr: JsonArray) => arr
                                case _ => return None
                            }
                        case _ => return None
                    }
            }
        case arr: JsonArray => arr
        case _ => return None
    }
    for (item in keysArr.getItems()) {
        match (item) {
            case keyObj: JsonObject =>
                match (jsonObjectString(keyObj, "kid")) {
                    case Some(k) where k == kid => return Some(keyObj)
                    case _ => ()
                }
            case _ => ()
        }
    }
    None
}

func jwkObjectToEcJson(obj: JsonObject): String {
    let kty = match (jsonObjectString(obj, "kty")) {
        case Some(v) => v
        case None => "EC"
    }
    let crv = match (jsonObjectString(obj, "crv")) {
        case Some(c) => c
        case None => throw WalletError.withCode(
            "Unable to resolve issuer signing key for issued SD-JWT",
            WalletErrorCode.TrustError
        )
    }
    let x = match (jsonObjectString(obj, "x")) {
        case Some(v) => v
        case None => throw WalletError.withCode(
            "Unable to resolve issuer signing key for issued SD-JWT",
            WalletErrorCode.TrustError
        )
    }
    let y = match (jsonObjectString(obj, "y")) {
        case Some(v) => v
        case None => throw WalletError.withCode(
            "Unable to resolve issuer signing key for issued SD-JWT",
            WalletErrorCode.TrustError
        )
    }
    "{\"kty\":\"${kty}\",\"crv\":\"${crv}\",\"x\":\"${x}\",\"y\":\"${y}\"}"
}

func httpGetUtf8(url: String): String {
    let bytes = HttpFetcher().fetch(url)
    String.fromUtf8(bytes)
}

func resolveJwtVcIssuerJwksJson(expectedIssuer: String, fetchJson: (String) -> String): String {
    let metaUrl = jwtVcIssuerMetadataUrl(expectedIssuer)
    let metadataJson = fetchJson(metaUrl)
    let parsed = parseJwtVcIssuerJwksJson(metadataJson, expectedIssuer)
    if (parsed.startsWith("URI:")) {
        let bytes = parsed.toArray()
        let uri = String.fromUtf8(bytes[4..bytes.size])
        return fetchJson(uri)
    }
    parsed
}

/**
 * iOS `validateIssuedSdJwt`: x5c → issuerTrustManager; else jwt-vc-issuer JWKS by kid
 * then verifyIssuance.
 */
func applySdJwtIssuerTrust(
    cfg: TrustConfiguration,
    serialized: String,
    expectedIssuerUrl: String,
    docType: String
): Unit {
    applySdJwtIssuerTrustFetched(cfg, serialized, expectedIssuerUrl, docType, httpGetUtf8)
}

func applySdJwtIssuerTrustFetched(
    cfg: TrustConfiguration,
    serialized: String,
    expectedIssuerUrl: String,
    docType: String,
    fetchJson: (String) -> String
): Unit {
    match (extractSdJwtX5cDer(serialized)) {
        case Some(chain) =>
            applyIssuerChainTrust(
                cfg,
                docType,
                chain,
                "Issued SD-JWT issuer certificate chain is not trusted"
            )
            return
        case None => ()
    }
    let kid = match (extractSdJwtHeaderString(serialized, "kid")) {
        case Some(k) => k
        case None =>
            throw WalletError.withDescription(
                "Issued SD-JWT is missing both x5c chain and key identifier"
            )
    }
    var jwksJson: String
    try {
        jwksJson = resolveJwtVcIssuerJwksJson(expectedIssuerUrl, fetchJson)
    } catch (e: WalletError) {
        throw e
    } catch (e: Exception) {
        throw WalletError.withCode(
            "Unable to resolve issuer signing key for issued SD-JWT",
            WalletErrorCode.TrustError
        )
    }
    let jwkObj = match (findJwkObjectByKid(jwksJson, kid)) {
        case Some(o) => o
        case None =>
            throw WalletError.withCode(
                "Unable to resolve issuer signing key for issued SD-JWT",
                WalletErrorCode.TrustError
            )
    }
    let ec = EcPublicKey.fromJson(jwkObjectToEcJson(jwkObj))
    let der = ec.toHuksSpki()
    let pub = SeamEcdsaPublicKey(rawBytes: der)
    let crypto = CoreCryptoProvider()
    let verifier = SdJwtVerifier(jws: crypto.jws, b64: crypto.base64Url, digest: crypto.digest)
    let result = verifier.verifyIssuance(serialized, pub)
    if (!result.isOk()) {
        let msg = match (result.err) {
            case Some(err) => err.message
            case None => "Unable to resolve issuer signing key for issued SD-JWT"
        }
        throw WalletError.withCode(msg, WalletErrorCode.TrustError)
    }
    Hilog.info(0, "OpenId4VciService", "SDJWT-JWKS kid=${kid} issuer=${expectedIssuerUrl}")
}
