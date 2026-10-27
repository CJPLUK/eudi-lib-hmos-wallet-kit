package ohos_app_cangjie_eudi_cjwallet_kit.wallet.issuance

import std.unittest.*
import std.unittest.testmacro.*
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.WalletError
import eudi_lib_core_crypto.Base64Url

func fixedMetaFetch(url: String): String {
    "{\"issuer\":\"https://issuer.example.com\",\"jwks\":{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"k1\",\"x\":\"AA\",\"y\":\"BB\"}]}}"
}

@Test
class SdJwtJwtVcIssuerJwksTests {
    @TestCase
    func wellKnownUrlPrependsPath(): Unit {
        @Expect(
            jwtVcIssuerMetadataUrl("https://issuer.example.com"),
            "https://issuer.example.com/.well-known/jwt-vc-issuer"
        )
        @Expect(
            jwtVcIssuerMetadataUrl("https://issuer.example.com/tenant"),
            "https://issuer.example.com/.well-known/jwt-vc-issuer/tenant"
        )
        @Expect(
            jwtVcIssuerMetadataUrl("https://issuer.example.com/"),
            "https://issuer.example.com/.well-known/jwt-vc-issuer"
        )
    }

    @TestCase
    func inlineJwksMatchesKid(): Unit {
        let json = "{\"issuer\":\"https://issuer.example.com\",\"jwks\":{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"key-1\",\"x\":\"abc\",\"y\":\"def\"}]}}"
        let jwks = parseJwtVcIssuerJwksJson(json, "https://issuer.example.com")
        match (findJwkObjectByKid(jwks, "key-1")) {
            case Some(_) => @Expect(true, true)
            case None => @Expect(false, true)
        }
        match (findJwkObjectByKid(jwks, "missing")) {
            case None => @Expect(true, true)
            case Some(_) => @Expect(false, true)
        }
    }

    @TestCase
    func xorRejectsBothJwksAndUri(): Unit {
        let json = "{\"issuer\":\"https://issuer.example.com\",\"jwks\":{\"keys\":[]},\"jwks_uri\":\"https://example.com/jwks\"}"
        var threw = false
        try {
            parseJwtVcIssuerJwksJson(json, "https://issuer.example.com")
        } catch (e: WalletError) {
            threw = true
        }
        @Expect(threw, true)
    }

    @TestCase
    func issuerMismatchIsRejected(): Unit {
        let json = "{\"issuer\":\"https://other.example.com\",\"jwks\":{\"keys\":[]}}"
        var threw = false
        try {
            parseJwtVcIssuerJwksJson(json, "https://issuer.example.com")
        } catch (e: WalletError) {
            threw = true
        }
        @Expect(threw, true)
    }

    @TestCase
    func jwksUriIsReturnedAsFetchToken(): Unit {
        let json = "{\"issuer\":\"https://issuer.example.com\",\"jwks_uri\":\"https://issuer.example.com/jwks\"}"
        let parsed = parseJwtVcIssuerJwksJson(json, "https://issuer.example.com")
        @Expect(parsed, "URI:https://issuer.example.com/jwks")
    }

    @TestCase
    func headerWithoutKidOrX5c(): Unit {
        let header = Base64Url.encode("{\"alg\":\"ES256\"}".toArray())
        let payload = Base64Url.encode("{}".toArray())
        let compact = header + "." + payload + ".sig"
        match (extractSdJwtX5cDer(compact)) {
            case None => @Expect(true, true)
            case Some(_) => @Expect(false, true)
        }
        match (extractSdJwtHeaderString(compact, "kid")) {
            case None => @Expect(true, true)
            case Some(_) => @Expect(false, true)
        }
    }

    @TestCase
    func resolveJwksByKidFromInlineMetadata(): Unit {
        let jwks = resolveJwtVcIssuerJwksJson("https://issuer.example.com", fixedMetaFetch)
        match (findJwkObjectByKid(jwks, "k1")) {
            case Some(_) => @Expect(true, true)
            case None => @Expect(false, true)
        }
    }
}
