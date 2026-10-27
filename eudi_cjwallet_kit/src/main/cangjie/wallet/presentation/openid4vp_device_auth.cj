/*
 * openid4vp_device_auth.cj
 *
 * EUDI Wallet Kit — holder key-binding proofs for OpenID4VP presentations.
 *
 * Two proof kinds, both signed with the document's SecureArea key (the key
 * created at issuance whose public part the issuer bound into the credential):
 *
 *   1. mdoc DeviceAuth: OpenID4VPHandover SessionTranscript + COSE_Sign1 over
 *      DeviceAuthenticationBytes, assembled into a DeviceResponse.
 *      Mirrors iOS Openid4VpUtils.generateOpenId4VpHandover +
 *      MdocHelpers.getDeviceResponseToSend(dauthMethod: .deviceSignature).
 *
 *   2. SD-JWT KB-JWT: {aud, nonce, iat, sd_hash} signed ES256, appended after
 *      the trailing "~" of the presented SD-JWT.
 *      Mirrors iOS OpenId4VpUtils.getSdJwtPresentation.
 *
 * Handover layout (OpenID4VP 1.0 §Handover; same bytes as iOS):
 *   HandoverInfo      = [clientId, nonce, jwkThumbprint | null, responseUri]
 *   OpenID4VPHandover = ["OpenID4VPHandover", bstr sha256(cbor(HandoverInfo))]
 *   SessionTranscript = [null, null, OpenID4VPHandover]
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.presentation

import kit.PerformanceAnalysisKit.Hilog

import std.collection.ArrayList
import std.time.DateTime
import stdx.encoding.json.*

import stdx.crypto.keys.ECDSAPrivateKey
import stdx.crypto.common.DerBlob
import eudi_lib_core_crypto.Digest
import eudi_lib_core_crypto.EcdsaP256
import eudi_lib_core_crypto.Base64Url

import ohos_app_cangjie_eudi_cjcbor.cbor.CborValue
import ohos_app_cangjie_eudi_cjcbor.cbor.CborTag
import ohos_app_cangjie_eudi_cjcbor.cbor.decodeCbor

import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.core.CoseSign1
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.core.CoseHeader
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.response.IssuerSigned
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.response.DeviceResponse
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.response.Document as MdocDocument
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.response.DeviceSigned
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.response.DeviceAuth
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.response.DeviceNameSpaces
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.response.DeviceSignedItems
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.SecureAreaRegistry
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.SecureArea
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.SigningAlgorithm
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.DocKeyInfo

import ohos_app_cangjie_eudi_cjmdoc_security.security.session.SessionTranscript
import ohos_app_cangjie_eudi_cjmdoc_security.security.device_auth.DeviceAuthentication

import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.WalletError

/**
 * Holder key-binding proof builders for OpenID4VP (module-internal).
 */
class Oid4VpDeviceAuth {

    /**
     * RFC 7638 JWK SHA-256 thumbprint of the verifier's encryption key, taken
     * from client_metadata.jwks (first key with use == "enc", else first EC
     * key). None when no usable key is present (unencrypted response).
     */
    static func encryptionJwkThumbprint(jwksJson: ?String): ?Array<UInt8> {
        let raw = match (jwksJson) {
            case Some(s) => s
            case None => return None
        }
        try {
            let parsed = JsonValue.fromStr(raw)
            let obj = match (parsed) {
                case o: JsonObject => o
                case _ => return None
            }
            let keys = match (obj.get("keys")) {
                case Some(arr: JsonArray) => arr.getItems()
                case _ => return None
            }
            var chosen: ?JsonObject = None
            for (item in keys) {
                match (item) {
                    case k: JsonObject =>
                        let isEnc = match (k.get("use")) {
                            case Some(u: JsonString) => u.getValue() == "enc"
                            case _ => false
                        }
                        if (isEnc) {
                            chosen = Some(k)
                            break
                        }
                        if (chosen.isNone()) { chosen = Some(k) }
                    case _ => ()
                }
            }
            let key = match (chosen) {
                case Some(k) => k
                case None => return None
            }
            func strField(name: String): ?String {
                match (key.get(name)) {
                    case Some(s: JsonString) => Some(s.getValue())
                    case _ => None
                }
            }
            let crv = match (strField("crv")) { case Some(v) => v; case None => return None }
            let kty = match (strField("kty")) { case Some(v) => v; case None => return None }
            let x = match (strField("x")) { case Some(v) => v; case None => return None }
            let y = match (strField("y")) { case Some(v) => v; case None => return None }
            // RFC 7638: required members only, lexicographic order, no spaces.
            let canonical = "{\"crv\":\"" + crv + "\",\"kty\":\"" + kty +
                "\",\"x\":\"" + x + "\",\"y\":\"" + y + "\"}"
            return Some(Digest.sha256(canonical.toArray()))
        } catch (_: Exception) {
            return None
        }
    }

    /**
     * OpenID4VP SessionTranscript = [null, null, OpenID4VPHandover].
     * Byte-identical to iOS Openid4VpUtils.generateOpenId4VpHandover.
     */
    static func buildSessionTranscript(
        clientId: String,
        responseUri: String,
        nonce: String,
        jwkThumbprint: ?Array<UInt8>
    ): SessionTranscript {
        let info = ArrayList<CborValue>()
        info.add(CborValue.TextStringVal(clientId))
        info.add(CborValue.TextStringVal(nonce))
        match (jwkThumbprint) {
            case Some(tp) => info.add(CborValue.ByteStringVal(tp))
            case None => info.add(CborValue.NullVal)
        }
        info.add(CborValue.TextStringVal(responseUri))
        let infoHash = Digest.sha256(CborValue.ArrayVal(info).encode())

        let handover = ArrayList<CborValue>()
        handover.add(CborValue.TextStringVal("OpenID4VPHandover"))
        handover.add(CborValue.ByteStringVal(infoHash))
        return SessionTranscript(None, None, CborValue.ArrayVal(handover).encode())
    }

    /**
     * Assemble a DeviceResponse for one mdoc credential with a deviceSignature
     * DeviceAuth over the OpenID4VP SessionTranscript.
     *
     * @param issuerSignedBytes raw IssuerSigned CBOR (Document.data as stored)
     * @param docType           ISO doctype of the credential
     * @param docId             storage id — the SecureArea key batch id
     * @param transcript        OpenID4VP session transcript
     * @return CBOR bytes of the complete DeviceResponse
     */
    static func buildDeviceResponse(
        issuerSignedBytes: Array<UInt8>,
        docType: String,
        docId: String,
        docKeyInfo: ?Array<UInt8>,
        transcript: SessionTranscript
    ): Array<UInt8> {
        // Stored credential data is either raw IssuerSigned CBOR or a
        // base64url string of it (issuance stores the encoded form) — same
        // dual-path decode as logic-core's mdocValidity.
        let issuerSignedRaw = if (presLooksLikeBase64UrlTextBytes(issuerSignedBytes)) {
            Base64Url.decode(String.fromUtf8(issuerSignedBytes))
        } else { issuerSignedBytes }
        let issuerSigned = IssuerSigned.fromCbor(decodeCbor(issuerSignedRaw))

        // DeviceNameSpaces = {} (no device-signed data elements) — its encoded
        // form feeds DeviceAuthentication and travels tag-24 in DeviceSigned.
        let emptyNsBytes = CborValue.MapVal(ArrayList<(CborValue, CborValue)>()).encode()

        let devAuthPayload = DeviceAuthentication(transcript, docType, emptyNsBytes).toTaggedBytes()

        // COSE_Sign1 (detached payload): protected {1: -7} (ES256), signature by
        // the document's SecureArea key (index 0 of the issuance batch).
        let protected_ = CoseHeader.build(-7, true, None)
        let phBytes = match (protected_.rawHeaderBytes) {
            case Some(b) => b
            case None => throw WalletError.withDescription("DeviceAuth: protected header missing raw bytes")
        }
        let sigStructure = ArrayList<CborValue>()
        sigStructure.add(CborValue.TextStringVal("Signature1"))
        sigStructure.add(CborValue.ByteStringVal(phBytes))
        sigStructure.add(CborValue.ByteStringVal(Array<UInt8>()))
        sigStructure.add(CborValue.ByteStringVal(devAuthPayload))
        let signingInput = CborValue.ArrayVal(sigStructure).encode()

        // Sign with the SecureArea batch key the issuer bound into the
        // credential. Older documents that still carry proofKeyDers keep
        // using that software key until they are reissued.
        var signature = Array<UInt8>()
        match (holderProofKey(docKeyInfo)) {
            case Some(priv) =>
                Hilog.info(0, "VPFLOW", "DeviceAuth signing with persisted proof key")
                signature = EcdsaP256.sign(priv, signingInput)
            case None =>
                let secureArea = SecureAreaRegistry.shared.get(None)
                let keyIndex = matchDeviceKeyIndex(secureArea, docId, issuerSigned)
                Hilog.info(0, "VPFLOW", "DeviceAuth signing with SecureArea keyIndex=" + keyIndex.toString())
                signature = secureArea.signature(docId, keyIndex, SigningAlgorithm.ES256, signingInput, None)
        }
        Hilog.info(0, "VPFLOW", "DeviceAuth signed docId=" + docId + " sigLen=" + signature.size.toString())

        let coseSign1 = CoseSign1(protected_, None, None, signature)
        // DeviceAuth embeds an untagged COSE_Sign1 array, matching the iOS
        // wallet and ISO 18013-5 DeviceSignature wire structure.
        let deviceAuth = DeviceAuth(true, coseSign1.toCbor())
        let deviceSigned = DeviceSigned(
            DeviceNameSpaces(ArrayList<(String, DeviceSignedItems)>()),
            deviceAuth
        )

        let docs = ArrayList<MdocDocument>()
        docs.add(MdocDocument(docType, issuerSigned, deviceSigned, None))
        return DeviceResponse(DeviceResponse.DEFAULT_VERSION, docs, None, 0).toCbor().encode()
    }

    /**
     * Build and append the KB-JWT for an SD-JWT presentation.
     *
     * @param sdJwtPresentation the presented SD-JWT ending with "~"
     * @param aud               the verifier client_id (prefix included)
     * @param nonce             the request nonce
     * @param docId             storage id — the SecureArea key batch id
     * @return full presentation string "<sd-jwt>~<kb-jwt>"
     */
    static func appendKbJwt(
        sdJwtPresentation: String,
        aud: String,
        nonce: String,
        docId: String,
        docKeyInfo: ?Array<UInt8>
    ): String {
        // sd_hash covers everything before the KB-JWT, INCLUDING the final "~".
        let withTilde = if (sdJwtPresentation.endsWith("~")) {
            sdJwtPresentation
        } else {
            sdJwtPresentation + "~"
        }
        let sdHash = Base64Url.encode(Digest.sha256(withTilde.toArray()))

        let header = "{\"typ\":\"kb+jwt\",\"alg\":\"ES256\"}"
        let iat = DateTime.now().toUnixTimeStamp().toMilliseconds() / 1000
        let payload = "{\"nonce\":\"" + jsonEscape(nonce) + "\",\"aud\":\"" + jsonEscape(aud) +
            "\",\"iat\":" + iat.toString() + ",\"sd_hash\":\"" + sdHash + "\"}"

        let signingInput = Base64Url.encode(header.toArray()) + "." + Base64Url.encode(payload.toArray())
        var signature = Array<UInt8>()
        match (holderProofKey(docKeyInfo)) {
            case Some(priv) =>
                Hilog.info(0, "VPFLOW", "KB-JWT signing with persisted proof key")
                signature = EcdsaP256.sign(priv, signingInput.toArray())
            case None =>
                let secureArea = SecureAreaRegistry.shared.get(None)
                Hilog.info(0, "VPFLOW", "KB-JWT signing with SecureArea")
                signature = secureArea.signature(docId, 0, SigningAlgorithm.ES256, signingInput.toArray(), None)
        }
        Hilog.info(0, "VPFLOW", "KB-JWT signed docId=" + docId + " sigLen=" + signature.size.toString())

        return withTilde + signingInput + "." + Base64Url.encode(signature)
    }

    /** Decode the persisted holder proof key from Document.docKeyInfo. */
    static func holderProofKey(docKeyInfo: ?Array<UInt8>): ?ECDSAPrivateKey {
        let bytes = match (docKeyInfo) {
            case Some(b) => b
            case None => return None
        }
        try {
            let info = DocKeyInfo.fromBytes(bytes)
            match (info.proofKeyDers) {
                case Some(ders) =>
                    if (ders.isEmpty()) { return None }
                    return Some(ECDSAPrivateKey.decodeDer(DerBlob(ders[0])))
                case None => return None
            }
        } catch (_: Exception) {
            return None
        }
    }

    /**
     * Find the issuance-batch key index whose public key matches the MSO's
     * deviceKey (COSE_Key label -2 = x coordinate). Falls back to 0 when the
     * MSO key cannot be parsed or nothing matches.
     */
    static func matchDeviceKeyIndex(
        secureArea: SecureArea,
        docId: String,
        issuerSigned: IssuerSigned
    ): Int64 {
        try {
            let dk = issuerSigned.issuerAuth.mso.deviceKeyInfo.deviceKey
            var msoX: ?Array<UInt8> = None
            match (dk) {
                case CborValue.MapVal(pairs) =>
                    for ((k, v) in pairs) {
                        match ((k, v)) {
                            // CBOR negative int: value = -1 - n, so label -2 ⇒ n == 1
                            case (CborValue.NInt64Val(n), CborValue.ByteStringVal(b)) =>
                                if (n == 1) { msoX = Some(b) }
                            case _ => ()
                        }
                    }
                case _ => ()
            }
            let x = match (msoX) {
                case Some(b) => b
                case None => return 0
            }
            let batchInfo = secureArea.getKeyBatchInfo(docId)
            var i: Int64 = 0
            while (i < batchInfo.usedCounts.size) {
                let pub = secureArea.getPublicKeyBytes(docId, i, batchInfo.crv)
                // pub = 0x04 || X(32) || Y(32)
                if (pub.size == 65 && x.size == 32) {
                    var same = true
                    for (j in 0..32) {
                        if (pub[1 + j] != x[j]) { same = false; break }
                    }
                    if (same) { return i }
                }
                i += 1
            }
            Hilog.warn(0, "VPFLOW", "No batch key matches MSO deviceKey; using 0")
            return 0
        } catch (e: Exception) {
            Hilog.warn(0, "VPFLOW", "matchDeviceKeyIndex failed: " + e.message)
            return 0
        }
    }

    /** Hex of the first n bytes, for diagnostics. */
    private static func hexPrefix(bytes: Array<UInt8>, n: Int64): String {
        let table = "0123456789abcdef".toArray()
        let count = if (bytes.size < n) { bytes.size } else { n }
        let out = ArrayList<UInt8>()
        var i: Int64 = 0
        while (i < count) {
            out.add(table[Int64(bytes[i] >> 4)])
            out.add(table[Int64(bytes[i] & 0x0Fu8)])
            i += 1
        }
        return String.fromUtf8(out.toArray())
    }

    /** Minimal JSON string escaping for values we control (quotes/backslash). */
    private static func jsonEscape(s: String): String {
        var out = ""
        for (b in s.toArray()) {
            if (b == b'"') {
                out = out + "\\\""
            } else if (b == b'\\') {
                out = out + "\\\\"
            } else {
                out = out + String.fromUtf8([b])
            }
        }
        return out
    }
}


// Detect base64url TEXT bytes: issuers commonly deliver mso_mdoc credentials
// as base64url strings. Feeding that text straight to the CBOR decoder can
// mis-read a byte as a huge length header and hang cbor4cj's reader instead
// of throwing, so the format is sniffed BEFORE decoding (an IssuerSigned map
// always starts with a byte >= 0xA0, never within the base64url alphabet).
func presLooksLikeBase64UrlTextBytes(bytes: Array<UInt8>): Bool {
    if (bytes.isEmpty()) { return false }
    for (b in bytes) {
        let ok = (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A) ||
            (b >= 0x30 && b <= 0x39) || b == 0x2D || b == 0x5F || b == 0x3D
        if (!ok) { return false }
    }
    return true
}
