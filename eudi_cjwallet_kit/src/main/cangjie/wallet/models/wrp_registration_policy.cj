/*
 * wrp_registration_policy.cj
 *
 * EUDI Wallet Kit — WRP registration policy decoded from a WRPRC.
 *
 * Cangjie port of:
 *   Sources/EudiWalletKit/Models/WrpRegistrationPolicy.swift  (v0.40.9)
 *
 * Package: ohos_app_cangjie_eudi_cjwallet_kit.wallet.models  (S-002)
 *
 * The Wallet Relying Party Registration Certificate (WRPRC, ETSI TS 119 475)
 * payload decodes into a WrpRegistrationPolicy. JSON keys are snake_case,
 * mirroring the iOS CodingKeys 1-to-1.
 *
 * Notes:
 *   - iOS `status: Status` (MdocDataModel18013 status-list reference) →
 *     PolicyStatusList { idx, uri } decoded from {"status_list":{"idx","uri"}}.
 *   - iOS ClaimPath (OpenID4VP) → ClaimPath from openid4vp.entity.dcql.
 *   - Swift Decodable → static fromJsonObject / fromJsonString factories
 *     using stdx.encoding.json (repo pattern, see issuance_models.cj).
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.models

import std.collection.ArrayList
import stdx.encoding.json.{JsonValue, JsonObject, JsonArray, JsonString, JsonInt, JsonFloat}
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vp.entity.dcql.ClaimPath

// ===========================================================================
// PolicyPurpose
// iOS: public struct PolicyPurpose: Decodable, Sendable
// ===========================================================================

/** A language-tagged free-text value (purpose / service description entry). */
public class PolicyPurpose {
    public let lang: String
    public let value: String

    public init(lang: String, value: String) {
        this.lang = lang
        this.value = value
    }

    public static func fromJson(obj: JsonObject): ?PolicyPurpose {
        let lang: String = match (obj.get("lang")) {
            case Some(js: JsonString) => js.getValue()
            case _ => return None
        }
        let value: String = match (obj.get("value")) {
            case Some(js: JsonString) => js.getValue()
            case _ => return None
        }
        return Some(PolicyPurpose(lang, value))
    }
}

// ===========================================================================
// SupervisoryAuthority
// ===========================================================================

/** The supervisory authority responsible for the registered relying party. */
public class SupervisoryAuthority {
    public let name: ?String
    public let email: ?String
    public let phone: ?String
    public let uri: ?String

    public init(name: ?String, email: ?String, phone: ?String, uri: ?String) {
        this.name = name
        this.email = email
        this.phone = phone
        this.uri = uri
    }

    public static func fromJson(obj: JsonObject): SupervisoryAuthority {
        return SupervisoryAuthority(
            policyJsonString(obj, "name"),
            policyJsonString(obj, "email"),
            policyJsonString(obj, "phone"),
            policyJsonString(obj, "uri")
        )
    }
}

// ===========================================================================
// PolicyIntermediary
// ===========================================================================

/**
 * The intermediary a WRP acts through, if any.
 * JSON keys: identifier ← "sub", name ← "sname" (the intermediary common
 * name is carried in the `sname` claim, not `name`).
 */
public class PolicyIntermediary {
    public let identifier: ?String
    public let name: ?String

    public init(identifier: ?String, name: ?String) {
        this.identifier = identifier
        this.name = name
    }

    public static func fromJson(obj: JsonObject): PolicyIntermediary {
        return PolicyIntermediary(
            policyJsonString(obj, "sub"),
            policyJsonString(obj, "sname")
        )
    }
}

// ===========================================================================
// RegistrationIdentifier
// ===========================================================================

/** An identifier of the registered relying party (derived from `sub`). */
public class RegistrationIdentifier {
    public let value: String

    public init(value: String) {
        this.value = value
    }
}

// ===========================================================================
// PolicyCredentialMeta / PolicyClaim / PolicyCredential
// ===========================================================================

/** Credential meta: vct values (SD-JWT) or doctype value (mso_mdoc). */
public class PolicyCredentialMeta {
    public let vctValues: ?Array<String>
    public let doctypeValue: ?String

    public init(vctValues: ?Array<String>, doctypeValue: ?String) {
        this.vctValues = vctValues
        this.doctypeValue = doctypeValue
    }

    public static func fromJson(obj: JsonObject): PolicyCredentialMeta {
        return PolicyCredentialMeta(
            policyJsonStringArray(obj, "vct_values"),
            policyJsonString(obj, "doctype_value")
        )
    }
}

/** A claim declared in the registration policy, identified by its path. */
public class PolicyClaim {
    public let path: ClaimPath

    public init(path: ClaimPath) {
        this.path = path
    }
}

/** A credential the relying party is registered to request / provide. */
public class PolicyCredential {
    public let format: String
    public let meta: PolicyCredentialMeta
    /** JSON key "claim" (singular), mirroring the iOS CodingKeys. */
    public let claims: ?Array<PolicyClaim>

    public init(format: String, meta: PolicyCredentialMeta, claims: ?Array<PolicyClaim>) {
        this.format = format
        this.meta = meta
        this.claims = claims
    }

    public static func fromJson(obj: JsonObject): ?PolicyCredential {
        let format: String = match (obj.get("format")) {
            case Some(js: JsonString) => js.getValue()
            case _ => return None
        }
        let meta: PolicyCredentialMeta = match (obj.get("meta")) {
            case Some(mObj: JsonObject) => PolicyCredentialMeta.fromJson(mObj)
            case _ => PolicyCredentialMeta(None, None)
        }
        let claims: ?Array<PolicyClaim> = match (obj.get("claim")) {
            case Some(arr: JsonArray) =>
                let acc = ArrayList<PolicyClaim>()
                for (item in arr.getItems()) {
                    match (item) {
                        case cObj: JsonObject =>
                            match (cObj.get("path")) {
                                case Some(pArr: JsonArray) =>
                                    acc.add(PolicyClaim(ClaimPath.fromJsonArray(pArr)))
                                case _ => ()
                            }
                        case _ => ()
                    }
                }
                Some(acc.toArray())
            case _ => None
        }
        return Some(PolicyCredential(format, meta, claims))
    }
}

// ===========================================================================
// PolicyStatusList
// iOS: MdocDataModel18013.Status (status-list reference) — {"status_list":{idx,uri}}
// ===========================================================================

/** Reference into a token status list carried in the WRPRC `status` claim. */
public class PolicyStatusList {
    public let idx: Int64
    public let uri: String

    public init(idx: Int64, uri: String) {
        this.idx = idx
        this.uri = uri
    }

    public static func fromStatusJson(obj: JsonObject): ?PolicyStatusList {
        let listObj: JsonObject = match (obj.get("status_list")) {
            case Some(lObj: JsonObject) => lObj
            case _ => return None
        }
        let idx: Int64 = match (listObj.get("idx")) {
            case Some(ji: JsonInt) => ji.getValue()
            case Some(jf: JsonFloat) => Int64(jf.getValue())
            case _ => return None
        }
        let uri: String = match (listObj.get("uri")) {
            case Some(js: JsonString) => js.getValue()
            case _ => return None
        }
        return Some(PolicyStatusList(idx, uri))
    }
}

// ===========================================================================
// WrpRegistrationPolicy
// iOS: public struct WrpRegistrationPolicy: Decodable, Sendable
// ===========================================================================

/**
 * The registration policy decoded from a WRP Registration Certificate payload.
 * Field names mirror iOS; JSON keys are snake_case (see fromJsonObject).
 */
public class WrpRegistrationPolicy {
    public let entitlements: ?Array<String>
    /** Subject identifier of the registered party (required). */
    public let sub: String
    public let country: ?String
    public let policyID: ?Array<String>
    public let credentials: ?Array<PolicyCredential>
    public let purpose: ?Array<PolicyPurpose>
    public let registryURI: ?String
    public let certificatePolicy: ?String
    public let srvDescription: ?Array<PolicyPurpose>
    public let supportURI: ?String
    public let supervisoryAuthority: ?SupervisoryAuthority
    public let privacyPolicy: ?String
    public let name: ?String
    public let infoURI: ?String
    public let subLn: ?String
    public let subGn: ?String
    public let subFn: ?String
    public let iat: ?Int64
    public let exp: ?Int64
    public let status: ?PolicyStatusList
    public let intendedUseID: ?String
    public let providesAttestations: ?Array<PolicyCredential>
    public let intermediary: ?PolicyIntermediary

    public init(
        entitlements: ?Array<String>,
        sub: String,
        country: ?String,
        policyID: ?Array<String>,
        credentials: ?Array<PolicyCredential>,
        purpose: ?Array<PolicyPurpose>,
        registryURI: ?String,
        certificatePolicy: ?String,
        srvDescription: ?Array<PolicyPurpose>,
        supportURI: ?String,
        supervisoryAuthority: ?SupervisoryAuthority,
        privacyPolicy: ?String,
        name: ?String,
        infoURI: ?String,
        subLn: ?String,
        subGn: ?String,
        subFn: ?String,
        iat: ?Int64,
        exp: ?Int64,
        status: ?PolicyStatusList,
        intendedUseID: ?String,
        providesAttestations: ?Array<PolicyCredential>,
        intermediary: ?PolicyIntermediary
    ) {
        this.entitlements = entitlements
        this.sub = sub
        this.country = country
        this.policyID = policyID
        this.credentials = credentials
        this.purpose = purpose
        this.registryURI = registryURI
        this.certificatePolicy = certificatePolicy
        this.srvDescription = srvDescription
        this.supportURI = supportURI
        this.supervisoryAuthority = supervisoryAuthority
        this.privacyPolicy = privacyPolicy
        this.name = name
        this.infoURI = infoURI
        this.subLn = subLn
        this.subGn = subGn
        this.subFn = subFn
        this.iat = iat
        this.exp = exp
        this.status = status
        this.intendedUseID = intendedUseID
        this.providesAttestations = providesAttestations
        this.intermediary = intermediary
    }

    /**
     * Identifiers of the registered relying party, derived from the `sub` claim.
     * Mirrors iOS computed property `identifiers`.
     */
    public func identifiers(): Array<RegistrationIdentifier> {
        return [RegistrationIdentifier(this.sub)]
    }

    /**
     * Decode from the WRPRC payload JSON object (snake_case keys mirroring
     * the iOS CodingKeys). Throws WalletError(InvalidWrprc) when the
     * required `sub` claim is missing.
     */
    public static func fromJsonObject(obj: JsonObject): WrpRegistrationPolicy {
        let sub: String = match (obj.get("sub")) {
            case Some(js: JsonString) => js.getValue()
            case _ =>
                throw WalletError.withCode(
                    "WRPRC payload is missing required claim 'sub'",
                    WalletErrorCode.InvalidWrprc
                )
        }
        let status: ?PolicyStatusList = match (obj.get("status")) {
            case Some(sObj: JsonObject) => PolicyStatusList.fromStatusJson(sObj)
            case _ => None
        }
        return WrpRegistrationPolicy(
            policyJsonStringArray(obj, "entitlements"),
            sub,
            policyJsonString(obj, "country"),
            policyJsonStringArray(obj, "policy_id"),
            policyCredentialArray(obj, "credentials"),
            policyPurposeArray(obj, "purpose"),
            policyJsonString(obj, "registry_uri"),
            policyJsonString(obj, "certificate_policy"),
            policyPurposeArray(obj, "srv_description"),
            policyJsonString(obj, "support_uri"),
            policySupervisoryAuthority(obj),
            policyJsonString(obj, "privacy_policy"),
            policyJsonString(obj, "name"),
            policyJsonString(obj, "info_uri"),
            policyJsonString(obj, "sub_ln"),
            policyJsonString(obj, "sub_gn"),
            policyJsonString(obj, "sub_fn"),
            policyJsonInt(obj, "iat"),
            policyJsonInt(obj, "exp"),
            status,
            policyJsonString(obj, "intended_use_id"),
            policyCredentialArray(obj, "provides_attestations"),
            policyIntermediary(obj)
        )
    }

    /** Decode from a raw UTF-8 JSON string (the WRPRC token payload). */
    public static func fromJsonString(jsonStr: String): WrpRegistrationPolicy {
        let parsed: JsonValue = try {
            JsonValue.fromStr(jsonStr)
        } catch (_: Exception) {
            throw WalletError.withCode(
                "WRPRC payload cannot be decoded as JSON",
                WalletErrorCode.InvalidWrprc
            )
        }
        match (parsed) {
            case obj: JsonObject => return WrpRegistrationPolicy.fromJsonObject(obj)
            case _ =>
                throw WalletError.withCode(
                    "WRPRC payload is not a JSON object",
                    WalletErrorCode.InvalidWrprc
                )
        }
    }
}

// ===========================================================================
// Package-private JSON helpers
// ===========================================================================

func policyJsonString(obj: JsonObject, key: String): ?String {
    match (obj.get(key)) {
        case Some(js: JsonString) => Some(js.getValue())
        case _ => None
    }
}

func policyJsonInt(obj: JsonObject, key: String): ?Int64 {
    match (obj.get(key)) {
        case Some(ji: JsonInt) => Some(ji.getValue())
        case Some(jf: JsonFloat) => Some(Int64(jf.getValue()))
        case _ => None
    }
}

func policyJsonStringArray(obj: JsonObject, key: String): ?Array<String> {
    match (obj.get(key)) {
        case Some(arr: JsonArray) =>
            let acc = ArrayList<String>()
            for (item in arr.getItems()) {
                match (item) {
                    case js: JsonString => acc.add(js.getValue())
                    case _ => ()
                }
            }
            Some(acc.toArray())
        case _ => None
    }
}

func policyPurposeArray(obj: JsonObject, key: String): ?Array<PolicyPurpose> {
    match (obj.get(key)) {
        case Some(arr: JsonArray) =>
            let acc = ArrayList<PolicyPurpose>()
            for (item in arr.getItems()) {
                match (item) {
                    case pObj: JsonObject =>
                        match (PolicyPurpose.fromJson(pObj)) {
                            case Some(p) => acc.add(p)
                            case None => ()
                        }
                    case _ => ()
                }
            }
            Some(acc.toArray())
        case _ => None
    }
}

func policyCredentialArray(obj: JsonObject, key: String): ?Array<PolicyCredential> {
    match (obj.get(key)) {
        case Some(arr: JsonArray) =>
            let acc = ArrayList<PolicyCredential>()
            for (item in arr.getItems()) {
                match (item) {
                    case cObj: JsonObject =>
                        match (PolicyCredential.fromJson(cObj)) {
                            case Some(c) => acc.add(c)
                            case None => ()
                        }
                    case _ => ()
                }
            }
            Some(acc.toArray())
        case _ => None
    }
}

func policySupervisoryAuthority(obj: JsonObject): ?SupervisoryAuthority {
    match (obj.get("supervisory_authority")) {
        case Some(sObj: JsonObject) => Some(SupervisoryAuthority.fromJson(sObj))
        case _ => None
    }
}

func policyIntermediary(obj: JsonObject): ?PolicyIntermediary {
    match (obj.get("intermediary")) {
        case Some(iObj: JsonObject) => Some(PolicyIntermediary.fromJson(iObj))
        case _ => None
    }
}
