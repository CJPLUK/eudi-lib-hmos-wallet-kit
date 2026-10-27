/*
 * wk_models_test.cj
 *
 * Unit tests for wallet-kit pure-logic data models:
 *   - doc_elements.cj   (DocElements / MsoMdocElement(s) / SdJwtElement(s) /
 *                        NameSpacedElements / DocPresentInfo / RequestItems)
 *   - issuance_models.cj (OfferedDocModel / OfferedIssuanceModel /
 *                         IssuanceOutcome(Helper) / PendingReason /
 *                         DeferredIssuanceModel / BatchCreateKeyResult /
 *                         ConfigurationCredentialMetadata)
 *   - config.cj          (ClientIdScheme / OpenId4VciConfiguration /
 *                         KeyAttestationConfiguration via WalletAttestationsProvider)
 *
 * All assertions use known inputs against deterministic, offline pure logic.
 */
package ohos_app_cangjie_eudi_cjwallet_kit.wallet.models

import std.unittest.*
import std.unittest.testmacro.*
import std.collection.ArrayList
import std.collection.HashMap

import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.claims.DocClaim
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.claims.DocDataFormat
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.{CredentialOptions, CredentialPolicy}
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.engagement.CoseKey
import ohos_app_cangjie_eudi_cjmdoc_transfer.transfer.framing.RequestItem
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.credential.Claim
import ohos_app_cangjie_eudi_cjopenid4vp_vci.openid4vci.entity.types.{CredentialConfigurationIdentifier, Display}

// Symbols under test (wallet.models). After consolidation this file's package is
// rewritten to ohos_app_cangjie_entry, so these must be imported explicitly.
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.{
    MsoMdocElement,
    SdJwtElement,
    NameSpacedElements,
    MsoMdocElements,
    SdJwtElements,
    DocElements,
    DocPresentInfo,
    RequestItems,
    docElementsToRequestItems,
    OfferedDocModel,
    OfferedIssuanceModel,
    IssuanceOutcome,
    IssuanceOutcomeHelper,
    PendingIssuanceModel,
    PendingReason,
    CredentialConfiguration,
    BatchCreateKeyResult,
    ConfigurationCredentialMetadata,
    DocTypeIdentifier
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mkMsoElement(id: String, valid: Bool, selected: Bool): MsoMdocElement {
    return MsoMdocElement(id, false, false, None, None, valid, selected)
}

func mkSdElement(path: Array<String>, valid: Bool, selected: Bool): SdJwtElement {
    return SdJwtElement(path, false, false, None, None, valid, selected, None)
}

func emptyClaims(): ArrayList<Claim> {
    return ArrayList<Claim>()
}

func defaultCredOptions(): CredentialOptions {
    return CredentialOptions(CredentialPolicy.OneTimeUse, 1)
}

// ===========================================================================
// MsoMdocElement / NameSpacedElements / MsoMdocElements
// ===========================================================================
@Test
class WkModelsMsoMdocElementsUT {

    @TestCase
    func elementIsValidAndSelectedTrue(): Unit {
        let e = mkMsoElement("family_name", true, true)
        @Expect(e.isValidAndSelected(), true)
        @Expect(e.id(), "family_name")
    }

    @TestCase
    func elementValidButNotSelected(): Unit {
        let e = mkMsoElement("family_name", true, false)
        @Expect(e.isValidAndSelected(), false)
    }

    @TestCase
    func elementSelectedButInvalid(): Unit {
        let e = mkMsoElement("family_name", false, true)
        @Expect(e.isValidAndSelected(), false)
    }

    @TestCase
    func elementRequestItemRoundTrip(): Unit {
        let e = MsoMdocElement("birth_date", true, true, None, None, true, true)
        let ri: RequestItem = e.requestItem()
        // intentToRetain=true, isOptional=true passed through.
        @Expect(ri.elementPath.size, 1)
        @Expect(ri.elementPath[0], "birth_date")
    }

    @TestCase
    func nameSpacedElementsId(): Unit {
        let elems = ArrayList<MsoMdocElement>()
        elems.add(mkMsoElement("a", true, true))
        let nse = NameSpacedElements("org.iso.18013.5.1", elems)
        @Expect(nse.id(), "org.iso.18013.5.1")
        @Expect(nse.elements.size, 1)
    }

    @TestCase
    func selectedItemsDictionaryFiltersUnselected(): Unit {
        let elems = ArrayList<MsoMdocElement>()
        elems.add(mkMsoElement("a", true, true))    // selected -> included
        elems.add(mkMsoElement("b", true, false))   // not selected -> excluded
        elems.add(mkMsoElement("c", false, true))   // invalid -> excluded
        let nse = NameSpacedElements("ns1", elems)
        let nseList = ArrayList<NameSpacedElements>()
        nseList.add(nse)
        let doc = MsoMdocElements("doc1", "org.iso.18013.5.1.mDL", None, true, nseList)
        let dict = doc.selectedItemsDictionary()
        @Expect(dict.contains("ns1"), true)
        @Expect(dict["ns1"].size, 1)
        @Expect(dict["ns1"][0].elementPath[0], "a")
    }

    @TestCase
    func selectedItemsDictionarySkipsEmptyNamespace(): Unit {
        let elems = ArrayList<MsoMdocElement>()
        elems.add(mkMsoElement("b", true, false))   // none selected
        let nse = NameSpacedElements("ns1", elems)
        let nseList = ArrayList<NameSpacedElements>()
        nseList.add(nse)
        let doc = MsoMdocElements("doc1", "t", None, true, nseList)
        let dict = doc.selectedItemsDictionary()
        // namespace with zero selected items is omitted entirely
        @Expect(dict.contains("ns1"), false)
        @Expect(dict.size, 0)
    }

    @TestCase
    func mandatoryElementKeysEmpty(): Unit {
        let keys = MsoMdocElements.getMandatoryElementKeys("org.iso.18013.5.1.mDL", "org.iso.18013.5.1")
        @Expect(keys.size, 0)
    }

    @TestCase
    func docIdAndType(): Unit {
        let nseList = ArrayList<NameSpacedElements>()
        let doc = MsoMdocElements("docXYZ", "org.iso.18013.5.1.mDL", Some("My mDL"), true, nseList)
        @Expect(doc.id(), "docXYZ")
        @Expect(doc.docType, "org.iso.18013.5.1.mDL")
    }
}

// ===========================================================================
// SdJwtElement(s)
// ===========================================================================
@Test
class WkModelsSdJwtElementsUT {

    @TestCase
    func sdElementIdJoinsPath(): Unit {
        let e = mkSdElement(["address", "country"], true, true)
        @Expect(e.id(), "address.country")
    }

    @TestCase
    func sdElementIdSinglePath(): Unit {
        let e = mkSdElement(["given_name"], true, true)
        @Expect(e.id(), "given_name")
    }

    @TestCase
    func sdElementSelectedRequestItemsNoNested(): Unit {
        let e = mkSdElement(["given_name"], true, true)
        let items = e.selectedRequestItems()
        // own request item only
        @Expect(items.size, 1)
        @Expect(items[0].elementPath[0], "given_name")
    }

    @TestCase
    func sdElementSelectedRequestItemsWithNested(): Unit {
        let nested = ArrayList<SdJwtElement>()
        nested.add(mkSdElement(["address", "country"], true, true))   // included
        nested.add(mkSdElement(["address", "city"], true, false))    // not selected -> excluded
        let parent = SdJwtElement(["address"], false, false, None, None, true, true, Some(nested))
        let items = parent.selectedRequestItems()
        // parent + one valid-and-selected nested
        @Expect(items.size, 2)
    }

    @TestCase
    func sdJwtElementsSelectedItemsDictionaryUsesEmptyNamespace(): Unit {
        let elems = ArrayList<SdJwtElement>()
        elems.add(mkSdElement(["given_name"], true, true))
        elems.add(mkSdElement(["family_name"], true, false)) // excluded
        let doc = SdJwtElements("docSd", "urn:eu.europa.ec.eudi:pid:1", None, true, elems)
        let dict = doc.selectedItemsDictionary()
        @Expect(dict.contains(""), true)
        @Expect(dict[""].size, 1)
        @Expect(dict[""][0].elementPath[0], "given_name")
    }
}

// ===========================================================================
// DocElements discriminated union
// ===========================================================================
@Test
class WkModelsDocElementsUnionUT {

    func mkMsoDoc(): MsoMdocElements {
        let elems = ArrayList<MsoMdocElement>()
        elems.add(mkMsoElement("a", true, true))
        let nse = NameSpacedElements("ns1", elems)
        let nseList = ArrayList<NameSpacedElements>()
        nseList.add(nse)
        return MsoMdocElements("mdocId", "org.iso.18013.5.1.mDL", None, true, nseList)
    }

    func mkSdDoc(): SdJwtElements {
        let elems = ArrayList<SdJwtElement>()
        elems.add(mkSdElement(["given_name"], true, true))
        return SdJwtElements("sdId", "urn:pid:1", None, false, elems)
    }

    @TestCase
    func msoMdocBranchAccessors(): Unit {
        let de = DocElements.MsoMdoc(mkMsoDoc())
        @Expect(de.isMsoMdoc(), true)
        @Expect(de.isSdJwt(), false)
        @Expect(de.docId(), "mdocId")
        @Expect(de.docTypeOrVct(), "org.iso.18013.5.1.mDL")
        @Expect(de.isValid(), true)
        @Expect(de.id(), "mdocId")
        @Expect(de.asMsoMdoc().isSome(), true)
        @Expect(de.asSdJwt().isNone(), true)
    }

    @TestCase
    func sdJwtBranchAccessors(): Unit {
        let de = DocElements.SdJwt(mkSdDoc())
        @Expect(de.isSdJwt(), true)
        @Expect(de.isMsoMdoc(), false)
        @Expect(de.docId(), "sdId")
        @Expect(de.docTypeOrVct(), "urn:pid:1")
        @Expect(de.isValid(), false)
        @Expect(de.asSdJwt().isSome(), true)
        @Expect(de.asMsoMdoc().isNone(), true)
    }

    @TestCase
    func docElementsToRequestItemsAggregates(): Unit {
        let list = ArrayList<DocElements>()
        list.add(DocElements.MsoMdoc(mkMsoDoc()))
        list.add(DocElements.SdJwt(mkSdDoc()))
        let items: RequestItems = docElementsToRequestItems(list)
        @Expect(items.contains("mdocId"), true)
        @Expect(items.contains("sdId"), true)
        @Expect(items.size, 2)
    }
}

// ===========================================================================
// DocPresentInfo value container
// ===========================================================================
@Test
class WkModelsDocPresentInfoUT {

    @TestCase
    func fieldsRoundTrip(): Unit {
        let claims = ArrayList<DocClaim>()
        let info = DocPresentInfo("org.iso.18013.5.1.mDL", Some("SoftwareSecureArea"),
            DocDataFormat.Cbor, Some("Driving Licence"), claims)
        @Expect(info.docType, "org.iso.18013.5.1.mDL")
        @Expect(info.secureAreaName.isSome(), true)
        @Expect(info.displayName.isSome(), true)
        @Expect(info.docClaims.size, 0)
    }
}

// ===========================================================================
// OfferedDocModel / OfferedIssuanceModel
// ===========================================================================
@Test
class WkModelsOfferedDocModelUT {

    func mkOffered(docType: ?String, vct: ?String, identifier: ?String): OfferedDocModel {
        return OfferedDocModel(
            "cfg-id",
            docType,
            vct,
            None,
            identifier,
            "Display",
            [],
            emptyClaims(),
            None,
            defaultCredOptions(),
            None
        )
    }

    @TestCase
    func docTypeOrVctPrefersDocType(): Unit {
        let m = mkOffered(Some("org.iso.18013.5.1.mDL"), Some("urn:pid:1"), None)
        let r = m.docTypeOrVct()
        @Expect(r.isSome(), true)
        match (r) {
            case Some(v) => @Expect(v, "org.iso.18013.5.1.mDL")
            case None => @Expect("none", "some")
        }
    }

    @TestCase
    func docTypeOrVctFallsBackToVct(): Unit {
        let m = mkOffered(None, Some("urn:pid:1"), None)
        match (m.docTypeOrVct()) {
            case Some(v) => @Expect(v, "urn:pid:1")
            case None => @Expect("none", "some")
        }
    }

    @TestCase
    func docTypeOrVctNoneWhenBothNone(): Unit {
        let m = mkOffered(None, None, None)
        @Expect(m.docTypeOrVct().isNone(), true)
    }

    @TestCase
    func docTypeIdentifierIdentifierWins(): Unit {
        let m = mkOffered(Some("org.iso.18013.5.1.mDL"), None, Some("my-id"))
        match (m.docTypeIdentifier()) {
            case Some(dt) => @Expect(dt.value(), "my-id")
            case None => @Expect("none", "some")
        }
    }

    @TestCase
    func docTypeIdentifierMsoMdoc(): Unit {
        let m = mkOffered(Some("org.iso.18013.5.1.mDL"), None, None)
        match (m.docTypeIdentifier()) {
            case Some(dt) =>
                @Expect(dt.value(), "org.iso.18013.5.1.mDL")
                @Expect(dt.docType().isSome(), true)
            case None => @Expect("none", "some")
        }
    }

    @TestCase
    func docTypeIdentifierSdJwt(): Unit {
        let m = mkOffered(None, Some("urn:pid:1"), None)
        match (m.docTypeIdentifier()) {
            case Some(dt) =>
                @Expect(dt.value(), "urn:pid:1")
                @Expect(dt.vct().isSome(), true)
            case None => @Expect("none", "some")
        }
    }

    @TestCase
    func docTypeIdentifierNoneWhenAllNone(): Unit {
        let m = mkOffered(None, None, None)
        @Expect(m.docTypeIdentifier().isNone(), true)
    }

    @TestCase
    func offeredIssuanceModelTxCodeRequiredFalse(): Unit {
        let docs = ArrayList<OfferedDocModel>()
        docs.add(mkOffered(Some("t"), None, None))
        let model = OfferedIssuanceModel("Issuer", None, docs, None)
        @Expect(model.isTxCodeRequired(), false)
        @Expect(model.issuerName, "Issuer")
        @Expect(model.docModels.size, 1)
    }
}

// ===========================================================================
// IssuanceOutcome / IssuanceOutcomeHelper / PendingReason / Deferred / Batch
// ===========================================================================
@Test
class WkModelsIssuanceOutcomeUT {

    func mkConfig(): CredentialConfiguration {
        return CredentialConfiguration(
            CredentialConfigurationIdentifier("cfg"),
            "https://issuer.example",
            Some("org.iso.18013.5.1.mDL"),
            None, None,
            false, false, false,
            [],
            None, None,
            ArrayList<Display>(),
            ArrayList<Display>(),
            emptyClaims(),
            None,
            DocDataFormat.Cbor,
            defaultCredOptions()
        )
    }

    func mkIssued(): IssuanceOutcome {
        let pairs = ArrayList<(Array<UInt8>, Array<UInt8>)>()
        let data: Array<UInt8> = [0x01u8, 0x02u8, 0x03u8]
        let pk: Array<UInt8> = [0xAAu8, 0xBBu8]
        pairs.add((data, pk))
        return IssuanceOutcome.Issued(pairs, mkConfig(), "token")
    }

    @TestCase
    func issuedIsNotDeferredNotPending(): Unit {
        let o = mkIssued()
        @Expect(IssuanceOutcomeHelper.isDeferred(o), false)
        @Expect(IssuanceOutcomeHelper.isPending(o), false)
        @Expect(IssuanceOutcomeHelper.pendingOrDeferredStatus(o).isNone(), true)
    }

    @TestCase
    func issuedGetDataAndPublicKey(): Unit {
        let o = mkIssued()
        let data = IssuanceOutcomeHelper.getDataToSave(o, 0)
        @Expect(data.size, 3)
        @Expect(data[0], 0x01u8)
        let pk = IssuanceOutcomeHelper.getPublicKey(o, 0)
        @Expect(pk.size, 2)
        @Expect(pk[0], 0xAAu8)
    }

    @TestCase
    func issuedOutOfRangeReturnsEmpty(): Unit {
        let o = mkIssued()
        @Expect(IssuanceOutcomeHelper.getDataToSave(o, 5).size, 0)
        @Expect(IssuanceOutcomeHelper.getPublicKey(o, -1).size, 0)
    }

    @TestCase
    func pendingOutcomeStatus(): Unit {
        let model = PendingIssuanceModel(
            PendingReason.PresentationRequestUrl("https://verifier.example"),
            mkConfig(), "key", "verifier", "S256", "state-abc")
        let o = IssuanceOutcome.Pending(model)
        @Expect(IssuanceOutcomeHelper.isPending(o), true)
        @Expect(IssuanceOutcomeHelper.isDeferred(o), false)
        match (IssuanceOutcomeHelper.pendingOrDeferredStatus(o)) {
            case Some(_) => @Expect(true, true)
            case None => @Expect("none", "some")
        }
    }

    @TestCase
    func batchCreateKeyResultFields(): Unit {
        let keys = ArrayList<CoseKey>()
        let r = BatchCreateKeyResult(keys, "attestation-jwt")
        @Expect(r.keyAttestation, "attestation-jwt")
        @Expect(r.keys.size, 0)
    }

    @TestCase
    func configurationCredentialMetadataRawJson(): Unit {
        let meta = ConfigurationCredentialMetadata("{\"a\":1}")
        @Expect(meta.rawJson, "{\"a\":1}")
    }
}
