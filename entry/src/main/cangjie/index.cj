package ohos_app_cangjie_entry

import kit.ArkUI.LengthProp
import kit.ArkUI.Column
import kit.ArkUI.Row
import kit.ArkUI.Text
import kit.ArkUI.Button
import kit.ArkUI.CustomView
import kit.ArkUI.CJEntry
import kit.ArkUI.loadNativeView
import kit.ArkUI.FontWeight
import kit.ArkUI.SubscriberManager
import kit.ArkUI.ObservedProperty
import kit.ArkUI.LocalStorage
import ohos.arkui.state_macro_manage.Entry
import ohos.arkui.state_macro_manage.Component
import ohos.arkui.state_macro_manage.State

import ohos_app_cangjie_eudi_cjwallet_kit.runEudiWalletDemo

@Entry
@Component
class EntryView {
    @State
    var resultText: String = "Press the button to run the wallet-kit demo."

    func build() {
        Column(space: 16) {
            Button("Run Wallet-Kit Demo")
                .width(80.percent)
                .margin(top: 24)
                .onClick({
                    evt => this.resultText = runEudiWalletDemo()
                })
            Text(this.resultText)
                .width(90.percent)
                .margin(top: 16)
                .fontSize(14.vp)
                .maxLines(40)
        }
        .width(100.percent)
        .height(100.percent)
        .padding(16)
    }
}
