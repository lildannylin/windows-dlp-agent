# Windows Transparent Proxy 可行性研究

**問題**:能不能在 Windows 上做一個 **transparent MITM proxy**,並用「**逼 QUIC fallback 到 TCP**」的方式讓 CA 解密可行?

**先澄清一個用詞**:fallback **不是「避免 CA 問題」**——你**仍然需要 CA**(要解密就要偽造憑證)。fallback 真正解決的是「**QUIC 沒辦法 MITM,CA 沒有舞台**」的問題:把流量逼回 TCP,CA 才有地方出示偽造憑證。所以正確說法是「**用 QUIC fallback 讓 CA 有用武之地**」,不是「避免 CA」。

---

## 0. 結論(TL;DR)

- **技術上可行**。Windows 有兩條成熟路徑做 transparent 重導,而且 Chrome 的 QUIC 和 ECH 都有辦法壓制。
- **但比 explicit 明顯複雜**:要一張**簽章的核心驅動** + **同時壓制 QUIC 和 ECH**。
- **在受管端點(GPO/Intune)上很可行**(政策就能關 QUIC + ECH);**在非受管環境上較難、較粗暴**(要網路層封 UDP + 操弄 DNS)。
- **定位建議**:當 **catch-all 補網層**(收非瀏覽器 / 不理會 proxy 的 app),**不要取代 explicit**——因為若你已能推政策,explicit 更省事且免費解掉 QUIC + host 辨識 + ECH。

---

## 1. 要解決的三個子問題

transparent MITM 要成立,必須同時搞定:

| 子問題 | 內容 |
|---|---|
| **A. 重導** | 把外送 TCP:443 導進本機 proxy(client 不知情)|
| **B. 消滅 QUIC** | 讓沒有東西從 UDP:443 溜走(否則盲區)|
| **C. 認得目標** | 沒有 CONNECT,要還原原始目的地 IP + **host 名稱**(偽造憑證用)|

---

## 2. 子問題 A:重導 — 兩條路

### A1. WFP connect-redirect callout 驅動(原生、最穩)★ 產品級
Windows Filtering Platform 內建的 **ALE connect-redirect** 功能,**Microsoft 官方文件明講就是給 TLS inspection 用的**(Win7+,本機重導 Win8+):

- callout 驅動在 `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6` 把連線重導到本機 proxy(loopback),填 `localRedirectTargetPID` + `localRedirectHandle`,並把**原始目的地存進 `localRedirectContext`**。
- 你的 user-mode proxy 用 `WSAIoctl` 查 **`SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT`** 拿**原始目的地 IP:port**,再用 `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` 在對外 socket 上關聯連線。
- **支援 TCP 與 UDP**;用 `FwpsQueryConnectionRedirectState0` 防止無限重導。
- **優點**:原生、無 Wi-Fi 限制、微軟背書、拿得到原始目的地。
- **缺點**:C 核心驅動、需 **EV/attestation 簽章**、開發複雜。

### A2. WinDivert(user-mode,快速原型)★ PoC 用
user-mode 封包 divert(底層是簽章的 WFP 驅動),把 TCP:443 重導到 loopback:

- **優點**:純 user-mode、prebuilt 驅動已簽章、上手快、社群多(多個 transparent proxy 專案用它,如 HttpFilteringEngine)。
- **缺點**:**防毒常誤標**;**Wi-Fi 介面卡有已知限制**(某些 Wi-Fi driver 邊界 user-mode 跨不過去,實測有人栽在這);商用要**自己拿憑證簽驅動**;封包重注要自己處理。

---

## 3. 子問題 B:消滅 QUIC — 兩條路

### B1. Chrome 政策 `QuicAllowed=false`(受管端點)★ 最乾淨
GPO / 登錄 `Software\Policies\Google\Chrome\QuicAllowed=0` → **Chrome 完全不用 QUIC**,不必碰網路層。

- **優點**:乾淨、無延遲、無副作用。
- **缺點**:只管 Chrome/Edge(其他 app 的 QUIC 不管);**而且——若你已能推政策,不如直接推 explicit proxy 政策**(見 §6)。

### B2. 封 UDP:443(網路層)★ 涵蓋所有 app
查證結果:**「封掉 UDP 80/443,Chrome 會自動 fail over 到 TCP」**。可用 WinDivert 丟包或 Windows 防火牆規則。

- **優點**:對**所有** app 生效(不只瀏覽器)。
- **缺點**:首次連線有 fallback **延遲**(Chrome 要偵測 QUIC 壞掉才降級,有「broken-QUIC」暖機);要封得**完整**;影響所有用 QUIC 的 app。

---

## 4. 子問題 C:認得目標 —— 而且卡在 ECH

- **原始目的地 IP:port**:WFP 原生給(`ORIGINAL_DESTINATION`);WinDivert 靠連線 tuple 追蹤。**已解決**。
- **host 名稱**(偽造憑證要填正確 SAN):**得偷看 TLS ClientHello 的 SNI**。
- ⚠️ **ECH 是最大變數**:查證結果 **ECH(Encrypted Client Hello)已在 Chrome 預設啟用**,會**把 SNI 加密** → **SNI-peek 失效 → 認不出 host → 偽造不了正確憑證**。而且 ECH 是 TLS 擴充,**跟走 TCP 還是 QUIC 無關**,逼到 TCP 也一樣加密。
  - **受管解法**:政策 `Software\Policies\Google\Chrome\EncryptedClientHelloEnabled=0` → SNI 恢復明文。★
  - **非受管解法**:封掉 DNS 的 **HTTPS/SVCB record**(ECH 公鑰的傳遞管道)→ Chrome 拿不到 ECH config → 退回明文 SNI。較粗暴。

> **對比 explicit**:explicit 從 `CONNECT chatgpt.com:443` 直接拿到明文 host,**天生免疫 ECH**。這是 transparent 額外要流血的地方。

---

## 5. CA 的角色(再次澄清)

- **CA 一樣要**,而且信任機制和 explicit **完全相同**(裝進 OS Trusted Root;對本機安裝的根,Chrome 跳過 pinning/CT)。
- QUIC fallback **沒有省掉 CA**;它只是把流量搬到 TCP,**讓 CA 有地方用**。

---

## 6. 可行性評分

| 情境 | 重導 (A) | 消滅 QUIC (B) | 認得 host (C) | 整體 |
|---|---|---|---|---|
| **受管端點(GPO/Intune)** | WFP callout 或 WinDivert | 政策 `QuicAllowed=0` | 政策 `EncryptedClientHelloEnabled=0` + SNI-peek | ✅ **可行**(政策把 B、C 都變簡單,你只要重導 + CA)|
| **非受管端點** | 同上 | 網路封 UDP:443(有延遲)| 封 DNS HTTPS record(脆弱)| ⚠️ **可行但脆弱**(多個網路層 hack + 驅動信任問題)|

---

## 7. 和 explicit 的成本對比 + 建議

**關鍵矛盾**:transparent 壓制 QUIC 和 ECH **最乾淨的辦法都是「推 Chrome 政策」**——但**你若已能推政策,直接推 explicit proxy 政策(`ProxyMode=fixed_servers`)反而更簡單**,而且 explicit **免費**拿到:棄 QUIC、host 從 CONNECT(免疫 ECH)、無驅動。

所以 transparent 的**唯一不可替代價值**是:**攔到「不理會 proxy 設定的 app」**(curl、桌面/Electron AI app)——這是 explicit 覆蓋不到的。

**建議定位(和現有專案的關係)**:

| 層 | 技術 | 攔什麼 |
|---|---|---|
| **主力(現有 endpoint 專案)** | explicit proxy(受管政策)| 瀏覽器,乾淨棄 QUIC,免疫 ECH |
| **補網(這份研究的產物)** | transparent(WFP redirect + 封 UDP:443)| **不理會 proxy 的 app** |

兩者**共用同一套 MITM 引擎 + CA + DLP**,只換「進料前門」。

---

## 8. PoC 路線圖(若要動手)

**原型(1–2 週,驗證概念):**
1. **WinDivert** 重導 TCP:443 → loopback,同時**丟棄 UDP:443**。
2. proxy 端新增「**無 CONNECT 入口**」:從連線拿原始 dst、**偷看 SNI** 得 host(現有程式是靠 CONNECT,transparent 走 SNI)。
3. 開發機推 `EncryptedClientHelloEnabled=0`(+ 可選 `QuicAllowed=0`)排除 ECH/QUIC 干擾。
4. host 拿到後,**沿用現有的 `ca.py` 偽造憑證 + `dlp/` + 串流轉發**——引擎不動。

**產品(數月,穩定):**
- 改用 **WFP connect-redirect callout 驅動**(擺脫 WinDivert 的 AV 誤標與 Wi-Fi 限制),**EV 簽章**。
- 受管政策一併推 `QuicAllowed=0` + `EncryptedClientHelloEnabled=0`。

---

## 9. 風險清單

| 風險 | 說明 |
|---|---|
| **驅動簽章** | WFP callout 要 EV/attestation 簽章;WinDivert 商用要自簽 |
| **防毒誤標** | WinDivert 常被 AV 標記 |
| **Wi-Fi 限制** | WinDivert 在某些 Wi-Fi 介面卡跨不過 driver 邊界(WFP callout 無此問題)|
| **ECH 軍備競賽** | ECH 預設開啟且持續演進;靠政策/DNS 壓制是持續維護成本 |
| **核心穩定性** | 核心驅動 bug = BSOD 風險 |
| **fallback 延遲** | 封 UDP 後首連有 QUIC 暖機延遲 |
| **全域副作用** | 封 UDP:443 影響所有 app |

---

## 10. 一句話總結

> **可行——尤其在受管端點上(政策解掉 QUIC+ECH,你只要做「重導 + CA」)。但 transparent 壓 QUIC/ECH 最乾淨的手段都是推政策,而推政策的話 explicit 更省事又免費解掉這些。所以 transparent 的價值在「補 explicit 攔不到的非瀏覽器 app」,該當 catch-all 疊加層,不是取代 explicit。CA 從頭到尾都省不掉——fallback 只是給 CA 一個能工作的 TCP 場地。**

---

## 參考來源

- WinDivert(官方):https://reqrypt.org/windivert.html ・文件 https://reqrypt.org/windivert-doc.html
- WinDivert Wi-Fi 限制實例:https://dev.to/chronocoders/why-my-windows-transparent-proxy-failed-on-wi-fi-and-worked-on-ethernet-3f6e
- 透明 TLS filtering proxy 參考實作(WinDivert):https://github.com/TechnikEmpire/HttpFilteringEngine
- WFP connect/bind redirection(Microsoft 官方):https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- WFP proxied connections tracking(Microsoft):https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- WFP proxy 攔截範例:https://github.com/huaraz/ProxyIntercept
- Chrome `QuicAllowed` 政策 / 封 UDP fallback:https://issues.chromium.org/issues/41159437 ・https://support.google.com/chrome/thread/42295038
- Chrome `EncryptedClientHelloEnabled` 政策:https://chromeenterprise.google/policies/encrypted-client-hello-enabled/
- 停用 ECH 的理由與方法:https://chasersystems.com/blog/disabling-encrypted-clienthello-in-google-chrome-and-why/
