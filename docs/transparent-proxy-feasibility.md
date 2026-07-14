# Windows Transparent Proxy 可行性研究

**問題**:能不能在 Windows 上做一個 **transparent MITM proxy**,並用「**逼 QUIC fallback 到 TCP**」的方式讓 CA 解密可行?

**先澄清一個用詞**:fallback **不是「避免 CA 問題」**——你**仍然需要 CA**(要解密就要偽造憑證)。fallback 真正解決的是「**QUIC 沒辦法 MITM,CA 沒有舞台**」的問題:把流量逼回 TCP,CA 才有地方出示偽造憑證。所以正確說法是「**用 QUIC fallback 讓 CA 有用武之地**」,不是「避免 CA」。

---

## 0. 結論(TL;DR)

- **技術上完全可行,而且是成熟做法**——這不是實驗性的:**整個端點 SWG/DLP 產業(Zscaler、Netskope、Forcepoint、Digital Guardian…)就是這樣運作的**(見 §1)。
- **他們處理 QUIC 和 ECH 的方式,和本研究的推論完全一致**:**封 QUIC 逼 TCP fallback**(Zscaler 明列為最佳實務,「不影響使用者體驗」)、**在受管裝置上停用/降級 ECH** 讓 SNI 明文(Cisco 三層策略)。
- **代價**:一張**簽章的核心驅動** + **同時壓制 QUIC 和 ECH**;**且這一切只在「裝置信任你的 CA」時成立**(= 受管端點)。
- **定位建議**:當 **catch-all 補網層**(收非瀏覽器 / 不理會 proxy 的 app),**不要取代 explicit**——因為若你已能推政策,explicit 更省事且免費解掉 QUIC + host 辨識 + ECH。

---

## 1. 真實成功案例(重點:這是產業標準做法)

### 1.1 商用端點產品(都在做「端點 + Root CA + 本機/近端 TLS 解密」)

| 產品 | 攔截模型 | 關鍵佐證 |
|---|---|---|
| **Zscaler Client Connector** | 端點 MITM,裝 Zscaler Root CA 進信任存放區,decrypt→inspect→re-encrypt | **官方最佳實務就是「封 QUIC(UDP 80/443)→ fallback TCP → 開 TLS inspection」,且「不影響使用者體驗」** |
| **Netskope Client** | **用 OS 函式在網路堆疊「較低層」導流,不需要設 proxy**(= transparent),經 TLS/DTLS tunnel;裝 Netskope Root + Intermediate 憑證 | 證明 **transparent 端點導流在生產環境大規模可行** |
| **Forcepoint DLP / Digital Guardian / Endpoint Protector / Kitecyber / Strac** | 端點本機 SSL decrypt/re-encrypt 做內容檢查 | 端點 DLP 直接在端點解密 HTTPS,不必走傳統網路 proxy |
| **Microsoft Purview Endpoint DLP** | 瀏覽器/Web 保護(偏 extension/OS 整合)| 微軟自家端點 DLP |
| **Cisco Secure Firewall** | 網路端(非端點),但 **ECH 對策**極具參考價值 | 見 §5 的三層 ECH 策略 |

**兩種架構模型**(你要的是第一種):

1. **端點本機 MITM**(Zscaler Client Connector、多數端點 DLP、**本專案**):在端點上就地解密、就地檢查。
2. **導流到雲**(Netskope):端點 transparent 導流,把流量丟進 TLS/DTLS tunnel 到雲端再檢查。

### 1.2 現成建構元件(你不必從零刻驅動)

| 元件 | 類型 | 定位 |
|---|---|---|
| **NetFilter SDK** | 商用 Windows SDK | 現成的 WFP-based transparent proxy/filtering SDK——**買它就省掉自寫核心驅動** |
| **WinDivert** | 開源(LGPL,簽章驅動)| user-mode 封包 divert,原型首選 |
| **自寫 WFP callout 驅動** | 微軟原生 API | 最大控制、最穩,但最花工 + 要 EV 簽章 |

### 1.3 開源參考實作

| 專案 | 說明 |
|---|---|
| **HttpFilteringEngine**(TechnikEmpire)| **Windows 上用 WinDivert 的 transparent filtering TLS proxy**——最直接的參考 |
| **SSLsplit**(droe)/ **SSLproxy**(sonertari)| transparent SSL/TLS 攔截的經典模型(主要 Linux/BSD,但架構通用)|
| **InterceptSuite** | Non-HTTP MITM proxy,**宣稱涵蓋 TCP/TLS/DTLS/QUIC**——QUIC MITM 屬前沿嘗試 |
| **ProxyBridge**(InterceptSuite)| 把 Windows TCP/UDP 依 app 導到 SOCKS5/HTTP proxy |
| **sni-proxy**(vstakhov)| **不做 MITM、不需憑證**——只依 SNI 路由(見 §6 的 no-CA 替代)|

**小結**:transparent 端點 TLS 攔截**不是可行性未知的東西,而是一個成熟產業的標準架構**。真正的問題不是「行不行」,而是「**你願不願意付驅動 + QUIC + ECH 的複雜度成本,以及這些成本相對 explicit 值不值得**」。

---

## 2. 要解決的三個子問題

| 子問題 | 內容 |
|---|---|
| **A. 重導** | 把外送 TCP:443 導進本機 proxy(client 不知情)|
| **B. 消滅 QUIC** | 讓沒有東西從 UDP:443 溜走(否則盲區)|
| **C. 認得目標** | 沒有 CONNECT,要還原原始目的地 IP + **host 名稱**(偽造憑證用)——**卡在 ECH** |

---

## 3. 子問題 A:重導 — 三個實作層級

### A1. 自寫 WFP connect-redirect callout 驅動(原生、最穩)★ 產品級
Windows Filtering Platform 內建的 **ALE connect-redirect**,**Microsoft 官方文件明講就是給 TLS inspection 用的**(Win7+,本機重導 Win8+):

- callout 在 `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4/V6` 把連線重導到本機 proxy(loopback),填 `localRedirectTargetPID` + `localRedirectHandle`,把**原始目的地存進 `localRedirectContext`**。
- proxy 用 `WSAIoctl` 查 **`SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT`** 拿**原始目的地 IP:port**,再用 `SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS` 在對外 socket 關聯連線。
- **支援 TCP 與 UDP**;`FwpsQueryConnectionRedirectState0` 防無限重導。
- 優點:原生、無 Wi-Fi 限制、微軟背書、拿得到原始目的地。缺點:C 核心驅動、EV 簽章、開發複雜。

### A2. NetFilter SDK(商用捷徑)★ 想省事又要穩
**現成的商用 WFP SDK**——把「重導 + 原始目的地還原」封裝好,**免自寫核心驅動**。代價是授權費。多數不想碰核心的商用產品走這條。

### A3. WinDivert(user-mode,快速原型)★ PoC 用
user-mode 封包 divert(底層是簽章 WFP 驅動),把 TCP:443 重導到 loopback。

- 優點:純 user-mode、prebuilt 驅動已簽章、上手快、有 HttpFilteringEngine 可參考。
- 缺點:**防毒常誤標**;**Wi-Fi 介面卡有已知限制**(某些 Wi-Fi driver 邊界跨不過去,實測有人栽在這);商用要自簽驅動;封包重注要自己處理。

---

## 4. 子問題 B:消滅 QUIC — 兩路(且有 Zscaler 背書)

### B1. Chrome 政策 `QuicAllowed=false`(受管端點)★ 最乾淨
GPO / 登錄 `Software\Policies\Google\Chrome\QuicAllowed=0` → **Chrome 完全不用 QUIC**。優點:乾淨、無延遲。缺點:只管 Chrome/Edge;**且若你已能推政策,不如直接推 explicit proxy 政策**(見 §8)。

### B2. 封 UDP:443(網路層)★ 涵蓋所有 app,產業最佳實務
**Zscaler 官方明列為最佳實務**:「**封 QUIC → fallback TCP → 開 TLS inspection**」,並明說「**不影響使用者體驗**」。三種做法:防火牆封 UDP 80/443 / Zero Trust Firewall 規則 / 瀏覽器政策。

- 優點:對**所有** app 生效;產業驗證過的做法。
- 缺點:首連有 fallback 暖機延遲;要封得完整。
- **註**:QUIC 目前「無法像 TCP 那樣被檢查」是普遍現況;但**原生 QUIC 檢查正在成形**(Zscaler 宣稱目標 2025 推出、InterceptSuite 也在嘗試)——中長期 QUIC 未必永遠只能封。

---

## 5. 子問題 C:認得目標 —— ECH 是最硬的關卡

- **原始目的地 IP:port**:WFP 原生給(`ORIGINAL_DESTINATION`);WinDivert 靠 tuple 追蹤。**已解決**。
- **host 名稱**(偽造憑證要填正確 SAN):**得偷看 TLS ClientHello 的 SNI**。
- ⚠️ **ECH(Encrypted Client Hello)已在 Chrome 預設啟用,會把 SNI(乃至整個 ClientHello 大部分)加密** → SNI-peek 失效 → 認不出 host。ECH 是 TLS 擴充,**跟走 TCP/QUIC 無關**,逼到 TCP 也一樣加密。

### 產業怎麼打 ECH:Cisco 三層策略(直接可抄)
1. **Layer 1 — DNS 控制(首要防線)**:ECH 的公鑰/參數是透過 **DNS 的 HTTPS/SVCB record** 派發的。**封掉加密 DNS(DoH/DoT/DoH3/DoQ)+ 擋掉 HTTPS/SVCB record**(resolver scrubbing 或防火牆規則)→ 瀏覽器拿不到 ECH config → **退回明文 SNI**。
2. **Layer 2 — 端點管理**:在受管裝置直接推**瀏覽器政策停用 ECH + 加密 DNS**(`EncryptedClientHelloEnabled=0`),從源頭關掉。★ 對受管端點最乾淨。
3. **Layer 3 — 選擇性解密 + 偵測(不可靠,當兜底)**:對仍用 ECH 的連線,廠商宣稱可用「**Decrypt-Resign**」剝掉 ECH 擴充觸發「secure disable」讓 client 退回明文 SNI。**但這招不可靠**:ECH 的外層 SNI 是 **decoy `public_name`(誘餌網域,如 CDN 名),不是真網域**,而且 ECH 有**反降級**設計,剝掉後 client 可能改用 retry-config 重試、或只暴露誘餌名,**不保證吐出真 SNI**。所以 Layer 3 只當兜底;無法解密的連線改用 **EVE(process fingerprinting)** 辨識來源程序做異常偵測。

> **對「受管端點」的實務結論**:靠 **Layer 2(政策停 ECH)** 就乾淨解決——你控制瀏覽器,直接關掉 ECH,SNI 恢復明文,不必碰不可靠的 Layer 3。
>
> **關鍵限制(Cisco 自己講的,和本研究一致)**:「**這只在 client 信任該防火牆的 CA 時有效——對訪客/非受管裝置無效。**」→ 再次印證:**ECH 對策 = 受管端點才玩得動。**

> **對比 explicit**:explicit 從 `CONNECT chatgpt.com:443` 直接拿到明文 host,**天生免疫 ECH**,不必碰 DNS/政策那一整套。這是 transparent 額外要流血的地方。

---

## 6. CA 的角色 + no-CA 替代

- **CA 一樣要**,信任機制和 explicit 完全相同(裝進 OS Trusted Root;對本機安裝的根,Chrome 跳過 pinning/CT)。QUIC fallback 沒省掉 CA,只是給 CA 一個 TCP 場地。
- **no-CA 替代(順帶一提)**:若你**只要「依網域放行/阻擋」而非看內容**,可用 **SNI-only proxy**(如 `sni-proxy`)——解析 SNI 決定路由/擋掉,**不需要憑證、不做 MITM**。但這是**全站阻擋**,**做不了「看 prompt、只有含卡號才擋」的內容型 DLP**。ECH 一開,連 SNI 都看不到,這招也會失效。

---

## 7. 可行性評分

| 情境 | 重導 (A) | 消滅 QUIC (B) | 認得 host / ECH (C) | 整體 |
|---|---|---|---|---|
| **受管端點(GPO/Intune)** | WFP callout / NetFilter SDK / WinDivert | 政策 `QuicAllowed=0` 或封 UDP:443 | 政策 `EncryptedClientHelloEnabled=0` + SNI-peek(Cisco Layer 2)| ✅ **可行且有產業先例**(政策把 B、C 變簡單,你只要重導 + CA)|
| **非受管端點** | 同上 | 網路封 UDP:443(有延遲)| 封 DNS HTTPS record + 剝 ECH downgrade(脆弱、且需 CA 信任)| ⚠️ **可行但脆弱**(多個網路/DNS hack;無 CA 信任時整套失效)|

---

## 8. 和 explicit 的成本對比 + 定位建議

**關鍵矛盾**:transparent 壓制 QUIC 和 ECH **最乾淨的手段都是「推 Chrome 政策」**——但**你若已能推政策,直接推 explicit proxy 政策(`ProxyMode=fixed_servers`)反而更簡單**,而且 explicit **免費**拿到:棄 QUIC、host 從 CONNECT(免疫 ECH)、無驅動。

所以 transparent 的**唯一不可替代價值**是:**攔到「不理會 proxy 設定的 app」**(curl、桌面/Electron AI app、以及像 Netskope 那樣「不想在整個 fleet 設 per-app proxy」的情境)——這是 explicit 覆蓋不到的。

**建議定位**:

| 層 | 技術 | 攔什麼 |
|---|---|---|
| **主力(現有 endpoint 專案)** | explicit proxy(受管政策)| 瀏覽器,乾淨棄 QUIC,免疫 ECH |
| **補網(這份研究的產物)** | transparent(WFP/NetFilter 重導 + 封 UDP:443 + 停 ECH)| 不理會 proxy 的 app |

兩者**共用同一套 MITM 引擎 + CA + DLP**,只換「進料前門」。

---

## 9. PoC 路線圖

**原型(1–2 週,驗證概念):**
1. **WinDivert** 重導 TCP:443 → loopback,同時**丟棄 UDP:443**。
2. proxy 端新增「**無 CONNECT 入口**」:拿原始 dst、**偷看 SNI** 得 host(現有程式靠 CONNECT,transparent 走 SNI)。
3. 開發機推 `EncryptedClientHelloEnabled=0`(+ 可選 `QuicAllowed=0`)排除 ECH/QUIC 干擾。
4. host 拿到後,**沿用現有的 `ca.py` 偽造憑證 + `dlp/` + 串流轉發**——引擎不動。
5. 參考 **HttpFilteringEngine** 的 WinDivert 用法。

**產品(數月,穩定):**
- 改用 **WFP connect-redirect callout 驅動**(或買 **NetFilter SDK** 省事),EV 簽章。
- 受管政策一併推 `QuicAllowed=0` + `EncryptedClientHelloEnabled=0`。
- ECH 殘留連線用 Cisco Layer 1/3(封 DNS HTTPS record / 剝 ECH downgrade)兜底。

---

## 10. 風險清單

| 風險 | 說明 |
|---|---|
| **驅動簽章** | WFP callout 要 EV/attestation 簽章;WinDivert 商用要自簽;NetFilter SDK 要授權費 |
| **防毒誤標** | WinDivert 常被 AV 標記 |
| **Wi-Fi 限制** | WinDivert 在某些 Wi-Fi 介面卡跨不過 driver 邊界(WFP callout / NetFilter 無此問題)|
| **ECH 軍備競賽** | ECH 預設開、持續演進;靠政策/DNS 壓制是持續維護成本;**訪客/非受管裝置無解** |
| **核心穩定性** | 核心驅動 bug = BSOD 風險 |
| **fallback 延遲** | 封 UDP 後首連有 QUIC 暖機延遲 |
| **全域副作用** | 封 UDP:443 影響所有 app |
| **法規/隱私** | 全機 MITM 解密的合規範圍要界定清楚(端點模式尤其)|

---

## 11. 信心水準與待驗證項(誠實揭露)

| 判斷 | 信心 | 備註 |
|---|---|---|
| transparent 端點 TLS 攔截「可行且成熟」 | **高** | 有 Zscaler/Netskope/多家 DLP 生產先例 |
| 封 UDP:443 → Chrome fallback TCP | **高** | Zscaler 官方最佳實務,多來源一致 |
| 受管裝置可用政策停 ECH(SNI 恢復明文)| **高** | `EncryptedClientHelloEnabled` 官方政策 + Cisco Layer 2 |
| WFP connect-redirect 能拿原始目的地 | **高** | Microsoft 官方文件 + 範例碼 |
| 「剝 ECH → client 重試明文 SNI」downgrade | **中** | Cisco 明列,但 ECH 反降級機制隨版本演進,需實測 Chrome 當前行為 |
| 非受管裝置的 ECH 兜底(封 DNS record)長期有效 | **中低** | DoH/DoH3 普及 + ECH 演進會侵蝕此招;訪客裝置本就無 CA 信任 |
| native QUIC 檢查何時成熟 | **低** | Zscaler 宣稱 2025、InterceptSuite 嘗試中,尚未成產業標準 |

**建議先做的最小驗證**:在一台受管測試機推 `QuicAllowed=0` + `EncryptedClientHelloEnabled=0`,用 WinDivert 重導 TCP:443,確認(a)Chrome 全走 TCP、(b)SNI 明文可見、(c)你現有的 CA-MITM 引擎能接手解密——這三點過了,產品化就只剩「換 WFP 驅動 + 簽章」。

---

## 12. 一句話總結

> **完全可行,而且是產業標準做法——Zscaler、Netskope、Forcepoint 等都在端點做這件事。他們處理 QUIC 和 ECH 的方式(封 UDP:443 逼 TCP、受管裝置停用/降級 ECH)正是本研究的結論,而且明確只在「裝置信任你的 CA」時成立。但這些壓制手段最乾淨的做法都是推政策,而推政策的話 explicit 更省事又免費解掉 QUIC/host/ECH。所以 transparent 的價值在「補 explicit 攔不到的非瀏覽器 app」,該當 catch-all 疊加層,不是取代 explicit。CA 從頭到尾都省不掉——fallback 只是給 CA 一個能工作的 TCP 場地。**

---

## 參考來源

**商用端點 TLS 攔截 / QUIC / ECH**
- Zscaler QUIC 最佳實務(封 QUIC → TCP,不影響體驗):https://www.zscaler.com/blogs/product-insights/quic-secure-communication-protocol-shaping-future-of-internet
- Zscaler TLS/SSL Inspection 參考架構:https://www.zscaler.com/resources/reference-architectures/tls-ssl-inspection-zscaler-internet-access.pdf
- Netskope client steering(不需 proxy 設定,OS 較低層導流):https://community.netskope.com/additional-discussions-9/netskope-client-steering-traffic-1275
- Netskope SSL/TLS inspection:https://www.netskope.com/platform/ssl-tls-inspection
- Cisco Secure Firewall 的 ECH 三層對策:https://secure.cisco.com/secure-firewall/docs/encrypted-client-hello-defense-strategies-how-cisco-secure-firewall-tackles-ech
- ECH 背景(CDT):https://cdt.org/insights/encrypted-client-hello-closing-the-sni-metadata-gap/
- 端點 DLP 產品盤點(Nightfall):https://www.nightfall.ai/blog/the-top-10-windows-dlp-solutions-of-2025-and-30-faqs-every-security-team-should-know

**Windows 攔截技術 / 建構元件**
- WFP connect/bind redirection(Microsoft 官方):https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection
- WFP proxied connections tracking(Microsoft):https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-proxied-connections-tracking
- NetFilter SDK(商用 WFP SDK):https://netfiltersdk.com/nfsdk.html
- WinDivert(官方):https://reqrypt.org/windivert.html ・文件 https://reqrypt.org/windivert-doc.html
- WinDivert Wi-Fi 限制實例:https://dev.to/chronocoders/why-my-windows-transparent-proxy-failed-on-wi-fi-and-worked-on-ethernet-3f6e

**開源參考實作**
- HttpFilteringEngine(WinDivert transparent TLS proxy):https://github.com/TechnikEmpire/HttpFilteringEngine
- SSLsplit:https://github.com/droe/sslsplit ・SSLproxy:https://github.com/sonertari/SSLproxy
- InterceptSuite(TCP/TLS/DTLS/QUIC MITM):https://interceptsuite.com/
- ProxyBridge(重導 TCP/UDP 到 proxy):https://github.com/InterceptSuite/ProxyBridge
- sni-proxy(no-CA、依 SNI 路由):https://github.com/vstakhov/sni-proxy

**Chrome 政策**
- `QuicAllowed`(停用 QUIC):https://issues.chromium.org/issues/41159437
- `EncryptedClientHelloEnabled`(停用 ECH):https://chromeenterprise.google/policies/encrypted-client-hello-enabled/
- 停用 ECH 的理由與方法(Chaser Systems):https://chasersystems.com/blog/disabling-encrypted-clienthello-in-google-chrome-and-why/

---

## 附錄:術語說明(較少見的技術用詞)

### 攔截 / 網路堆疊
- **MITM(Man-in-the-Middle,中間人)**:攔在 client 與伺服器之間、解密再重新加密的角色。做內容檢查的必要手段。
- **Transparent proxy(透明代理)**:client **不知情**、不需設定,流量在網路層被就地重導攔截。相對於 **explicit proxy(顯式代理)**——client 被明確設定指向 proxy、會送 `CONNECT`。
- **WFP(Windows Filtering Platform)**:Windows 內建的封包/連線過濾框架,防火牆、EDR、VPN、TLS 檢查產品都建構在它之上。
- **ALE(Application Layer Enforcement)**:WFP 裡「連線建立」層級的過濾層(如 `ALE_CONNECT_REDIRECT`),能在應用程式發起連線時檢查/重導,拿得到程序、位址等資訊。
- **Callout driver**:註冊到 WFP 的核心模式驅動,可對封包/連線做「檢查、放行、擋、重導」等自訂動作。
- **Connect-redirect / bind-redirect**:WFP 的重導功能——把應用程式原本要連的目的地改成本機 proxy(connect 層影響單一連線,bind 層影響整個 socket)。
- **`SO_ORIGINAL_DST`**:透明攔截後,proxy 用來「還原 client 原本想連的目的地 IP:port」的機制(Linux 用語;Windows 對應 WFP 的 `ORIGINAL_DESTINATION` metadata)。
- **NDIS LWF(Lightweight Filter driver)**:網路卡附近(L2/L3)的過濾驅動,看到的是**原始封包**;適合擷取/VPN,**不適合**做 MITM(要自己重組 TCP/TLS)。
- **WinDivert**:user-mode 封包攔截/改寫函式庫,底層是一張簽章的 WFP 驅動;做 Windows 透明攔截原型最快,但常被防毒誤標。
- **NetFilter SDK**:商用的 Windows WFP 過濾/透明 proxy SDK,買它可省掉自寫核心驅動。
- **Loopback**:本機回送位址(127.0.0.1);重導到本機 proxy 就是導到 loopback。

### 協定 / TLS
- **QUIC / HTTP-3**:Google 主導、跑在 **UDP** 上、把傳輸與 TLS 1.3 綁在一起的協定。傳統 TCP proxy 攔不到,是本研究的核心難題。
- **ALPN(Application-Layer Protocol Negotiation)**:TLS 握手時協商「握手後要講哪個應用協定」(如 `h2`、`http/1.1`)的擴充。本專案把它鎖成 `http/1.1` 以免自己解 HTTP/2 frame。
- **SNI(Server Name Indication)**:TLS ClientHello 裡**明文**標示「我要連哪個網域」的欄位;透明 proxy 靠偷看它得知目標 host。
- **ECH(Encrypted Client Hello,前身 ESNI)**:把 SNI(乃至整個 ClientHello 大部分)**加密**的 TLS 擴充,讓中間人看不到目標網域。已在 Chrome 預設啟用,是透明攔截最大的變數。
- **HTTPS / SVCB DNS record**:新式 DNS 記錄,用來派發網站的連線參數,**包括 ECH 的公鑰**。擋掉它,瀏覽器就拿不到 ECH config → 退回明文 SNI。
- **DoH / DoT / DoH3 / DoQ**:加密 DNS(DNS over HTTPS / TLS / HTTP-3 / QUIC)。會把 DNS 查詢藏起來,連帶讓 ECH config 難以攔截。
- **CONNECT method**:顯式 proxy 專用的 HTTP 方法——client 送 `CONNECT host:443` 告訴 proxy 要建往哪的通道;proxy 因此直接知道 host(免疫 ECH)。
- **DTLS**:跑在 UDP 上的 TLS(Netskope 的 client tunnel 會用到)。

### 憑證信任
- **CA / Root CA / leaf 憑證**:CA 是「憑證簽發者」;Root CA 是信任鏈頂端;leaf 是實際出示給瀏覽器的網站憑證。MITM 就是用自己的 CA **即時簽 leaf** 冒充網站。
- **Certificate pinning(憑證釘選)**:網站或瀏覽器把「只接受某些憑證」寫死。**HPKP**(網站自釘)已被 Chrome 移除;Chrome 對某些 Google 網域有**內建 static pin**——但**對「本機安裝的根」會刻意停用 pin**(企業 MITM 豁免)。
- **CT(Certificate Transparency)**:要求公開信任的憑證登錄到公開 log。**對本機安裝的根同樣停用**——所以你的偽造憑證不用進 CT。
- **EV / attestation 簽章**:核心驅動要能載入,必須用高等級憑證(EV 或微軟 attestation)數位簽章。
- **GREASE**:在協定裡故意塞「保留/隨機值」以防中間設備僵化(ossification);ECH 有 GREASE 機制來偵測/抵抗降級。

### 產業對策 / 其他
- **Decrypt-Resign**:TLS 檢查設備「解密後用自己的 CA 重簽」再轉發的動作(= 就是 MITM 的產業講法)。
- **ECH「secure disable」/ 反降級**:ECH 設計用 `public_name`(誘餌網域)當外層 SNI + 加密內層真 SNI,並有反降級確認。廠商宣稱「剝掉 ECH 擴充可讓 client 退回明文 SNI」,但**不可靠**——實際可能只暴露誘餌名或觸發 retry-config 重試,**不保證吐出真網域**。受管端點應改用政策直接停用 ECH。
- **EVE(Encrypted Visibility Engine)**:Cisco 的技術,對**無法解密**的連線用「來源程序指紋」判斷是 Chrome 還是惡意程式,做異常偵測。
- **Domain fronting(網域偽裝)**:SNI 與 HTTP `Host` 標頭不一致以規避阻擋;產業會偵測這種不一致。
- **SWG(Secure Web Gateway)**:安全網頁閘道——做 URL 過濾 + TLS 檢查 + DLP 的產品類別(Zscaler、Netskope 屬此)。
- **DLP(Data Loss Prevention)**:資料外洩防護——本專案的目的。
- **fail-open / fail-closed**:遇到無法處理的情況時「放行(open)」還是「擋掉(closed)」的政策取向。
- **BSOD(Blue Screen of Death)**:Windows 藍屏當機;核心驅動 bug 的最壞後果。
- **broken-QUIC detection**:Chrome 偵測到 QUIC 連不通後,一段時間內改走 TCP、不再嘗試 QUIC 的行為(封 UDP 後的「暖機」現象)。
