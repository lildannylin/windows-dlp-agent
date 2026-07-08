# 技術架構與設計解析：Windows AI-DLP 端點 Proxy

這份文件解釋這個專案**用了什麼技術、解了什麼問題、和一般 MITM proxy 差在哪、
CA 從哪來、以及有哪些繞過方式**。內容大量取自實作過程中在真實 Chrome / ChatGPT
上跑出來的實測結果。

> 一句話定位：這是一個**跑在每台 Windows 端點上的本機 MITM proxy**,用來在使用者把
> 敏感資料貼進 AI 網站(ChatGPT / Claude / Gemini)**送出之前**攔截、判斷、擋下,並由
> agent 彈系統通知。

---

## 1. 它解決什麼問題

### 1.1 核心問題:AI 資料外洩(AI-DLP)
員工把公司機密、客戶個資、API 金鑰、信用卡號等貼進 ChatGPT 這類 AI 網站,資料就離開了
組織的控制。傳統 DLP 大多看檔案傳輸或郵件,對「瀏覽器裡貼一段文字送給 AI」這條路缺乏
在**送出前**攔截的能力。這個專案就是補這一塊:在**離開這台機器之前**做偵測 → 擋下 → 通知。

### 1.2 真正的技術難題:QUIC
要看到 HTTPS 內容就得解密,要解密就得做 MITM。但**現代瀏覽器對 Google 系服務大量走
QUIC / HTTP-3**(跑在 **UDP** 上),而 QUIC:

- **不經過傳統 HTTP proxy**(proxy 是 TCP 概念,QUIC 是 UDP);
- 憑證/金鑰機制和 TCP TLS 不同,一般的 CA MITM 對 QUIC 無效;
- 用透明攔截(WFP)硬攔,Chrome 仍會嘗試 QUIC 撞牆,體驗與可靠性都差。

**如果不解決 QUIC,就等於有一大塊流量看不到、擋不到。**

### 1.3 這個專案的關鍵洞見(整個設計的基石)
> **只要用「顯式 proxy 設定」把瀏覽器指向本機 proxy,Chrome 就會自動放棄 QUIC、全部退回
> HTTP/2 over TCP。**

因為 HTTP-3(QUIC)**不經傳統 proxy**,Chrome 一偵測到有設 proxy,就不發 QUIC。於是:

- QUIC 問題**自動消失**——不用封鎖 QUIC、不用寫 kernel driver、不用碰 UDP;
- 剩下的全是 TCP 上的 TLS,用**已安裝的 CA** 就能正常 MITM。

**這一點我們實測證明過**(見 §9),不是理論推測。

---

## 2. 技術堆疊

| 層面 | 用的技術 | 為什麼 |
|---|---|---|
| 非同步網路伺服器 | **Python `asyncio`**(`start_server` / `StreamWriter.start_tls`)| 單執行緒事件迴圈撐大量並發連線;3.11+ 可就地把既有連線升級成 TLS |
| TLS 終止 + 依 SNI 換憑證 | **`ssl`** 模組(`SSLContext` + ALPN)| 握手時依 SNI host 換上偽造憑證;**ALPN 只提供 `http/1.1`** 讓瀏覽器跟我們走 HTTP/1.1,免解 HTTP/2 frame |
| 憑證產生 / 即時偽造 | **`cryptography`** | 產自簽 root CA;per-host 簽發 leaf 憑證並快取 |
| HTTP/1.1 解析 | **`h11`**(sans-IO)| 純狀態機,把 bytes 餵進去拿事件出來,和 asyncio 解耦,最省事 |
| 向上游轉發 | **`httpx[http2]` + `h2`** | async、支援 HTTP/2、支援**串流**(`client.stream()` + `aiter_raw()`)|
| DLP 引擎 | 自寫 `re` + checksum + 熵;(可外掛 **Presidio**)| 結構化 pattern + 檢查碼誤判極低;熵抓無格式 secret |
| 桌面通知 | **`windows-toasts`**(非 Windows 自動降級)| 命中時彈系統 toast,不注入瀏覽器頁面 |
| 常駐服務 | **pywin32** 或 **NSSM** | 開機自啟、崩潰自動重啟 |
| 強制部署 | Windows 受管政策(`.reg` / GPO / Intune)、`certutil` | 鎖死 proxy 設定、把 CA 裝進信任存放區 |
| 觀測驗證 | Chrome `--log-net-log`、Windows `pktmon` | 證明 QUIC 有沒有走(見 §9)|

**設計原則**:「從頭用 Python 刻這個 MITM proxy,但用成熟函式庫處理 TLS/憑證/HTTP,
不重造輪子。」`mitmproxy` 只當**原型驗證與參考**,產品本身是自寫的(理由見 §5)。

---

## 3. 端到端運作流程

```
Windows 端點
┌────────────────────────────────────────────────────────────────────┐
│  Chrome/Edge(受管政策 → proxy=127.0.0.1:8888)                       │
│    │  設了 proxy → Chrome 棄 QUIC → 全部 HTTP/2 over TCP              │
│    ▼                                                                 │
│  本機 MITM proxy (asyncio)                                           │
│    1. 收 CONNECT host:443 → 回 200 Connection Established            │
│    2. 對 client 做 TLS 握手,用 CA 即時偽造 host 憑證(ALPN=http/1.1) │
│    3. h11 解密解析 HTTP/1.1 request                                  │
│    4. 是 AI 網域的 prompt 端點? → 抽 prompt → DLP 判斷              │
│         命中 → 回 451、不轉發(資料從未離開本機)→ toast + 稽核     │
│         放行 → httpx 連真站、串流轉發回應                            │
│    5. 是 WebSocket 升級? → 依政策 relay(雙向透傳)或 block         │
│                          │                                          │
│                          ▼                                          │
│                 Windows 系統通知 (toast)                            │
└────────────────────────────────────────────────────────────────────┘
```

**關鍵順序**:DLP 判斷在**轉發之前**。命中就直接回 451,**真站永遠收不到那個請求**——
敏感資料一個 byte 都沒離開機器。這也是為什麼日誌上被擋的請求**不會**有對上游的紀錄
(這反而是它被擋在轉發前的證明)。

---

## 4. CA 怎麼來的

這是整個 MITM 能不能成立的核心。

### 4.1 為什麼需要 CA
要看 HTTPS 內容就得終止 client 的 TLS,而終止 TLS 就要**冒充目標網站出示憑證**。瀏覽器
會驗這張憑證的簽發者是不是它信任的 CA。所以我們得:**自己當一個 CA,簽出各網站的假憑證,
再讓端點信任這個 CA。**

### 4.2 CA 是「自己當場產生」的,不是外來的
`ca.py` 的 `CertificateAuthority`:

- **`generate()`**:用 `cryptography` 產一張自簽 root CA——RSA 2048、CN =
  `Windows DLP Agent Root CA`、`BasicConstraints(ca=True)`、含 KeyUsage/SKI。
- **`load_or_generate(ca_dir)`**:第一次跑時若該目錄沒有 CA 就產一張並存檔;之後載入同一張。
  → 這是規格的**「選項 B:新專案自己產一張 root CA」**,不牽涉任何外部/路由器憑證,
  私鑰全程只在本機。
- **`forge_leaf(host)`**:針對每個 SNI host **即時簽發** leaf 憑證(含該 host 的
  SAN),用 CA 私鑰簽。
- **`context_for(host)`**:把偽造 leaf 包成 `SSLContext`,**ALPN 鎖 `http/1.1`**,並**快取**
  (同一 host 只簽一次)。握手時 `ssl` 依 SNI 叫這個 context。

### 4.3 端點怎麼「信任」這張 CA
偽造憑證要被接受,root CA 必須進端點的信任存放區:

- 測試:`certutil -user -addstore -f Root proxy-ca.crt`(當前使用者,免系統管理員)
- 產品:機器存放區(需管理員)或用 `deploy-bundle` 產生的 `install.ps1`,透過 GPO/Intune 推。

裝好之後,Chrome 就會接受我們對每個網站簽出來的假憑證——**實測 Chrome 載入真實網站、
解密真實流量都成功**(§9)。

### 4.4 CA 的安全性(要害)
- **CA 私鑰 = 皇冠上的寶石**:拿到它的人就能對這台(信任它的)機器上所有 HTTPS 做 MITM。
  必須嚴格保密,**絕不進 git**(`.gitignore` 已排除 `*.key` / `*.pem` / `ca/` / `certs/`)。
- **同名 CA 衝突陷阱(實作中踩過)**:我們所有 CA 的 CN 都叫 `Windows DLP Agent Root CA`。
  若信任存放區裡殘留一張**同名但不同金鑰**的舊 CA,`ssl.create_default_context()` 驗證時
  可能挑錯那張 → `certificate signature failure`。啟示:正式部署**每台一張、重裝先移除舊的**,
  或給 CA 帶唯一序號/名稱。

---

## 5. 和「一般 MITM proxy」差在哪

「MITM proxy」是一種**技術**(攔在中間、解密、看內容);`mitmproxy` 是一個**通用工具**。
這個專案**用了 MITM 技術,但它是一個 DLP 強制代理**,不是通用攔截器。差別:

| 面向 | 一般 MITM proxy(如 mitmproxy)| 本專案 |
|---|---|---|
| **目的** | 通用攔截/檢視/改寫,給人除錯、研究 | **DLP 政策強制**:偵測→擋→通知→覆寫→稽核 一條龍 |
| **檢查範圍** | 預設看**所有**流量 | **只檢查認得的 AI prompt 端點**;其他一律放行(不這樣做會擋爆整個網路,見 §9)|
| **QUIC 處理** | 一般不主動處理,透明模式常撞 QUIC | **刻意用顯式 proxy 逼 Chrome 棄 QUIC**——這是架構決策,不是自動發生 |
| **client 協定** | 常需支援 HTTP/2 | **ALPN 鎖 http/1.1**,client 端不必解 HTTP/2 frame(上游 HTTP/2 交給 httpx)|
| **回應處理** | 一般透傳 | **擋在轉發前**;放行則**串流**;WebSocket 有 **relay/block 政策** |
| **部署定位** | 開發者手動跑的工具 | **端點常駐服務 + 受管政策**,使用者改不掉(不可繞過為目標)|
| **實作** | 現成 runtime,擴充靠 addon | **自寫精簡 Python**(可控、可嵌入、無 mitmproxy runtime 依賴);mitmproxy 只當 spike/參考 |

**一句話**:mitmproxy 回答「我能看到並改這些流量嗎」;本專案回答「這段內容能不能送給這個
AI,不能就在它離開機器前擋下並通知」。

---

## 6. DLP 偵測引擎

分層設計,精準度高→低,動作對應風險(`dlp/engine.py`):

1. **結構化 pattern + 檢查碼**(誤判極低)→ **硬擋(block)**
   - 信用卡(Luhn)、台灣身分證(加權碼)、統一編號(加權digit-sum)、
     API key 前綴(`sk-`、AWS `AKIA`、GCP `AIza`、GitHub `ghp_`…)、JWT、PEM 私鑰、DB 連線字串。
2. **高熵(Shannon entropy)**→ 抓無固定格式的 secret/token → **warn**
3. **關鍵字/字典**(`機密`、`營業秘密`、confidential…)→ **warn**
4. **(可外掛)Presidio / NER** → 自由文本 PII

**精準度分流(§4.3)**:
- 結構化+檢查碼(幾乎不誤判)→ **block**(硬擋)
- 啟發式/熵/ML(可能誤判)→ **warn-with-override**(先擋 + 通知,使用者可一次性核准放行)
- 動作(block / warn / redact)由政策依資料類型決定,可更新。

**遮罩原則**:命中片段在 toast、稽核、除錯 log 裡**一律遮罩**(如 `4111…11`),
**明文永不落地**——稽核檔本身不能變成外洩點。

---

## 7. 回應通道:串流與 WebSocket

早期版本把上游回應**整包緩衝**才回傳,導致 ChatGPT 的逐字回覆會「停頓後一次跳出」。
現在:

- **串流透傳**:`_forward` 用 `httpx` 的 `client.stream()` + `aiter_raw()`,chunk 一到就以
  HTTP/1.1 chunked 轉給瀏覽器,並保留原始 content-encoding 原樣轉發。→ 回覆逐字順跑(實測驗過)。
- **WebSocket 政策**:登入態 ChatGPT 用 `wss://ws.chatgpt.com/...` 收即時訊息,而 h11 無法
  代理 WS 升級。偵測到 `Upgrade` 握手時:
  - **`relay`(預設,fail-open)**:開一條 TLS 到上游、重播握手、把解密後的位元組**雙向透傳**
    (任一端關閉就收工)。
  - **`block`(fail-closed)**:直接拒絕升級,更安全但會弄壞 WS 網站。

**fail-open 是不是破口?** 對 ChatGPT **不是**——因為使用者的 prompt 是走 **HTTP POST**
送出的(我們照樣攔),WS 主要用來**收**。一般情況下,若某 app 把輸入**透過 WS 送出**,
fail-open 就不會檢查那條通道(這是已知取捨);因為中繼走的是「解密→重加密」的 MITM 形狀,
**未來可在此加 WS frame 層 DLP** 把 WS 送出的內容也掃進來。

---

## 8. 強制與「怎麼繞過」(涵蓋範圍與限制)

誠實列出這套機制**攔不到什麼、可以怎麼繞過**——這對評估防護強度很重要。

### 8.1 強制手段(讓它難以繞過)
- **受管 proxy 政策**:Chrome/Edge `ProxyMode=fixed_servers` + `ProxyServer=127.0.0.1:8888`,
  透過 GPO/Intune 推,**使用者在瀏覽器設定裡改不掉**。
- **CA 裝進機器存放區**、proxy 以**常駐服務**開機自啟、崩潰自動重啟。
- 無痕模式一樣走 proxy、一樣被擋。

### 8.2 繞過方式 / 涵蓋不到的地方
| 繞過途徑 | 說明 | 對策 |
|---|---|---|
| **不理會 proxy 設定的程式** | curl、桌面版 AI app、部分 Electron app 不吃系統/瀏覽器 proxy → 不經過我們 | §附錄的 **WFP/WinDivert catch-all**(後期選配,攔 UDP/所有流量)|
| **QUIC(若 proxy 沒設)** | 一旦 proxy 被取消,Chrome 就改走 QUIC 繞過我們 | 受管政策鎖死 proxy,使用者改不掉 |
| **不信任/移除 CA** | 若 CA 不在信任存放區,偽造憑證被拒 → HTTPS 直接失敗(某種 fail-closed);但也代表擋不了「看內容」 | CA 由政策強制安裝、一般使用者無權移除 |
| **憑證釘選(pinning)** | 有些 app 釘選特定憑證,會拒絕我們的偽造憑證 → 連線失敗、無法 MITM | 對這類流量只能選擇放行或封鎖,無法檢查 |
| **程式/API 型呼叫** | app 直接打 `api.openai.com`(不是瀏覽器)→ 內容是程式產生的,雖然也可能經 proxy,但語意不同 | 用 **LiteLLM** 這類 LLM gateway 另管(互補路線)|
| **WebSocket 送出(fail-open 下)** | 若輸入透過 WS 送出,relay 政策不檢查 | 改 `--websocket block`,或做 WS frame 層 DLP |
| **偵測規避(evasion)** | 使用者把卡號拆成多則、base64 編碼、塞進圖片(需 OCR)、改寫格式繞過 regex | 多層偵測(熵/關鍵字/ML)提高難度,但非萬無一失 |
| **沒裝 agent 的機器** | 端點模式的本質:只保護裝了它的那台 | 逐台部署(無互動 installer 批次推)|

**設計立場**:這套機制對「一般員工用瀏覽器貼資料進 AI 網站」這個**最常見、最主要**的
外洩路徑防護力很強;對「刻意規避的進階使用者」或「非瀏覽器管道」則需搭配 catch-all 與
gateway 才完整。DLP 是**降低風險**,不是**絕對圍堵**。

---

## 9. 實測發現(在真實 Chrome / ChatGPT 上跑出來的)

這些不是理論,是實作過程中量到的:

- **QUIC 自動棄用(核心前提)**:用 Chrome `--log-net-log` 對 youtube 做 A/B——
  - 直連:**QUIC 封包送出 7,403、收到 33,203**,197 條 QUIC 連線,UDP socket 事件 41,034。
  - 走 proxy:**QUIC 封包 0 / 0**,只有 7 個 `QUIC_SESSION_POOL_MARK_ALL_ACTIVE_SESSIONS_GOING_AWAY`
    (Chrome 主動停用 QUIC 的動作),UDP socket 事件 34。
  - 有趣的是伺服器回應標頭帶 `alt-svc: h3=":443"`(**宣告**支援 QUIC),但 Chrome-behind-proxy
    直接忽略、繼續走 TCP。→ 「設 proxy → 棄 QUIC」鐵證。
- **CA 通、能解密**:Chrome 未加 `--ignore-certificate-errors` 也能載入,proxy 解密了 9 個
  真實 Google/Chrome TLS 網域。
- **攔得下(登入態 + 匿名態)**:對 `chatgpt.com/backend-api/f/conversation`(登入)與
  `/backend-anon/f/conversation`(匿名)送假卡號,都回 **451**、稽核記到 `credit_card=4111…11`、
  真站沒收到。
- **不能掃全部流量(踩過的雷)**:早期對每個 POST 都跑 DLP,結果把 `challenges.cloudflare.com`
  的挑戰 token 當密鑰擋下 → **Cloudflare 過不去、ChatGPT 載不進來**。修正:**只檢查認得的
  AI 網域**,其他一律放行。
- **平台細節**:Windows 內建 `curl.exe` 用 **Schannel**,會**忽略 `--cacert`**(要 `-k` 或裝進
  系統存放區);PowerShell 內嵌 JSON 的引號會被拆壞(要用檔案 `--data-binary @file`)。

---

## 10. 限制與後續工作

- **回應串流已做**;**WebSocket relay 已做**(fail-open/closed 可選)。
- **WS frame 層 DLP**(讓 WS 送出的內容也能檢查)——下一步。
- **catch-all(WFP/WinDivert)**——收不理會 proxy 的 app、UDP;規格標為後期選配。
- **更多 AI 服務對應**與 prompt 抽取器(端點/欄位可設定更新)。
- **偵測強化**:更完整的金融/PHI 偵測器、ML/NER classifier(可外掛 Presidio)。

---

## 附:程式模組對照

| 模組 | 職責 |
|---|---|
| `proxy.py` | asyncio 顯式 MITM proxy:CONNECT、TLS 終止、DLP hook、擋(451)/串流轉發、WebSocket relay/block |
| `ca.py` | Root CA 載入/產生 + 逐 host 偽造 leaf、ALPN 鎖定的 SSLContext |
| `dlp/` | 分層偵測引擎(regex + 檢查碼 + 熵 + 關鍵字)、精準度分流 |
| `extract.py` | 從 request body 抽 AI prompt(ChatGPT/Claude/Gemini + shadow-AI 註冊制)|
| `override.py` / `control.py` | 一次性、有 TTL 的 warn-with-override + loopback 控制端點 |
| `audit.py` | append-only JSONL 稽核(遮罩,不記明文)|
| `notify.py` | Windows toast(非 Windows 降級為記錄)|
| `deploy.py` | 產生 Chrome/Edge proxy 政策 `.reg`、CA 信任指令、`install.ps1` |
| `service.py` | 以 Windows service 常駐(NSSM/sc.exe 或原生 pywin32)|

延伸閱讀:[`spec.md`](spec.md)(完整規格)、[`testing.md`](testing.md)(手動驗收步驟)。
