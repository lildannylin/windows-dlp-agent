# Windows AI-DLP 端點 Proxy — 實作規格書（決定版）

> **一句話**：在 LAN 上每台 Windows PC 跑一個**本機 MITM proxy**，Chrome 用**顯式 proxy 設定**
> 指向它。因為「設了 proxy → Chrome 自動棄 QUIC → 全走 TCP」，所以**不用碰 QUIC、不用 kernel
> driver**；用**已安裝的 CA** 在 TCP 上 MITM，解密後對 AI prompt 做 DLP，命中就**擋下請求**並由
> agent 彈 **Windows 系統通知**（不是瀏覽器彈窗）。**用 Python 從頭實作**（用成熟函式庫處理 TLS/HTTP，不重造輪子）。

---

## 0. 目標與範圍

**目標**：使用者在 AI 網站（ChatGPT / Gemini / Claude / 其他）輸入 / 貼上敏感資料並送出時，
在**送出前**：偵測 → 擋下請求 → agent 系統通知。涵蓋**所有敏感資料類型**（見 §4）。

**部署位置**：**LAN 端每台要保護的 Windows PC**（端點程式，不在路由器上）。只保護安裝它的那台。
（涵蓋範圍見 §7。）

---

## 1. 關鍵設計決策（為什麼這樣做 — 承接前期結論）

1. **顯式 proxy，不是透明 WFP**：Chrome 一旦設了 proxy 就**不走 QUIC/HTTP-3**（HTTP-3 不經傳統 proxy），
   自動退 HTTP-2 over TCP → **QUIC 問題自動消失、免封 QUIC、免 kernel driver**。（透明 WFP 反而讓 Chrome 照走 QUIC 撞牆。）
2. **TCP 上 MITM 要 CA**：看內容就得解密＝偽造憑證＝客戶端要信 CA。TCP 的 CA Chrome 會接受（QUIC 那張裝了也沒用）；**CA 已安裝**（§3.2）。
3. **端點、不在路由器**：路由器 / 端點都解不了 Chrome QUIC，但**只有端點能用 proxy 設定逼 Chrome 棄 QUIC**。代價：逐台部署。
4. **Python 從頭刻，不重用 tls_proxy_go**：用成熟函式庫（`ssl` / `cryptography` / `h11` / `httpx` 等，見 §3.4）處理 TLS/憑證/HTTP，自己組出這個 MITM proxy，不重造 TLS。

---

## 2. 系統架構

```
LAN 端 Windows PC
┌──────────────────────────────────────────────────────────────┐
│  Chrome / Edge（受管政策設定 proxy）                            │
│     │  proxy 已設 → Chrome 棄 QUIC → 全部 HTTP/2 over TCP       │
│     ▼                                                          │
│  本機 MITM proxy  (127.0.0.1:<port>)  = 自寫 Python (§3.4)      │
│     ├─ 解析 HTTP CONNECT 取目標網域                             │
│     ├─ 用 CA 偽造該網域憑證（Chrome 已信 CA）→ 終止 client TLS  │
│     ├─ 解密 → 抽 AI prompt → DLP 判斷                           │
│     │      命中 → 不轉發、擋下該請求                            │
│     │      放行 → httpx / 標準 TLS 連真實伺服器、轉發           │
│     └─ 命中事件 → Native 通知模組                               │
│                          │                                     │
│                          ▼                                     │
│                 Windows 系統通知 (toast)  ← 不是瀏覽器彈窗       │
└──────────────────────────────────────────────────────────────┘
```

---

## 3. 本機 MITM proxy（核心，Python 從頭實作）

從零用 Python 刻，但用成熟函式庫處理 TLS/HTTP，不重造輪子（元件見 §3.4）。

### 3.1 顯式 proxy 流程
- **HTTPS**：client 送 `CONNECT host:443 HTTP/1.1` → proxy 回 `200 Connection Established`
  → 在該通道對 client 做 TLS 握手（用 CA **即時偽造 `host` 憑證**）→ 解密 → 解析 request → DLP → 擋/轉發。
- **HTTP（少見，AI 站幾乎全 HTTPS）**：client 送絕對 URI `GET http://host/path` → 直接處理。

### 3.2 憑證（CA）
- **要信任的是 forging root CA**（pico 的 `proxy-ca.crt`，指紋 `1C:E5:BB:15:…:89`），
  **不是** `server.crt`（`04:EB:A9…`，路由器管理憑證，無關）。
- **一致性規則（唯一要對的事）**：**proxy 簽偽造憑證用的 CA == 端點信任的 CA**。
- 兩種選擇：
  - **A（快速驗證）**：沿用 pico 的 `proxy-ca.key/.crt`（+ `forged-leaf.key`）→ 端點已信、零新安裝。
  - **B（獨立產品）**：新 repo 自己產一張 root CA → 端點改裝這張。出貨建議走 B（不把 router 私鑰帶進新專案）。
- **私鑰 `proxy-ca.key` 必須保密**，別進 git（`.gitignore`）。

### 3.3 QUIC 處理
**不需要做任何事** —— Chrome 設了 proxy 就不發 QUIC。

### 3.4 建議的 Python 建構元件（從頭刻但不重造 TLS）
| 需求 | 建議函式庫 |
|---|---|
| async 網路伺服器 | **asyncio**（`start_server` / `loop.start_tls`）|
| 解析 CONNECT / HTTP/1.1 | **h11**（或手解 CONNECT 那一行）|
| TLS 終止 + 依 SNI 換憑證 | **`ssl`** 模組的 `sni_callback`：握手時得知 host → 換上偽造憑證 |
| 即時偽造憑證（CA 簽 leaf）| **`cryptography`**：載入 CA key，per-host 生成並快取 leaf 憑證 |
| 向上游轉發 | **httpx**（async，支援 HTTP/2）或 **aiohttp** |
| DLP 引擎 | 自寫 `re` + checksum；重的可外掛 **Presidio**（Python 原生，剛好合）|
| Windows 通知 (toast) | **winotify** / **windows-toasts** / plyer |
| Windows service | **pywin32**（win32service）或用 **NSSM** 把腳本包成 service |

**關鍵簡化技巧**：把你的 MITM server 的 **ALPN 只提供 `http/1.1`** → Chrome 就跟你的 proxy 走 HTTP/1.1，
**不用實作 HTTP/2 frame 解析**（用 h11 就好，這是從頭刻 MITM 最省事的一步）。上游要不要 HTTP/2 交給 httpx，跟你解耦。

---

## 4. DLP 偵測引擎（涵蓋所有敏感資料）

**目標：所有敏感資料都要能偵測並擋，不只 API key。**

### 4.1 分類（要涵蓋的範圍）
| 類別 | 例子 | 主要偵測法 |
|---|---|---|
| **憑證 / 機密** | API key（`sk-…`、AWS `AKIA…`、GCP、GitHub `ghp_…`）、密碼、私鑰（PEM）、JWT、bearer token、DB 連線字串 | 前綴/結構 regex + **高熵偵測** |
| **個資 PII（在地化）** | 台灣身分證、健保卡、護照、統一編號、電話、email、地址、姓名組合 | regex + **檢查碼驗證** |
| **金融** | 信用卡（**Luhn**）、銀行帳號、IBAN | regex + checksum |
| **公司機密** | 原始碼、內部文件、客戶/員工清單、未公開財報、合約、專案代號 | 關鍵字/字典 + 原始碼啟發式 + (選)文件分類 |
| **健康 PHI** | 病歷、診斷、處方 | 關鍵字 + 上下文 |

### 4.2 分層偵測（精準度高→低）
1. **結構化 pattern + checksum**（誤判極低）→ **硬擋**。
2. **高熵（Shannon entropy）**→ 抓無固定格式的 secret/token。
3. **關鍵字 / 字典**（自訂敏感詞、`機密` 標記、專案代號）。
4. **上下文近似**（`password:`/`token=` 附近的值）。
5. **ML / NER（選配）**→ 自由文本 PII、原始碼、文件敏感度分類（重的可外掛 Presidio）。

### 4.3 精準度分流（避免誤判反感）
- 結構化 + checksum（幾乎不誤判）→ **block 硬擋**。
- 啟發式 / 高熵 / ML（可能誤判）→ **warn-with-override**（先擋 + agent 通知，允許確認放行）。
- 動作（block / warn / redact）由**政策依資料類型與風險**決定，規則集可更新。

### 4.4 prompt 抽取（各 AI 服務）
| 服務 | 端點（攔 body）| prompt 欄位 |
|---|---|---|
| ChatGPT | `POST chatgpt.com/backend-api/(f/)conversation` | `messages[].content.parts[]` |
| Gemini | `POST gemini.google.com/_/BardChatUi/data/batchexecute` | batchexecute f.req |
| Claude.ai | `POST claude.ai/api/organizations/<id>/…/completion` | completion payload |
| 其他 / shadow AI | 已知 AI 網域清單 + 泛型 | 泛型：最大字串欄位 |

（各站 request 形狀自行實作，前期先支援 ChatGPT；端點/欄位對應要可設定更新。）

---

## 5. 阻擋與通知 UX

**要求**：命中時「**請求被擋下**」，且「**提示由系統/agent 呈現，不是瀏覽器頁面彈窗**」。

- **擋（在 proxy）**：命中 → **不轉發給真實伺服器**，對 client 回一個錯誤（例如 451 / 自訂錯誤頁）。
  → 敏感資料**從未離開這台機器**。
- **提示（agent 出）**：proxy 把命中事件送給 **Native 通知模組 → 彈 Windows toast**
  （「偵測到 <資料類型>，已阻擋送往 <服務>」）。**不注入瀏覽器頁面。**
- **動作類型**：
  - **block**：擋 + toast。
  - **warn-with-override**：先擋 + toast 詢問；使用者在 toast/agent 上選「仍要送出」才放行（記錄 override）。
  - **redact**：把命中片段換成 `[REDACTED]` 再轉發 + toast 告知。

---

## 6. 部署與強制

- **打包 installer**：安裝 proxy（背景 service）、（選 B 時）安裝 CA 到 Trusted Root、設定 Chrome/Edge proxy 政策。
- **強制 proxy（防繞過）**：受管 Chrome/Edge 政策 `ProxyMode=fixed_servers` + `ProxyServer=127.0.0.1:<port>`
  （或 PAC），**使用者改不掉**。透過 GPO / Intune / MDM 推。
- **多台部署**：每台 PC 都要裝（端點模式）→ 做成無互動 installer 批次推。
- **service**：proxy 以 Windows service 常駐、開機自啟、崩潰自動重啟。

---

## 7. 涵蓋範圍與限制

- **涵蓋**：安裝它的那台 PC 上、尊重 proxy 設定的 app（**瀏覽器全算**）的 AI 流量。
- **不涵蓋**：
  - **無視 proxy 設定的 app / curl / 桌面版 AI app** → 需 §附錄 的 WFP catch-all（後期選配）。
  - **其他沒裝的 PC** → 端點模式本質，需逐台裝。
  - **程式/API 型 LLM 呼叫**（內部 app 直接打 OpenAI API）→ 用 LiteLLM 這類 gateway 另管（見附錄）。
- **只吃 TCP**（Chrome 已棄 QUIC）—— 正合設計。

---

## 8. 測試 / 驗收

- **零建置 spike（先做）**：Windows 跑 **mitmproxy**（explicit proxy 模式）+ 匯入 pico `proxy-ca` →
  Chrome 設 proxy 指向它 → 開 ChatGPT → 應**看到解密內容、且 Chrome 沒走 QUIC**。證明「CA 通 + QUIC 自動消失 + 能解內容」。
- **擋得下**：輸入假卡號 `4111 1111 1111 1111` / `sk-` API key → 送出 → **請求被擋（DevTools Network 看不到成功送出）** + **桌面 toast**。
- **協定無關**：`chrome://flags` 開/關 QUIC 結果一樣（因為設了 proxy 就不走 QUIC）。
- **防繞過**：確認 proxy 政策使用者改不掉；無痕也生效。
- **誤判/漏判**：跑正常 + 敏感 prompt 批次，量 FP/FN 調 classifier。

---

## 9. 實作階段

1. **Spike**：mitmproxy + pico CA + Chrome proxy 設定 → 確認能解、QUIC 自動不走。（零 code）
2. **MVP proxy（Python）**：asyncio + `ssl`(sni_callback) + `cryptography`（即時偽造憑證）做 CONNECT + TLS MITM；ALPN 鎖 `http/1.1` 用 h11 解析 → 能解密 ChatGPT 流量。
3. **DLP + 擋**：接 §4 偵測引擎（先結構化 regex）+ §5 擋 hook（命中不轉發）。
4. **通知**：Native 模組 + Windows toast（+ override）。
5. **多服務 + 完整 DLP 分類**（§4.1）+ 精準度分流。
6. **部署**：installer + Chrome/Edge proxy 政策 + service 常駐 +（選 B）自動裝 CA。
7. **（選配後期）catch-all**：WFP/WinDivert 收無視 proxy 的 app。

---

## 附錄 A：免費 / 開源方案與定位

### A.1 proxy（僅原型 & 參考 —— 產品是自寫 Python）
| 工具 | 用途 |
|---|---|
| **mitmproxy** | **僅 spike / 參考**：explicit proxy 現成，匯入你的 CA 立刻驗證「能解 + QUIC 自動不走」；其原始碼/addon 可當 MITM 實作參考。**產品不用它為引擎，自寫 Python（見 §3.4）** |
| Python 標準/第三方庫 | 見 §3.4（asyncio / ssl / cryptography / h11 / httpx …）= **產品實作基石** |

### A.2 DLP 引擎（可外掛）
| 工具 | 用途 |
|---|---|
| **Microsoft Presidio** | 開源 PII 偵測/去識別化 → 當 §4 的重量級 classifier |
| **LLM Guard** | 開源 LLM 輸入/輸出掃描（DLP、injection）|
| **LiteLLM** | 開源 LLM **API gateway** + guardrails |

### A.3 ⚠️ LiteLLM 的定位（別誤用）
LiteLLM 是 **API gateway** —— 只在「你的 app 把 LLM 呼叫路由經過它」時生效，**攔不到瀏覽器打
chatgpt.com**。它對應**「程式/API 型 AI 呼叫」**這條路（與本 proxy 互補），其 guardrail 邏輯
（Presidio/secret 偵測）可搬進本 proxy 的 DLP 引擎。

### A.4 catch-all（後期選配，前期不用碰）
收「無視 proxy 設定的 app」需 **WinDivert**（LGPLv3，⚠️ AV 有時誤標）或自刻簽章 WFP 驅動。

### A.5 參考連結
- mitmproxy explicit proxy / modes：https://docs.mitmproxy.org/stable/concepts/modes/
- mitmproxy Windows local mode：https://www.mitmproxy.org/posts/local-capture/windows/
- Microsoft Presidio：https://github.com/microsoft/presidio
- LiteLLM guardrails：https://docs.litellm.ai/docs/proxy/guardrails/quick_start
- WinDivert：https://github.com/basil00/WinDivert
