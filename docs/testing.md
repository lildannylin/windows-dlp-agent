# 測試指南（手動驗收，對應規格 §8）

自動化測試(`pytest`,55 個)已涵蓋 proxy / DLP / override / 部署的邏輯。
這份文件是**在真實環境上手動驗收**的步驟,由易到難分三層:

- **Level 0**:自動化測試(已完成,`pytest`)
- **Level 1**:用 `curl` 隔離驗證 proxy 本身(不牽涉瀏覽器)
- **Level 2**:用 `curl` 驗證「擋得下」(不需登入 AI 站)
- **Level 3**:真實 Chrome 端到端(§8 完整驗收:能解密 + QUIC 自動不走 + toast)

先在專案根目錄啟用 venv:

```powershell
cd C:\Users\danny.lin\windows-dlp-agent
.\.venv\Scripts\Activate.ps1
```

---

## 前置:匯出 CA 並啟動 proxy

### 1. 匯出根 CA

```powershell
python -m windows_dlp_agent export-ca .\proxy-ca.crt
```

### 2. (要看到桌面 toast 才需要)安裝 Windows 通知套件

沒裝的話 proxy 會自動降級成「不彈通知、只記錄」,擋的行為不受影響。

```powershell
pip install windows-toasts
```

### 3. 啟動 proxy(開 verbose + 稽核 + 覆寫控制端點)

另開一個 PowerShell 視窗常駐它(用 8888,因為 8080 實測會被 VS Code 占走):

```powershell
python -m windows_dlp_agent --port 8888 --control-port 8889 --audit-log .\dlp-audit.jsonl -vv
```

看到這兩行就代表起來了:

```
MITM proxy listening on ('127.0.0.1', 8888)
override control endpoint on 127.0.0.1:8889
```

---

> ⚠️ **兩個 Windows 實測踩過的坑(已驗證)**
>
> 1. **Windows 內建 `curl.exe` 用 Schannel(不是 OpenSSL)**,`curl -V` 可確認。
>    Schannel **會忽略 `--cacert`**,改用 Windows 憑證存放區驗證。所以隔離測試 proxy 時
>    請改用 `-k`(跳過驗證)先證明 MITM 通;要驗「CA 被信任」則先把 CA 裝進 Windows 存放區
>    (見 Level 3 的 `certutil`)再不加 `-k` 測。
> 2. **不要用 PowerShell 內嵌 `-d '{\"...\"}'` 送 JSON**——反斜線與空白會被 PowerShell/
>    curl 拆壞,body 送不進去(實測會變成亂七八糟的請求)。**一律把 JSON 寫成檔案**,用
>    `--data-binary "@card.json"`。
> 3. **8080 可能被占用**(實測被 VS Code 占走)。被占就換 port,例如 `--port 8888`,
>    下面範例即用 8888。

## Level 1 — 用 curl 驗證 proxy 能解密並轉發（無瀏覽器）

這一步證明「CONNECT → 用偽造憑證終止 TLS → 轉發到真站」整條通。

```powershell
# -k 跳過 Schannel 驗證,先證明 MITM 解密+轉發這條路通
curl.exe -k -x 127.0.0.1:8888 -o NUL -w "HTTP %{http_code}`n" https://example.com
```

**預期**:`HTTP 200`(實測通過)。

- proxy 的 `-vv` 視窗會出現對 `example.com` 的處理紀錄。
- 想順便驗「CA 被信任」:先做 Level 3 的 `certutil -user -addstore -f Root`,
  然後**拿掉 `-k`** 再測一次,一樣 200 才代表信任鏈正確。

---

## Level 2 — 用 curl 驗證「擋得下」（不需登入 AI 站）

因為命中是在**轉發前**擋下,所以不需要真的登入 ChatGPT——直接對它的端點送假卡號,
proxy 應該回 **451** 且**從未把資料送出**。

先把測試 body 寫成檔案(避開 PowerShell 內嵌 JSON 的坑):

```powershell
Set-Content -Encoding ascii card.json  '{"messages":[{"content":{"parts":["my card 4111 1111 1111 1111"]}}]}'
Set-Content -Encoding ascii key.json   '{"messages":[{"content":{"parts":["key sk-abcdefghijklmnopqrstuvwxyz0123"]}}]}'
Set-Content -Encoding ascii clean.json '{"messages":[{"content":{"parts":["what is the capital of France"]}}]}'
```

假卡號 → 預期 **451**(實測通過):

```powershell
curl.exe -k -x 127.0.0.1:8888 -o NUL -w "HTTP %{http_code}`n" `
  -X POST https://chatgpt.com/backend-api/conversation `
  -H "content-type: application/json" --data-binary "@card.json"
```

**預期**:

- `HTTP 451`(實測通過)
- proxy 視窗出現 `DLP block on chatgpt.com/backend-api/conversation: credit_card(...)`
- `dlp-audit.jsonl` 多一行 `"outcome":"block"`,卡號**被遮罩**成 `4111…11`(不是明文)
- 裝了 `windows-toasts` 的話,桌面右下角彈出通知

API key → 也應該 **451**:

```powershell
curl.exe -k -x 127.0.0.1:8888 -o NUL -w "HTTP %{http_code}`n" `
  -X POST https://chatgpt.com/backend-api/conversation `
  -H "content-type: application/json" --data-binary "@key.json"
```

對照組——乾淨內容**不被擋**(會往上游轉發;未登入時 chatgpt.com 回 403 challenge,
但**不是 451**,代表 DLP 正確放行。實測拿到 403):

```powershell
curl.exe -k -x 127.0.0.1:8888 -o NUL -w "HTTP %{http_code}`n" `
  -X POST https://chatgpt.com/backend-api/conversation `
  -H "content-type: application/json" --data-binary "@clean.json"
```

### 測 warn-with-override（§5）

用 email(warn 級)觸發「先擋、可覆寫」:

```powershell
Set-Content -Encoding ascii email.json '{"messages":[{"content":{"parts":["email me at alice@example.com"]}}]}'

# 1) 先送 → 預期 451(warn 也先擋)
curl.exe -k -x 127.0.0.1:8888 -o NUL -w "HTTP %{http_code}`n" `
  -X POST https://chatgpt.com/backend-api/conversation `
  -H "content-type: application/json" --data-binary "@email.json"

# 2) 算 fingerprint（host 用 chatgpt.com,prompt 用送出的那段字）
python -c "from windows_dlp_agent.override import fingerprint; print(fingerprint('chatgpt.com','email me at alice@example.com'))"

# 3) 核准（把上一行印出的值填進去）
python -m windows_dlp_agent override <貼上fingerprint> --control-port 8889

# 4) 再送同一份 → 這次放行(不再 451,轉發後拿到上游 403)；再送第三次 → 又擋(一次性)
```

> 註:Level 2 是用 curl 手算 fingerprint 驗證機制;真實情境下 fingerprint 會顯示在 toast /
> agent UI 上讓使用者一鍵核准(尚未接按鈕,見 README「尚未做」)。

---

## Level 3 — 真實 Chrome 端到端（§8 完整驗收）

證明三件事一次到位:**CA 通 + Chrome 棄 QUIC 全走 TCP + 能解密內容並擋下**。

### 1. 讓 Windows/Chrome 信任 CA

單機測試用「目前使用者」的根存放區即可(**不需系統管理員**):

```powershell
certutil -user -addstore -f Root .\proxy-ca.crt
```

> 正式部署才用機器存放區(需管理員):`certutil -addstore -f Root .\proxy-ca.crt`,
> 或用 `deploy-bundle` 產生的 `install.ps1`。

### 2. 用「指定 proxy + 全新設定檔」啟動 Chrome

全新 profile 可避開既有的 QUIC 快取與登入狀態干擾:

```powershell
& "C:\Program Files\Google\Chrome\Application\chrome.exe" `
  --proxy-server="127.0.0.1:8888" `
  --user-data-dir="$env:TEMP\dlp-chrome-test"
```

### 3. 開 ChatGPT,實測

- 開 `https://chatgpt.com`(此測試需要你登入才會真的送出對話)。
- 按 **F12 → Network**,勾選保留紀錄。
- 在輸入框貼上假卡號 `4111 1111 1111 1111` 或 `sk-` 開頭的假 key,送出。

**預期(對應 §8「擋得下」)**:

- 送出的 `conversation` 請求在 Network 面板顯示**失敗 / 451**,**看不到成功送出**。
- 桌面彈出 toast:「偵測到 financial,已阻擋送往 ChatGPT」。
- `dlp-audit.jsonl` 記到這次 block。

### 4. 驗證 QUIC 自動不走（§8「協定無關」)

- 在 Network 面板加開 **Protocol** 欄位(右鍵表頭 → Protocol)。
- 所有請求的 Protocol 應為 `http/1.1` 或 `h2`(TCP),**不會是 `h3`(QUIC)**。
- 對照:`chrome://flags` 把 QUIC 開或關,結果一樣(因為設了 proxy 就不發 QUIC)。

### 5. 驗證防繞過(§8)

- 用 `deploy-bundle` 產生的 `.reg` 套用受管政策後,使用者在 `chrome://settings` 改不掉 proxy。
- 無痕模式一樣走 proxy、一樣被擋。

---

## 已知限制(測試時會遇到,先知道)

1. **串流回應會被緩衝**:目前 proxy 用 httpx 一次抓完上游回應再回傳,對 ChatGPT 的 SSE
   串流回覆,乾淨訊息的**回覆會等整段完成才一次出現**(甚至可能逾時)。**擋**的路徑不受影響
   (擋在轉發前)。串流透傳是後續優化項。
2. **ChatGPT 端點/欄位可能改版**:`_extract_chatgpt` 對 `messages[].content.parts[]`;
   若哪天改了,專屬抽取器可能漏抓,但**通用 fallback 會掃 body 內所有字串**,假卡號/API key
   仍會被擋。用 `-vv` 看實際路徑與 body 來校準 `extract.py`。
3. **toast 需 `windows-toasts`**:沒裝只會記錄不彈窗。
4. **toast 覆寫按鈕尚未接**:warn 覆寫目前走 CLI / 控制端點(見 Level 2)。

---

## 疑難排解

| 現象 | 可能原因 / 處置 |
|---|---|
| curl 憑證錯誤 | `--cacert` 沒指到剛匯出的 CA;或 proxy 用的 CA 與匯出的不一致(確認同一個 `--ca-dir`) |
| Chrome 顯示 `ERR_PROXY_CONNECTION_FAILED` | proxy 沒啟動,或 port 不對 |
| Chrome 顯示憑證不受信任 | CA 沒進根存放區;重跑 `certutil -user -addstore -f Root`,並**重開 Chrome** |
| 乾淨訊息一直轉圈 | 串流緩衝限制(見上);先用 Level 2 curl 驗擋的行為 |
| 沒彈 toast | 沒裝 `windows-toasts`,或用的是非 Windows 環境 |
| DLP 沒擋到 | 看 proxy `-vv` 是否有解到該請求;確認 body 真的含觸發字串;必要時依實際 body 調 `extract.py` |
