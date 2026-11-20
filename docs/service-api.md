# SSHDeck 常駐服務 API／CLI 契約

本文件定義 protocol version 1。服務模式與既有 standalone 模式是互斥入口；服務設定錯誤、認證失敗、版本不相容或服務中斷時，CLI **不會**讀取 standalone 資料、不詢問私鑰密語，也不重送遠端命令。

## 啟動與資料隔離

```text
sshdeck service start [--host 127.0.0.1] [--port 8788]
```

服務啟動必須提供下列環境變數；不會替代生成、從其他設定回退或把值寫入命令列：

| 變數 | 用途 |
| --- | --- |
| `SSHDECK_SERVICE_HOME` | 必須是絕對路徑；服務主機資料、金鑰索引、信任紀錄及加密私鑰的專屬根目錄。 |
| `SSHDECK_ENCRYPTION_KEY` | 獨立的 32-byte AES-256-GCM 金鑰，以恰好 64 個十六進位字元提供。不得與資料卷同置、不得使用 `EXTENSION_SECRET_KEY`。 |
| `SSHDECK_SERVICE_TOKEN` | main／headless CLI 專用 Bearer token，至少 32 個字元。 |
| `SSHDECK_UI_TOKEN` | UI server-side adapter 專用 Bearer token，至少 32 個字元且不得與 CLI token 相同；不得傳給瀏覽器。UI 登入憑證與此 token 各自獨立。 |

`SSHDECK_SERVICE_TERMINAL_ORIGIN` 是選填設定，只影響 terminal WebSocket 的 Host／Origin 檢查。當 UI adapter 經由 HTTPS ingress 連到 service，而對外 authority 與 service 的內部 listener 不同時，將它設為精確、canonical 的 HTTP(S) origin，例如 `https://sshdeck.example`；非預設 port 必須明列，例如 `https://sshdeck.example:8443`。值不可含帳密、路徑、query 或 fragment。未設定時，terminal WebSocket 仍須符合 service listener 的既有 Host／Origin 與有效 port 檢查。

service 設定 `SSHDECK_SERVICE_TERMINAL_ORIGIN`；UI adapter 的 `SSHDECK_SERVICE_URL` 指向同一個對外 HTTPS origin：

```text
SSHDECK_SERVICE_URL=https://sshdeck.example
SSHDECK_SERVICE_TERMINAL_ORIGIN=https://sshdeck.example
```

服務預設只監聽 `127.0.0.1`。若部署需要其他 bind address，必須由部署提供隔離網路、只允許授權呼叫端存取及 TLS ingress；TLS 在 ingress 終止，本服務本身不提供 TLS。若使用上述 origin 設定，ingress 必須保留轉送至 service 的 `Host` 與 `Origin`，不得改寫；service 只接受與設定值完全相符的 authority，不會因此信任任意 Host／Origin 或允許任意 upstream。服務目錄不得與 standalone 的 `SSHDECK_HOME`／平台預設資料目錄相同；若發生碰撞，服務拒絕啟動。服務資料也不接受指向既有外部私鑰的 `keyPath`。

啟動時會驗證主機 JSON、金鑰索引、鎖定狀態及每個服務金鑰封套。任何缺少的加密金鑰、無法驗證／解密的封套、損壞資料或不支援的外部私鑰關聯都會使服務拒絕啟動；啟動驗證不會修補、重建或覆寫來源資料。封套使用隨機 nonce、AES-256-GCM authentication tag 及固定格式 AAD；每份私鑰與原匯入密語僅以密文保存。API 只回傳公鑰與必要主機資訊。

## HTTP 與認證

所有路徑均以 `/v1` 開始。除健康與版本查詢外，使用：

```http
Authorization: Bearer <server-side-token>
```

認證比對使用 constant-time byte comparison。token 不可放在 query、URL、命令列、瀏覽器程式碼或 log。

| 路徑 | 權限 | 回應與用途 |
| --- | --- | --- |
| `GET /v1/health` | 無 | `{ "status": "ok", "protocolVersion": 1 }`；僅健康狀態，不含主機資料。 |
| `GET /v1/version` | 無 | `{ "name": "sshdeck-service", "version": "...", "protocolVersion": 1 }`；CLI 每次命令先核對 protocol version。 |
| `GET /v1/hosts` | CLI 或 UI token | 主機摘要、是否關聯服務金鑰及最新檢查狀態；不含私鑰路徑。 |
| `POST /v1/hosts` | UI token | 新增主機 JSON：`alias`、`hostname`、`port`、`username`。不接受 `keyPath`。 |
| `GET /v1/hosts/{alias}` | CLI 或 UI token | 單一主機摘要。 |
| `PUT /v1/hosts/{alias}`、`DELETE /v1/hosts/{alias}` | UI token | 更新或刪除主機；刪除主機不會自動刪除其金鑰或撤銷遠端授權。更新／刪除會使主機檢查快取失效。 |
| `POST /v1/hosts/{alias}/key/create` | UI token | 建立 Ed25519 金鑰、加密保存並關聯主機；回傳 `{id, publicKey, guide}`。 |
| `POST /v1/hosts/{alias}/key/import` | UI token | JSON `{ "privateKey": "<OpenSSH private key>", "passphrase": "<optional>" }`；輸入僅供該次 TLS／受信任內部要求使用，不回傳或記錄。 |
| `POST /v1/hosts/{alias}/key/link` | UI token | JSON `{ "keyId": "..." }`，將服務管理金鑰關聯至主機；允許明確共用。 |
| `POST /v1/hosts/{alias}/key/unlink` | UI token | 解除關聯、清除該主機檢查快取；私鑰及遠端授權保留。 |
| `GET /v1/hosts/{alias}/key` | UI token | 回傳已關聯金鑰的公鑰與安裝指南。 |
| `GET /v1/keys` | UI token | 金鑰 ID、公開資訊及所有關聯 alias。 |
| `DELETE /v1/keys/{id}` | UI token | 只可刪除未關聯金鑰；仍有任何主機關聯時以 `409 KEY_IN_USE` 拒絕。 |
| `POST /v1/hosts/{alias}/check` | CLI 或 UI token | 以服務憑證檢查 SSH；不設定 `expectedFingerprint` 時未知／變更指紋回 `409`。 |
| `POST /v1/hosts/{alias}/exec` | CLI 或 UI token | JSON `{ "command": "..." }`，以 NDJSON 回傳單次遠端命令串流。 |
| `GET /v1/hosts/{alias}/terminal` | 僅 UI token | WebSocket upgrade，建立該受管 alias 的互動 SSH PTY；拒絕 CLI token、未知主機及手動鎖定狀態。 |
| `POST /v1/lock`、`POST /v1/unlock` | UI token | 手動鎖定／明確解鎖所有服務金鑰。解鎖只在服務端完成。 |

`expectedFingerprint` 僅能在先取得 challenge 並經可信管道人工核對後，傳入 check／exec。服務會在同一 SSH 握手中確認目前 fingerprint 與核對值完全相同才記錄信任；不相符仍拒絕。CLI 的明確核對入口為：

```text
SSHDECK_MODE=service sshdeck host trust <alias> --fingerprint SHA256:<人工核對值>
```

此命令不互動、不接受自動信任；未核對的 host key 會阻擋遠端命令。

## 串流、取消與錯誤

成功執行使用 `application/x-ndjson`；每行是一個 JSON event：

```json
{"type":"stdout","data":"..."}
{"type":"stderr","data":"..."}
{"type":"exit","code":0}
```

事件順序保留各自串流順序；stdout 與 stderr 不合併。最後必須有一個 `exit` event。SSH／認證／信任錯誤若在串流開始前發生，回傳 JSON `{ "code": "...", "error": "...", "fingerprint": "..." }` 及相應 HTTP status；串流開始後則以 `type: "error"` 結束。主要穩定代碼包含 `UNAUTHORIZED`、`FORBIDDEN`、`SERVICE_LOCKED`、`KEY_REQUIRED`、`HOST_TRUST_REQUIRED`、`HOST_KEY_CHANGED`、`AUTHENTICATION_FAILED`、`HOST_NOT_FOUND`、`KEY_IN_USE`、`DATA_CORRUPT` 及 `REMOTE_EXEC_FAILED`。

CLI 將 stdout／stderr event 各自寫入對應檔案描述元，遠端結束碼作為 CLI 結束碼。使用者取消或 client 斷線會關閉該 HTTP 要求及對應 SSH channel；不會自動重連或重送。沒有完整 exit event 的斷線回報 `SERVICE_DISCONNECTED`，不會被當成遠端命令失敗後重新執行。取消只保證關閉本機 SSH 工作階段，不保證遠端已啟動的子程序停止。

## 互動 PTY WebSocket（protocol v1）

終端 endpoint 為 `GET /v1/hosts/{alias}/terminal`，使用標準 WebSocket upgrade；`alias` 必須是 service 已配置且已關聯服務管理金鑰的主機。要求必須帶有 `Authorization: Bearer <SSHDECK_UI_TOKEN>`，只接受 UI token，不接受 `SSHDECK_SERVICE_TOKEN`。缺少／錯誤 token 回 `401`；CLI token、非法 Host／Origin 回 `403`；未知 alias 回 `404`；手動鎖定回 `423`。endpoint 不接受 query string、不支援任意 upstream。Host 與 Origin 必須符合相同的服務 authority；若已設定 `SSHDECK_SERVICE_TERMINAL_ORIGIN`，兩者都必須與該精確 origin 相符，否則依 service listener authority 檢查。

UI adapter 的瀏覽器端路徑為 `/api/shell?alias=<alias>`（受 `SSHDECK_BASE_PATH` 影響時包含 base path，例如 `/sshdeck/api/shell`）。adapter 只使用 server-side `SSHDECK_UI_TOKEN` 連到設定中的固定 `SSHDECK_SERVICE_URL` 與上述 service endpoint；`SSHDECK_SERVICE_TOKEN`、`SSHDECK_UI_TOKEN` 及加密金鑰都不會進入瀏覽器 bundle、URL／query、console、一般回應或 log。瀏覽器傳來的 Basic `Authorization` 不會鏡像至 adapter 或 service WebSocket。adapter 保留自己的 Host／Origin ingress gate，且不接受瀏覽器指定 service URL。

成功 upgrade 後，client 與 service 使用以下 frame：

| 方向 | Frame | 用途 |
| --- | --- | --- |
| client → service | Binary | 原樣寫入此 session 的 SSH PTY stdin。 |
| service → client | Binary | 原樣轉送此 session 的 SSH PTY stdout。 |
| client → service | `{ "type": "resize", "cols": 80, "rows": 24 }` | 調整遠端 PTY 尺寸；列、欄必須是 `1`–`1000` 的整數。 |
| service → client | `{ "type": "trust-required", "code": "HOST_TRUST_REQUIRED", "fingerprint": "SHA256:..." }` | 首次連線須先由使用者透過可信管道核對並明確確認指紋；尚未開啟 PTY。 |
| service → client | `{ "type": "host-key-changed", "code": "HOST_KEY_CHANGED", "fingerprint": "SHA256:...", "previousFingerprint": "SHA256:..." }` | 主機指紋變更；舊信任不會自動沿用，確認前不開 PTY。 |
| client → service | `{ "type": "trust", "fingerprint": "SHA256:..." }` | 提交使用者已確認的精確指紋。service 會重新連線，只有目前 fingerprint 完全相同時才記錄信任並開 PTY。 |
| client → service | `{ "type": "trust-reject" }` | 拒絕 trust challenge，關閉此 session。 |
| service → client | `{ "type": "started", "alias": "...", "username": "...", "cols": 80, "rows": 24 }` | SSH PTY 已成功建立。 |
| client → service | `{ "type": "close" }` | 關閉此 session 的本機 SSH PTY。WebSocket close／disconnect 具相同清理效果。 |
| service → client | `{ "type": "error", "code": "...", "error": "..." }` | SSH／憑證／協定錯誤；service 隨後關閉該 session。 |
| service → client | `{ "type": "closed", "code": 0 }` | 遠端 PTY 正常結束；可附 `error`、`signal`。 |

control frame 使用 JSON text frame；未知或格式錯誤的控制訊息會拒絕並關閉 session。PTY 輸入、輸出與 resize 僅屬於各自 alias 的獨立 SSH channel；取消、瀏覽器／adapter disconnect、手動 lock、主機設定或 key 關聯變更及 service shutdown 會關閉相應本機 PTY，不自動重連或重送。手動 lock 或主機／key 變更會先傳送 `error` 再關閉該 session；adapter disconnect 與 service shutdown 會關閉 WebSocket。`POST /v1/lock` 會關閉所有既有 service PTY 並拒絕新連線；只有 UI token 明確呼叫 `/v1/unlock` 且服務端重新驗證金鑰後才能恢復。關閉本機 SSH session 不保證遠端已啟動的子程序停止。

## 手動鎖定與重啟

一般服務重啟會以 `SSHDECK_ENCRYPTION_KEY` 驗證並解密服務金鑰，服務可立即使用。`POST /v1/lock` 先原子寫入 `hosts.json.service-state.json` 的手動鎖定狀態，再清除記憶體金鑰、取消進行中的 SSH 執行並關閉所有既有 PTY；服務重啟後仍保持鎖定。只有受信任 UI server-side 呼叫 `POST /v1/unlock`、完成資料重新驗證及原子清除鎖定狀態後才恢復。服務 token 不具解鎖權限。刪除金鑰只刪除本機密文及公鑰，不會撤銷遠端 `authorized_keys` 授權。

## CLI 模式

設定 `SSHDECK_MODE=service` 後，`SSHDECK_SERVICE_URL` 和 `SSHDECK_SERVICE_TOKEN` 必須存在；目前支援：

```text
sshdeck exec <alias> -- <remote command>
sshdeck host list
sshdeck host check <alias>
sshdeck host trust <alias> --fingerprint <verified fingerprint>
```

service mode 不讀取 `SSHDECK_HOME`、平台預設資料目錄或本機私鑰，不提示輸入密語，也不回退至 standalone。未設定 `SSHDECK_MODE=service` 時，既有 standalone 命令及互動行為維持原狀。
