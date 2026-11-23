# SSHDeck service 部署與憑證交接

本文件說明 SSHDeck service、CLI、UI adapter 與 server-side TCP tunnel consumer 的設定分工。正式部署須以部署端的 secret manager／受限檔案提供憑證；本文件中的變數名稱是設定鍵，不是可提交的憑證值。

## 程序與憑證角色

SSHDeck service 使用獨立的 `SSHDECK_SERVICE_HOME`，啟動時必須提供下列環境變數：

| 設定 | 提供給 | 用途 |
| --- | --- | --- |
| `SSHDECK_SERVICE_HOME` | service | 絕對路徑；保存 service 專用 host、trust 與加密 managed-key 資料。 |
| `SSHDECK_ENCRYPTION_KEY` | service | 獨立的 32-byte AES-256-GCM key，以 64 個十六進位字元提供；不可與資料卷同置或使用其他產品設定 fallback。 |
| `SSHDECK_SERVICE_TOKEN` | CLI／headless service client | 一般 SSHDeck service API 的 CLI role；不得提供給瀏覽器或一般 Bot 執行環境。 |
| `SSHDECK_UI_TOKEN` | UI adapter；受信任的 server-side grant manager | 管理 UI 所需的 service API role，亦用於直接建立／撤銷 TCP target grant；不授權 tunnel WebSocket。 |
| `SSHDECK_TUNNEL_TOKEN` | 受信任的 server-side tunnel consumer | 僅用於直接開啟 TCP tunnel WebSocket；不授權讀取或管理 hosts／keys、建立 grant、exec、PTY 或 lock。 |

Service API、token role、target grant 與 WebSocket frame 契約詳見 [`service-api.md`](service-api.md)。啟動時，`SSHDECK_SERVICE_TOKEN`、`SSHDECK_UI_TOKEN`、`SSHDECK_TUNNEL_TOKEN` 各須至少 32 個字元；`SSHDECK_UI_TOKEN` 不得等於 `SSHDECK_SERVICE_TOKEN`，而 `SSHDECK_TUNNEL_TOKEN` 不得等於 `SSHDECK_SERVICE_TOKEN`、`SSHDECK_UI_TOKEN` 或 `SSHDECK_ENCRYPTION_KEY`。規格與實作不要求 `SSHDECK_SERVICE_TOKEN`、`SSHDECK_UI_TOKEN` 與 `SSHDECK_ENCRYPTION_KEY` 彼此互異。若上述啟動驗證失敗，service 會拒絕啟動。

## 連線路徑

- Headless CLI 明確使用 `SSHDECK_MODE=service`、固定的 `SSHDECK_SERVICE_URL` 及 server-side `SSHDECK_SERVICE_TOKEN`。Service 設定錯誤或不可達時，CLI 不回退 standalone 資料。
- UI adapter 是獨立的 server-side 程序，使用固定 `SSHDECK_SERVICE_URL` 及 `SSHDECK_UI_TOKEN` 呼叫管理 API。其 host／origin allowlist、HTTPS ingress 與登入保護由部署設定；不要把 UI token 或 encryption key 傳入 browser bundle。
- Target grant manager 與 tunnel consumer 只能由受信任的 server-side 程序直接呼叫 service：grant route 使用 UI token，`/v1/hosts/{alias}/tcp-tunnel` 使用不同的 tunnel token。UI adapter 不代理 grant/tunnel 路由，亦不可把 tunnel token 轉交 UI 或 Bot。
- Service 預設只監聽 loopback，且本身不提供 TLS。非 loopback 部署須使用隔離網路、只允許授權呼叫端存取及 TLS ingress；對外 tunnel 連線使用 `wss://`。不得因設定 `SSHDECK_SERVICE_TERMINAL_ORIGIN` 而放寬精確 Host／Origin 驗證。

## 秘密與日誌界線

- 以 secret manager 或具存取控制的檔案注入憑證；不要寫入 Git、container image、命令列參數、服務 URL／query、shell history 或一般 log。
- Bearer token 只放在 HTTP `Authorization` header；不可放在 URL 或 query。Tunnel destination 由 server-side opaque grant 決定，不由 browser、CLI 參數或 Bot payload 指定。
- CLI／service／UI adapter 的可觀測 stdout、stderr、API response、browser-visible data、package skill/docs 不得含 token 值、encryption key、private key 或 passphrase。只記錄安全錯誤代碼與必要操作狀態。
- `SSHDECK_SERVICE_TOKEN`、`SSHDECK_UI_TOKEN` 與 `SSHDECK_TUNNEL_TOKEN` 是不同權限角色，不可互相替用。UI 登入憑證也與 UI adapter token 分離。

此文件描述 SSHDeck package 提供的 service contract，不宣稱已驗證任何外部 Agent System backend/browser/Bot runtime 的跨 repo 資料流，也不授權修改其他 repo 的 deployment pin、發布或部署。
