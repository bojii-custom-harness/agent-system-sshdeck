---
name: agent-system-sshdeck
description: 使用 agent-system-sshdeck（相容指令 sshdeck）管理 SSH 主機與登入金鑰、檢查 SSH／Docker、執行遠端命令或開啟互動終端。安裝或更新此 CLI 時亦使用。
---

# 使用 agent-system-sshdeck CLI

## 選擇執行入口

1. 確認使用者要操作的主機別名與工作；沒有指定工作時先列出主機，再詢問目標。
2. 已安裝時使用 `agent-system-sshdeck`，舊版使用 `sshdeck`。在此工具的原始碼 repo 中，可直接使用 `node bin/sshdeck.js`；先確認 `package.json` 與入口存在，缺少依賴時執行 `npm ci`。
3. 以 `host list` 驗證所選入口可執行。需要確認版本時讀取本機套件資訊或使用 `npm list -g --depth=0`；此 CLI 未提供 `--version`／`--help`。
4. 安裝或更新時讀取 [安裝與版本辨識](references/install.md)。其餘操作依下方命令執行；範例中的 `sshdeck` 代表已確認可用的入口，可替換為新指令或原始碼入口。

## 主機與資料位置

```sh
sshdeck host list
sshdeck host add dev --hostname example.org --user alice --port 22 --key ~/.ssh/id_ed25519
sshdeck host update dev --hostname new.example.org --port 2222
sshdeck host delete dev
```

- 以實際主機、帳號與金鑰路徑替換範例；新增前先核對別名是否已存在，已存在且需調整時使用 `update`。未指定的更新欄位保留原值。
- 準備由工具產生金鑰時，新增主機可省略 `--key`。
- 資料目錄由 `SSHDECK_HOME` 指定；預設為 Windows `%APPDATA%\sshdeck`、macOS `~/Library/Application Support/sshdeck`、Linux `${XDG_DATA_HOME:-~/.local/share}/sshdeck`。新舊指令沿用同一資料位置。
- 在既有使用情境沿用使用者資料；驗證或示範則以獨立 `SSHDECK_HOME` 隔離。備份時先停止 UI，再備份整個資料目錄及另存於外部的私鑰，保留原權限。
- 修改後用 `host list` 核對結果。刪除主機設定只移除設定，金鑰與遠端授權是獨立操作。

## SSH 與 Docker 檢查

```sh
sshdeck host check dev
```

此命令先檢查 SSH，再以同一登入帳號檢查 Docker；分別回報結果。列表中的歷史檢查結果不是即時連線證明。

- 首次連線或指紋改變時，由使用者透過可信管道核對主機指紋，再回到 CLI 確認。不能把剛收到的未知指紋當作可信依據。
- 密語輸入與信任確認需要互動終端。執行工具沒有互動 stdin 時，交給使用者在本機終端執行並回報結果；不把密語放入對話、命令參數、環境變數或檔案，也不自動輸入 `yes`。
- Docker 權限不足、CLI 缺少或 daemon 不可用時，保留實際診斷；需要管理員操作時用 `guide` 取得指引。Docker 群組授權具有近似 root 的主機權限，不以自動 `sudo` 取代診斷。

## 單次遠端命令

```sh
sshdeck exec dev -- "uname -a"
sshdeck exec dev -- "printf '%s' 'hello world'"
```

執行前核對別名對應的主機與帳號，以及使用者要求的命令。`--` 後參數以空格串成一條字串，再交給遠端登入 shell 解讀；將整條命令依本機 shell 規則引用，尤其注意 `$`、引號、管線與重新導向。

`exec` 即使使用未加密私鑰也會詢問密語（可按 Enter），不要假設它具備無互動模式或沿用 UI 的解鎖狀態。無互動 stdin 時提供完整命令讓使用者執行。

成功依據為遠端結束碼與輸出符合工作要求；保留 stdout、stderr 與非零結束碼的差異。Ctrl+C 或取消只關閉本機 SSH 工作階段，不保證遠端衍生程序停止；連線中斷後先確認遠端結果，再決定是否重跑有副作用的命令。

## 互動終端與本機 UI

```sh
sshdeck shell dev
sshdeck ui --port 8787
```

- `shell` 需要使用者終端的互動輸入；以 `exit` 或 Ctrl+D 結束，Ctrl+C 傳給遠端程式。
- `ui` 是長駐服務；若代為啟動，使用可追蹤的背景程序，回報實際網址及停止方式。工具時限依工作環境規範設定。
- UI 僅監聽 `127.0.0.1`。本機指的是 CLI 所在機器；在遠端或容器執行時，不把該網址當成使用者電腦可直接開啟的網址。
- 使用者在 UI 的密語欄位解鎖；手動鎖定會清除新連線可用的密語快取，但不會中斷既有終端連線。

## 金鑰生命週期

```sh
sshdeck key list
sshdeck key create dev
sshdeck key show dev
sshdeck guide dev
sshdeck key unlink dev
sshdeck key delete dev
```

- `create` 要求主機尚未關聯金鑰，並由使用者互動輸入非空密語；產生加密 Ed25519 私鑰。
- `show`／`guide` 讀取私鑰旁的 `.pub` 檔；外部金鑰缺少此檔時，先處理公鑰檔來源，不誤判為 SSH 認證失敗。
- `guide` 只輸出遠端安裝／撤銷指引；輸出成功不代表遠端已授權。遠端操作完成後，再執行 `host check` 驗證。
- `unlink` 解除主機關聯，保留本機檔案與遠端授權。
- `delete` 刪除工具管理的本機金鑰；以 `key list` 核對金鑰及關聯後，依使用者的刪除要求操作。外部私鑰用 `unlink`；仍共用的金鑰需先處理關聯。
- 刪除本機私鑰不會撤銷遠端 `authorized_keys`。需要撤銷時先保留對應公鑰與指南，再由有權限的操作者移除精確對應的公鑰行。

## 完成回報

回報實際使用的 CLI 入口、目標別名、操作結果與必要的下一步。將「本機設定完成」「SSH 已驗證」「Docker 可用」分開記錄；互動步驟尚待使用者執行時，明確標記待完成，不宣稱連線或遠端命令成功。
