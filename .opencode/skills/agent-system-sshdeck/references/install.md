# 安裝與版本辨識

Repository：<https://github.com/bojii-custom-harness/agent-system-sshdeck>

## 先確認已發布附件

需要安裝或更新時，先查實際 Release：

```sh
gh release view --repo bojii-custom-harness/agent-system-sshdeck --json tagName,assets
```

沒有 `gh` 時，可查 GitHub 公開 Releases 頁面或 API。以回傳的正式版本、附件名稱及下載網址為準；本機 `package.json` 有新版不代表已經發布。

- 新命名套件的附件為 `agent-system-sshdeck.tgz`，主要指令為 `agent-system-sshdeck`。
- 舊版 `v0.1.0` 的附件為 `sshdeck.tgz`，套件與指令名稱為 `sshdeck`。
- Repo 移轉不會重建舊版附件。若最新 Release 仍只有舊附件，就安裝該已發布版本並使用 `sshdeck`；不要要求使用者下載不存在的新名稱附件。

## 安裝與驗證

先用 `node --version`、`npm --version` 確認 Node.js ≥20 與 npm。以下新版指令只在查到對應附件後使用；為確保可重現，優先使用該版本附件的完整下載網址：

```sh
npm install -g https://github.com/bojii-custom-harness/agent-system-sshdeck/releases/latest/download/agent-system-sshdeck.tgz
agent-system-sshdeck host list
```

已發布的舊版安裝入口：

```sh
npm install -g https://github.com/bojii-custom-harness/agent-system-sshdeck/releases/download/v0.1.0/sshdeck.tgz
sshdeck host list
```

需要改用新套件且原本安裝了舊 `sshdeck` 時，先確認新附件可取得，再執行 `npm uninstall -g sshdeck`，接著安裝新套件，避免相容指令衝突。使用者資料保存在獨立的資料目錄，升級時沿用。

全域安裝位置用 `npm prefix -g` 查詢。安裝完成但指令找不到時，核對 Windows 的 prefix 或 Unix 的 `<prefix>/bin` 是否在 PATH；不以重新安裝或提高權限作為預設解法。

正式套件也包含 `agent-system-sshdeck` skill。全域安裝後，可在 `npm root -g` 列出的目錄下，從 `agent-system-sshdeck/.opencode/skills/agent-system-sshdeck/` 取得 `SKILL.md` 及 `references/install.md`；依 OpenCode skill discovery 規則將整個 `agent-system-sshdeck` 目錄放入目標專案的 `.opencode/skills/`。

若選擇下載附件後安裝，下載同版 `SHA256SUMS` 並比對檔案雜湊，再執行 `npm install -g <本機附件路徑>`。HTTPS tarball 安裝仍需要從 npm registry 取得相依套件。

## 原始碼入口

在已確認為此 CLI 的 repo 根目錄執行：

```sh
npm ci
node bin/sshdeck.js host list
```

需要全域使用尚未發布的本機版本時，使用 `npm install -g .`，並明確回報安裝來源為本機 checkout，而非正式 Release。
