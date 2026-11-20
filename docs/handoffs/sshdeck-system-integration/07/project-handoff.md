# SSHDeck Ticket 07 專案交接

更新日期：2026-11-20

負責任務：SSHDeck Ticket 07 唯一產品實作 owner

## 基線與成果

- 權威工作項目：Agent System `.scratch/sshdeck-system-integration/issues/07-service-mode-terminal.md`；本票只修改 SSHDeck 產品 repo，未修改 Agent System issue、tickets、`test.md`、`execution-state.md` 或 Ticket 03／04。
- 基底：Ticket 01／02 已驗收的 SSHDeck integration `c2b96f437bcf1ae1122b113794292996aaca485f`。
- 產品程式碼提交：`35d75f52e090c084357418bdd4ea61757d66227c`（新增 service-mode 互動終端與 WebSocket bridge）、`e7017765a69a4781bfb8d5c1d11d18576b5a823f`（處理 service WebSocket 非正常關閉），以及 `1b32e86ecfccb8e3d36d892f62c45bce0ace2dcd`（保留 service shutdown 執行清理）。
- README／service API 文件提交：`49646597d11b33b3e42f2836dd471b67570b822c`（文件化 service-mode 互動終端契約）。`0.1.3` package candidate 僅以此已提交 source SHA 打包；後續 handoff/evidence commit 不改變該 candidate 的來源。
- 目前產品版本：`0.1.3`；本機 candidate 已建立並完成隔離安裝與相容 smoke，未發布。
- 產品程式與 README／service API 以獨立 source commits 保存；本目錄的 handoff、candidate 與 evidence 另行獨立提交，未納入 package source snapshot。

## 交付狀態

| 項目 | 狀態 | 證據／備註 |
| --- | --- | --- |
| T1：UI token 專用 service PTY WebSocket endpoint | 實作完成 | 驗證缺少／錯誤 token、CLI token、非法 Host／Origin、未知 alias 與 lock 拒絕。 |
| T2：server-side UI adapter bridge 與 service-mode UI | 實作完成 | upstream 固定使用設定的 service origin 與 server-side UI token；不轉送 browser Basic Authorization。 |
| T3：PTY input/output、resize、trust、取消、正常結束與資源清理 | 實作及真實驗收通過 | 並行 session、單獨取消、瀏覽器 disconnect、lock、adapter／service shutdown 與遠端 shell 結束後重開均有真實測試。 |
| T4：真實 service／隔離 OpenSSH／Chromium 測試與 standalone 相容 | 實作及驗收通過 | Ticket 07 service 與 standalone Chromium E2E 均使用真實隔離 WSL OpenSSH PTY，未以 mock SSH／WebSocket 取代。 |
| T5：文件與固定版本 package candidate | 完成 | README／service API 於 `49646597d11b33b3e42f2836dd471b67570b822c` 提交；`0.1.3` archive、packlist、檔案清單、SHA-256、隔離安裝及相容 smoke 均完成。 |
| V1 | 通過 | 真實 Chromium 經 UI adapter／service WebSocket 到兩個隔離 OpenSSH PTY；驗證輸入、輸出、resize、取消、結束及重開。 |
| V2 | 通過 | 驗證 UI-only token、拒絕缺少／錯誤／CLI token、非法來源、未知 alias、locked；未確認首次／變更 fingerprint 時不開 PTY，人工確認後可連線；browser Basic 未轉送，token 不出現在瀏覽器資產、URL、console、log 或一般回應。 |
| V3 | 通過 | 兩個並行 PTY 的獨立取消與瀏覽器 disconnect、service lock 關閉既有並拒絕新 PTY、明確 unlock、adapter／service shutdown 清理，以及 standalone 相容均通過。 |
| V4 | 通過 | 固定 `0.1.3` candidate 以 source SHA `49646597d11b33b3e42f2836dd471b67570b822c` 打包；15 個檔案、unpacked size 292,678 bytes；archive SHA-256 `241b6e8e42affeddfac737c6ef1335c3c48f39f1519f3c89986d052471efcb32`。隔離安裝、packlist、installed contents、兩個 CLI bin 與 standalone／service UI compatibility smoke 通過。 |

## 驗證與證據

執行環境：Windows worktree、Node.js `v24.20.0`、npm `11.19.0`、Playwright `1.64.1`、Chromium `156.0.8078.4`；真實 OpenSSH fixtures 使用 Ubuntu WSL transient units。測試 ports 為 UI `18792`、service API `18793`、兩個 OpenSSH targets `2227`／`2228`。測試啟動前及收尾後均核對 ports／transient units；本次驗收後 listener 與測試 unit 均已清理。

- 聚焦 Ticket 07：`node --test --test-concurrency=1 test/service-terminal.test.js`，3 pass、0 fail、0 skip。`ticket-07-terminal-20261120-08/` 驗證 abnormal upstream disconnect 修正；最終 HEAD 的聚焦案例亦包含於下列完整 suite `ticket-07-suite-20261120-07/`。
- 完整產品 suite：`npm test`，62 tests、38 pass、0 fail、24 skip，duration 約 96 秒。24 項是其他既有 Playwright／外部測試前置設定未提供而 skip；Ticket 07 service 與 standalone 真實 Chromium E2E 均有執行並通過。最終程式碼的證據：`docs/handoffs/sshdeck-system-integration/07/evidence/ticket-07-suite-20261120-07/`。
- `node --check` 覆蓋本票修改的 JavaScript 檔案，`git diff --check` 與 staged `git diff --cached --check` 均通過；完整 suite 的 `0.1.3` 版本與現有 service/API 測試亦通過。
- 聚焦測試紀錄確認 service、UI、fixture cleanup 均通過；fixture 記錄兩個 transient units 為 `not-found`、ports `2227`／`2228` free，並已移除本次隔離目錄。
- 先前測試失敗及其清理證據保留於本目錄的 `evidence/`；最終驗收以 `ticket-07-terminal-20261120-08` 與 `ticket-07-suite-20261120-07` 為準。較早 run 的失敗屬測試條件／斷言修正，已重跑受影響測試及完整 suite。新增的 abnormal upstream WebSocket close 回歸使用真實 service TCP socket destroy，並確認 PTY 清理後可重連。
- `npm run verify:package` 通過；實際 archive packlist 另以 `node scripts/verify-release-package.js --packlist docs/handoffs/sshdeck-system-integration/07/candidate/v0.1.3/packlist.json` 驗證，包含 5 項必要執行／文件／skill 檔。
- candidate：`docs/handoffs/sshdeck-system-integration/07/candidate/v0.1.3/agent-system-sshdeck-0.1.3.tgz`，size 75,304 bytes。完整 npm pack JSON 在同目錄 `packlist.json`，人類可讀清單在 `file-list.txt`，checksum 在 `SHA256SUMS`，provenance 在 `provenance.json`；15 個 packlist 檔案未包含 handoff 或測試證據。
- 以 archive 在 `C:\\Users\\andt3\\AppData\\Local\\Temp\\opencode` 下建立唯一隔離 prefix，執行 `npm install --prefix <prefix> --ignore-scripts --no-audit --no-fund <archive>`，安裝 12 個 packages；`verify-release-package.js --installed` 與安裝後 `agent-system-sshdeck host list`／`sshdeck host list` 兩個 bin shim 均通過。prefix 路徑、輸出與 exit code 保存在 `evidence/ticket-07-package-20261120-01/`；完成後已移除該唯一 prefix。
- `node scripts/smoke-release-package.js --installed <isolated-package-root>` 通過，實測安裝後 standalone root UI／assets/API CRUD 與 service `/sshdeck/` UI／assets/API CRUD；service CLI stopped、UI stopped、ports `18792`／`18793` free、`cleanupPassed: true`。完整 smoke evidence 同上。

## 文件授權、package 與發布限制

- README 與 `docs/service-api.md` 的文件提交授權已取得，且已於 `49646597d11b33b3e42f2836dd471b67570b822c` 分開提交；本輪沒有再修改兩份 gated 文件。
- handoff／evidence／candidate artifacts 將與產品 source 分開提交；package source SHA 固定為上述文件 commit，不包含此次 handoff/evidence commit。
- 本票沒有建立新 tag、push、npm publish 或公開 GitHub Release。V4 本地 candidate 已完成，任何外部發布仍未授權。

## 下一步

1. 獨立票級 reviewer 檢查產品提交、真實 E2E 證據與本地 candidate provenance；本 owner 不代替 reviewer。
2. 本目錄的 handoff、先前失敗及成功驗收證據、package candidate 與 V4 evidence 已與產品 source 分開提交，供 reviewer 查閱。
3. 不建立 tag、不 push、不 publish、不建立 GitHub Release；發布若有需求仍須另行取得明確授權。README／service API 若需再改，須再取得該批文件的明確授權。
