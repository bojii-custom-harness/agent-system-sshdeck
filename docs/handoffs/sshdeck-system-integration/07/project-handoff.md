# SSHDeck Ticket 07 專案交接

更新日期：2026-11-20

負責任務：SSHDeck Ticket 07 唯一產品實作 owner

## 基線與成果

- 權威工作項目：Agent System `.scratch/sshdeck-system-integration/issues/07-service-mode-terminal.md`；本票只修改 SSHDeck 產品 repo，未修改 Agent System issue、tickets、`test.md`、`execution-state.md` 或 Ticket 03／04。
- 基底：Ticket 01／02 已驗收的 SSHDeck integration `c2b96f437bcf1ae1122b113794292996aaca485f`。
- 產品程式碼提交：`35d75f52e090c084357418bdd4ea61757d66227c`（新增 service-mode 互動終端與 WebSocket bridge）、`e7017765a69a4781bfb8d5c1d11d18576b5a823f`（處理 service WebSocket 非正常關閉）、`1b32e86ecfccb8e3d36d892f62c45bce0ace2dcd`（保留 service shutdown 執行清理），以及 `3bcc715f3ac8b657ef5da4df55652a35ca2a5b42`（修正非法控制訊息及 HTTP default-port 來源驗證）。
- README／service API 文件提交：`49646597d11b33b3e42f2836dd471b67570b822c`（文件化 service-mode 互動終端契約）；README 版本/tag 範例另於 `265769e815d608d7bfc1ce7cb83fc46b74cbfd0c` 更新，改由 `package.json` 版本推送對應 tag。
- 目前產品版本：`0.1.3`；本機 V4 candidate 已由 source SHA `2107539cb4d1df65e071f01640e8c3406ed14e6f` 重建並完成 package 驗證，archive SHA-256 `69dea1146a326c59574a2bc2a068dce68b2c1fd55b584d610c2e027c0355a0ed`；僅本機候選，未發布。
- 產品程式與 README／service API 以獨立 source commits 保存；本目錄的 handoff、candidate 與 evidence 另行獨立提交，未納入 package source snapshot。

## 交付狀態

| 項目 | 狀態 | 證據／備註 |
| --- | --- | --- |
| T1：UI token 專用 service PTY WebSocket endpoint | 實作完成 | 驗證缺少／錯誤 token、CLI token、非法 Host／Origin、未知 alias 與 lock 拒絕。 |
| T2：server-side UI adapter bridge 與 service-mode UI | 實作完成 | upstream 固定使用設定的 service origin 與 server-side UI token；不轉送 browser Basic Authorization。 |
| T3：PTY input/output、resize、trust、取消、正常結束與資源清理 | 實作及真實驗收通過 | 並行 session、單獨取消、瀏覽器 disconnect、lock、adapter／service shutdown 與遠端 shell 結束後重開均有真實測試。 |
| T4：真實 service／隔離 OpenSSH／Chromium 測試與 standalone 相容 | 實作及驗收通過 | Ticket 07 service 與 standalone Chromium E2E 均使用真實隔離 WSL OpenSSH PTY，未以 mock SSH／WebSocket 取代。 |
| T5：文件與固定版本 package candidate | 本機 candidate 驗證完成；新版候選 review 待辦 | README／service API 契約於 `49646597d11b33b3e42f2836dd471b67570b822c` 提交；STD-F02 README tag 範例於 `265769e815d608d7bfc1ce7cb83fc46b74cbfd0c` 修正。V4 `0.1.3` candidate 已由 F03 source `2107539cb4d1df65e071f01640e8c3406ed14e6f` 重建，packlist、隔離安裝、兩個 CLI shim 與 standalone/service package smoke 通過；不代表 candidate reviewer PASS。 |
| V1 | 通過 | 真實 Chromium 經 UI adapter／service WebSocket 到兩個隔離 OpenSSH PTY；驗證輸入、輸出、resize、取消、結束及重開。 |
| V2 | 通過 | 驗證 UI-only token、拒絕缺少／錯誤／CLI token、非法來源、未知 alias、locked；未確認首次／變更 fingerprint 時不開 PTY，人工確認後可連線；browser Basic 未轉送，token 不出現在瀏覽器資產、URL、console、log 或一般回應。 |
| V3 | 通過 | 兩個並行 PTY 的獨立取消與瀏覽器 disconnect、service lock 關閉既有並拒絕新 PTY、明確 unlock、adapter／service shutdown 清理，以及 standalone 相容均通過。 |
| V4 | 本機 package 驗證通過；新版候選 review 待辦 | 目前 `0.1.3` candidate source SHA `2107539cb4d1df65e071f01640e8c3406ed14e6f`；15 個檔案、unpacked size 296,253 bytes、archive size 76,156 bytes、archive SHA-256 `69dea1146a326c59574a2bc2a068dce68b2c1fd55b584d610c2e027c0355a0ed`。npm SHA-1／SHA-512 integrity、packlist/source、隔離安裝、兩個 Windows CLI bin shim 與 standalone／service UI package smoke 均通過。舊 `265769e...` candidate archive 已於覆寫前保存並驗 hash；新版 targeted review 尚待原 reviewers 處理。 |

## 驗證與證據

執行環境：Windows worktree、Node.js `v24.20.0`、npm `11.19.0`、Playwright `1.64.1`、Chromium `156.0.8078.4`；真實 OpenSSH fixtures 使用 Ubuntu WSL transient units。測試 ports 為 UI `18792`、service API `18793`、兩個 OpenSSH targets `2227`／`2228`。測試啟動前及收尾後均核對 ports／transient units；本次驗收後 listener 與測試 unit 均已清理。

- 聚焦 Ticket 07：`node --test --test-concurrency=1 test/service-terminal.test.js`，3 pass、0 fail、0 skip。`ticket-07-terminal-20261120-08/` 驗證 abnormal upstream disconnect 修正；最終 HEAD 的聚焦案例亦包含於下列完整 suite `ticket-07-suite-20261120-07/`。
- 完整產品 suite：`npm test`，62 tests、38 pass、0 fail、24 skip，duration 約 96 秒。24 項是其他既有 Playwright／外部測試前置設定未提供而 skip；Ticket 07 service 與 standalone 真實 Chromium E2E 均有執行並通過。最終程式碼的證據：`docs/handoffs/sshdeck-system-integration/07/evidence/ticket-07-suite-20261120-07/`。
- `node --check` 覆蓋本票修改的 JavaScript 檔案，`git diff --check` 與 staged `git diff --cached --check` 均通過；完整 suite 的 `0.1.3` 版本與現有 service/API 測試亦通過。
- 聚焦測試紀錄確認 service、UI、fixture cleanup 均通過；fixture 記錄兩個 transient units 為 `not-found`、ports `2227`／`2228` free，並已移除本次隔離目錄。
- 先前測試失敗及其清理證據保留於本目錄的 `evidence/`；最終驗收以 `ticket-07-terminal-20261120-08` 與 `ticket-07-suite-20261120-07` 為準。較早 run 的失敗屬測試條件／斷言修正，已重跑受影響測試及完整 suite。新增的 abnormal upstream WebSocket close 回歸使用真實 service TCP socket destroy，並確認 PTY 清理後可重連。
- 歷史候選 source `265769e815d608d7bfc1ce7cb83fc46b74cbfd0c` 的 `npm run verify:package` 與舊 packlist 驗證結果保留於 `evidence/v4-rebuild-20261120-265769e-01/`；該結果不代表目前 F03 source。source `2107539...` 的新候選驗證見 `evidence/v4-rebuild-20261120-2107539-01/candidate-validation-summary.json`。
- 已被取代的 candidate source 為 `265769e815d608d7bfc1ce7cb83fc46b74cbfd0c`，archive SHA-256 `0db06a8fd40ff82bd27ce9200034a47ecffa1332fc1d59999f1196f520dadbc9`；重建前將 archive、SHA256SUMS、provenance、packlist 與 file list 保存並核 hash 至 `evidence/v4-rebuild-20261120-2107539-01/previous-candidate/`。目前 candidate 同一檔位已由新 source 重建，舊 archive 不可用來代表新 source。上上版 source `49646597d11b33b3e42f2836dd471b67570b822c` 與 archive `241b6e8e42affeddfac737c6ef1335c3c48f39f1519f3c89986d052471efcb32` 的歷史保存紀錄仍見舊 V4 evidence。
- 歷史 source `265769e...` 的隔離安裝／CLI shim 結果保留於舊 V4 evidence。新 source 的隔離安裝、installed verifier、逐檔比較與兩個 Windows CLI shim 結果均保存於 `evidence/v4-rebuild-20261120-2107539-01/`；Windows npm 唯一安裝正規化為 `bin/sshdeck.js` shebang CRLF→LF。首次 shim 輸出已遮蔽，安全重跑使用隔離 `SSHDECK_HOME`。
- 舊 source `265769e...` 的 package smoke 證據保留於 `evidence/v4-rebuild-20261120-265769e-01/`。新 source smoke 另行通過 standalone root 與 mounted `/sshdeck/` UI／assets/API CRUD、service health；UI/service stopped、ports `18792`／`18793` free，cleanup 與 prefix/staging 清理見 `evidence/v4-rebuild-20261120-2107539-01/cleanup.json`。

## Review 修正（2026-11-20）

- 唯一 source/test commit：`3bcc715f3ac8b657ef5da4df55652a35ca2a5b42`，只包含 `lib/service-server.js`、`test/service-terminal.test.js`、`test/helpers/service-process.js`、`scripts/service-process-worker.js`；README、service API、handoff 與 evidence 未納入該 commit。
- `SSHDECK-07-SPEC-01` 根因：JSON `null` 等非 object frame 在讀取 `message.type` 時會丟出未處理 `TypeError`，使 service process 結束；resize 邊界錯誤則被靜默忽略。預防：先驗證 frame 為非 null、非 array object；未知／不合法控制 frame 及非整數或不在 1–1000 範圍的 resize 都回報 `INVALID_TERMINAL_FRAME` 並關閉該 session。真實 service 回歸涵蓋 `null`、`true`、`[]`、`{}` 與六種 resize 邊界／型別；每次拒絕後確認 survivor PTY 可輸入／輸出、service health 仍為 200，且 active terminal 清為 0。Red 根因與修復後證據分別見 `evidence/review-fixes-20261120-06-red-structure-e520fda266af4f1c90b1e239ea5b3867/structure.json`、`evidence/review-fixes-20261120-10-green-targeted-6d91bf8883b6483d956e11d03fb5b38a/structure.json`、`resize.json`。
- `SSHDECK-07-STD-F01` 根因：Node URL 會正規化省略的預設 port，`Number(hostUrl.port)` 因空字串成為 0，導致合法 HTTP port 80 authority 被拒絕。預防：以 URL scheme 的預設值計算 Host／Origin 有效 port，兩者均須等於實際 listener port，並保留來源協定白名單及 Host/Origin authority 比對。真實 port 80 service／PTY 成功連線，錯誤 port 與 HTTPS default-port Origin 仍拒絕；證據見 `evidence/review-fixes-20261120-10-green-targeted-6d91bf8883b6483d956e11d03fb5b38a/http80.json`。
- 聚焦回歸命令：`node --test --test-concurrency=1 --test-reporter=tap --test-name-pattern=ticket07-review test/service-terminal.test.js`；Node `v24.20.0`，3 pass／0 fail／0 skip，32,110 ms。證據目錄：`evidence/review-fixes-20261120-10-green-targeted-6d91bf8883b6483d956e11d03fb5b38a/`。
- 全套回歸命令：`npm test`（以 `cmd.exe /d /s /c "npm.cmd test"` 執行）；Node `v24.20.0`、npm `11.19.0`、timeout 180,000 ms，exit 0，66 tests／42 pass／0 fail／24 skip，125,090 ms。真實 service、兩個隔離 WSL OpenSSH 與 Chromium E2E 均在本輪執行。證據：`evidence/review-fixes-20261120-11-npm-test-fef74c1d59d743e480c92b13a2097230/`。
- 清理：聚焦測試三組 service／fixture 均回報 passed、active terminals 0、fixture ports `2227`／`2228` 清理、service process exit 0、臨時目錄移除；全套測試後 cleanup 記錄無 Windows listener／相關 process／剩餘 temp dir，WSL Ticket07 units 與 `2227`／`2228` listener 已清除。剩餘失敗重試與 runner 診斷輸出保留於同一 `evidence/` 目錄，未混入 source commit。
- 本次改動已實作並通過自身回歸，尚待原 Spec／Standards reviewers 對已修正的 `SSHDECK-07-SPEC-01`、`SSHDECK-07-STD-F01` 進行 targeted re-review；owner 不自行標示 review PASS。
- `SSHDECK-07-STD-F02` 已於 README commit `265769e815d608d7bfc1ce7cb83fc46b74cbfd0c` 修正：`npm version patch` 後從 `package.json` 讀取實際版本並推送 `"v$version"`。此處只修改範例；本輪未執行 `npm version`、建立 tag、push、publish 或 Release。

## 文件授權、package 與發布限制

- README 與 `docs/service-api.md` 的文件提交授權已取得；service-mode 契約於 `49646597d11b33b3e42f2836dd471b67570b822c` 提交，README tag 範例另於 `265769e815d608d7bfc1ce7cb83fc46b74cbfd0c` 單獨提交。
- 本地 V4 candidate source SHA 固定為 `2107539cb4d1df65e071f01640e8c3406ed14e6f`；舊 `265769e...` archive SHA `0db06a8...` 已另存於新 evidence，candidate、handoff 與新 evidence 依本批明確授權提交，不改變 package source snapshot。
- 本票沒有建立新 tag、push、npm publish 或公開 GitHub Release。V4 本地 candidate 已完成，任何外部發布仍未授權。

## 下一步

1. 主 agent 安排原 Spec／Standards reviewers 針對 source `2107539...` 的本地 V4 candidate 執行必要 targeted review；F03 固定 source range 的既有 review 結果依 integration `test.md` 記錄，owner 不自行標示新版 candidate review PASS。
2. 本次 candidate、handoff 與唯一新 evidence subtree `evidence/v4-rebuild-20261120-2107539-01/` 依授權獨立提交；既有 `review-fixes-20261120-01` 至 `-13` evidence 原樣保留，`-01` 至 `-11` 內容未讀未改。
3. 不建立 tag、不 push、不 publish、不建立 GitHub Release；發布若有需求仍須另行取得明確授權。README／service API 若需再改，須再取得該批文件的明確授權。

## Ticket 07 V4 candidate 以 F03 source 重建（2026-11-20）

- 採用主控 integration 權威 `test.md` SHA-256 `5869D5B69C3E661B7B1F7FE19751D632A1FEA85CE6A3FA2D4809D9CC186AC854`；產品 source 固定為 `2107539cb4d1df65e071f01640e8c3406ed14e6f`／tree `1ef22754b0be9a02de8dd67395768956cc1b794b`。`npm run verify:package`、`npm pack --json`、packlist 驗證與 archive/source 逐檔 bytes 核對均 exit 0。
- 新 `0.1.3` candidate SHA-256 為 `69dea1146a326c59574a2bc2a068dce68b2c1fd55b584d610c2e027c0355a0ed`（76,156 bytes；15 files／296,253 unpacked bytes）。先前 source `265769e815d608d7bfc1ce7cb83fc46b74cbfd0c` 的 archive SHA-256 `0db06a8fd40ff82bd27ce9200034a47ecffa1332fc1d59999f1196f520dadbc9` 在任何覆寫前已複製到新 evidence 並核 hash；兩個來源不可混用。
- `npm install --prefix <unique-prefix> --ignore-scripts --no-audit --no-fund <candidate>` exit 0，新增 12 packages；installed verifier、15 個檔案的 source／archive／安裝內容比較、兩個 Windows CLI shim、standalone 與 service package smoke 均通過。只執行 package 必要驗證；未重跑 source 未變更的完整 suite（69 tests／38 pass／0 fail／31 skipped，依 canonical test baseline 摘要）。
- Smoke 使用 ports `18792`／`18793`，standalone 與 `/sshdeck/` UI、assets、API CRUD 及 service health 通過；服務、ports、smoke temp dir 均確認清理。isolated install prefix、npm pack staging 與 candidate replacement 已精確移除；完整 raw output、config、metadata、sha 與 cleanup 記錄位於 `evidence/v4-rebuild-20261120-2107539-01/`。
- 此工作未修改產品 source、README 或 `docs/service-api.md`，未修改 Agent System issue／`test.md`／`execution-state.md`；未建立 tag、push、npm publish 或 GitHub Release。新版 candidate targeted review 尚待主 agent 安排，owner 不宣稱 reviewer PASS。
