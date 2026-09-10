# 2026-09-09：接手檢查與研究交接

## 範圍

基準為 `c291fff`，檢查另一位 Astra 留下的 8 個未提交檔案；沒有新增 subagent。此文件是進度紀錄，並非已完成的產品研究報告。

## 已確認

- TestGenerator 已移除 Orbital 的主機執行呼叫。預設停用執行；啟用時因缺乏 container backend 回報錯誤 diagnostic。
- securepath 的相對路徑以 baseDir 解讀，實際讀寫使用 `os.OpenRoot`；新增外部 symlink 與內部相對 symlink 測試。
- `Config.Validate` 集中驗證設定；明確指定的 TOML 檔案拒絕未知欄位。
- 接手時 `go test ./... -count=1` 全部通過。這不能取代漏洞偵測品質 benchmark。

## 本次補齊

`fix` 原本沒有呼叫新增的 `Config.Validate`，使 `scan` 和 `fix` 對無效設定行為不同。現在兩個入口都在開始掃描前拒絕無效設定。新增五種錯誤設定的 CLI 回歸測試，並更新 MIGRATION.md。

## 尚未解決，依優先序

1. `fix` 對部分掃描失敗仍會繼續，最後可能回傳成功；不能讓 CI 把不完整掃描當成完整成功。應保存原始掃描錯誤，在輸出修復建議後維持非零退出碼。
2. TestGenerator 仍先呼叫模型，生成內容既未執行也未輸出。會花費模型成本卻沒有可用產物。下一步需選定「停用時提前略過」或「明確提供生成 artifact」；不能宣稱已完成測試驗證。
3. `executionFindings` 與 Orbital 舊模組仍保留；執行失败不等於已證實的產品漏洞，不能直接沿用為未來 container runner 的判定標準。
4. `fix` 的 Fixed 狀態仍代表生成 patch，非已套用且通過測試；不要用它宣稱修復成功率。

## 產品研究：保留反證，避免重新走回原定位

資料查核日：2026-09-08；下列為來源描述的能力，尚未做競品實測。

- 通用 scanner、BYOK reviewer、SARIF、repo memory 均不足以形成 moat。Semgrep Guardian 已進入 agent 掃描與依賴防護工作流。[官方文件](https://docs.semgrep.dev/semgrep-guardian/overview)
- 「執行後附證據」也不是空白市場。Greptile TREX 已描述 disposable sandbox、腳本、API trace 與執行 artifact。[工程說明，2026-06-17](https://www.greptile.com/blog/trex-code-execution)
- 「RLS 租戶隔離 CI」已有直接開源替代品；tenant-guard 描述讀寫隔離與多種執行檢查。[專案](https://github.com/FedericoTs/tenant-guard)
- 更窄的「migration 前後權限 diff」仍有直接競品。pgrls 描述 semantic policy diff、Z3、暫存資料庫 migration 套用及 pytest 整合；Atlas 提供 RLS policy 與 migration lint。因此不能把這個方向直接當作研究結論。[pgrls](https://github.com/pgrls/pgrls)、[Atlas](https://atlasgo.io/guides/rls-policy)
- pgTAP 加上 coding agent 是必須比較的免費替代方案。[資料庫測試文件](https://supabase.com/docs/guides/database/testing)

目前沒有證據證明 Sift 已有可防守的市場位置，也沒有完成使用者訪談。下一份正式研究應包含候選方向淘汰表、1 位全職開發者的 3–6 個月條件式版本，以及明確停止投入門檻。不得以新增功能數代替採用驗證。

Benchmark 必須分開真實 bug、人工 mutant、乾淨變更；比較 precision、recall、每百次乾淨 PR 誤擋數、無法分析比例、設定與維護時間。按 repository 分割 holdout，凍結工具與模型版本。只有被維護者修掉的評論不代表完整 ground truth。[Martian 方法](https://github.com/withmartian/code-review-benchmark)、[PrimeVul 論文](https://arxiv.org/abs/2403.18624)
