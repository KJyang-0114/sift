# 審查與合併流程

所有變更都經由 GitHub Pull Request 進入 `main`，討論、退回與合併紀錄都留在 PR 上。

## 流程

1. 開發者（含 AI agent）從 `main` 開分支，命名為 `類型/簡述`，例如 `ci/release-automation`、`feat/osv-vulnerability-scan`。
2. Push 分支並開 PR，依 [PR 模板](../.github/pull_request_template.md) 填寫目的、變更、驗證與審查重點。
3. CI 自動執行；`quality` 與三平台 `build` 必須通過。
4. 審查者在 PR 的 **Files changed** 對程式碼留言（手機 GitHub App 也可以）。
5. 開發者修正後 push 到同一分支並回覆留言；審查者確認後按 **Resolve conversation**。
6. CI 全綠、所有留言都 resolve 之後，由審查者按 **Squash and merge**。分支合併後自動刪除。

## 審查者的操作

| 想做的事 | 操作 |
|---|---|
| 要求修改（退回） | 在程式碼行或 PR 留言說明問題，不要 resolve；未 resolve 的討論會擋住合併 |
| 只是提問 | 留言；回答後自行 resolve |
| 放棄這個方向 | Close pull request，並留言原因 |
| 同意合併 | 確認 CI 全綠後 Squash and merge |
| 暫緩 | 加上 `on-hold` label |

由於 PR 作者與審查者目前使用同一個 GitHub 帳號，GitHub 不允許對自己的 PR 送出 Approve／Request changes，因此改以「未 resolve 的留言擋合併」作為退回機制，合併按鈕只由審查者操作。

## `main` 分支規則（GitHub ruleset：`main protection`）

- 必須透過 PR 合併，禁止直接 push、force push 與刪除分支。
- 必須通過 `quality`、`build (ubuntu-latest)`、`build (macos-latest)`、`build (windows-latest)`。
- 所有 review 討論必須 resolve。
- 只允許 squash merge；PR 標題即為 `main` 上的 commit 訊息。
- Repo 管理員保留緊急 bypass，平時不使用。

## Labels

- 類型：`ci`、`feature`、`security`、`docs`、`bug`
- 狀態：`on-hold`
