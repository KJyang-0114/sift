# 安全政策 / Security Policy

## 支援版本

只有最新的 release 會收到安全修正。

| 版本 | 支援 |
|---|---|
| 最新 release | ✅ |
| 更舊的版本 | ❌ |

## 回報漏洞

**請不要用公開 issue、pull request 或討論區回報 Sift 本身的安全漏洞。**

請到本 repo 的 **Security → Report a vulnerability**（[私下回報](https://github.com/KJyang-0114/sift/security/advisories/new)）。內容只有維護者看得到，請盡量附上：

- 受影響的版本與平台
- 重現步驟或概念驗證
- 可能的影響（例如：讀取掃描範圍外的檔案、執行任意指令、報告遺漏 findings）

處理流程：

1. 7 天內回覆收到。
2. 在私密 advisory 與私有 fork 中確認並修正。
3. 發布修正版後公開 advisory，並視情況申請 CVE；回報者會被列名致謝（除非你不希望）。

## 範圍

屬於本政策：Sift CLI、`install.sh`、release 產物、GitHub Actions 設定。

不屬於本政策：

- Sift 掃描**你的專案**時找到的漏洞（那是掃描結果，請在你的專案處理）。
- 第三方依賴已公開的 CVE：請直接開 PR 升級，或等 dependabot 更新。
- 規則誤報／漏報：請開一般 issue。

---

**English:** Please do not report security vulnerabilities in Sift through public issues or pull requests. Use [private vulnerability reporting](https://github.com/KJyang-0114/sift/security/advisories/new) instead. We aim to acknowledge reports within 7 days and will coordinate disclosure after a fix is released.
