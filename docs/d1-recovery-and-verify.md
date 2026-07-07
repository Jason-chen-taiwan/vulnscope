# D1 恢復 + 增量機制驗證 步驟卡

**背景**：正式 D1 `vulnscope`(id `9cdd7df2-6e0e-4586-a3e8-bc5dc7736f78`，Workers Paid）
目前處於間歇性 `CPU time limit exceeded [code: 7429]` 的 reset 閃爍狀態。
成因：先前對 74k 列 / 286MB 的庫跑了多次全表掃描（`SELECT count(*)`）+
大批次 import，把它推進 reset 迴圈。

**重要**：網站 `vulnscope.dev` 一直正常（Worker binding 路徑健康）。
壞的只是 wrangler/CI 的 REST query/import 路徑。

---

## Step 1 — 等 D1 自癒（不要碰它）

每次失敗的 import + retry 都在加重 reset 迴圈。**至少靜置 30–60 分鐘**，
期間不要對它跑任何查詢或 push。

## Step 2 — 確認恢復（輕量、只讀、indexed）

過一段時間後，用 `!` 前綴在本機跑（連續 3 次都秒回結果 = 穩了）：

```
! node_modules/.bin/wrangler d1 execute vulnscope --remote --command="SELECT cve_id FROM vulnerabilities WHERE cve_id='CVE-2021-44228'"
```

- ✅ 回 `"cve_id": "CVE-2021-44228"` → 穩了，進 Step 3
- ❌ 回 `exceeded [code: 7429]` → 還沒好，再等
- ⚠️ **不要**跑 `SELECT count(*)`（全表掃描會再次觸發 reset，前功盡棄）

## Step 3 — 小範圍增量 CI 驗證（npm only）

D1 穩定後，GitHub → Actions → **"Ingest → D1"** → **Run workflow**：
- `incremental` = ✅ **true**
- `ecosystems` = `npm`（只一個生態系，最小、最安全）
- Run

看 CI log：`Build SQLite — incremental` 應顯示 `changed=… imported=…`，
`Push to D1 (incremental delta)` 應顯示 `delta applied in N batch(es)`。

- ✅ 成功 → 增量機制在真實 CI + 正式 D1 上通了。進 Step 4。
- ❌ 又倒在 Push（7429）→ 見下方「若 npm 仍失敗」。

## Step 4 — 逐步放大

npm 成功後，重跑 workflow，`ecosystems` 依序放大：
1. `npm,PyPI,crates.io`
2. 留空（= 全 13 個生態系，冷啟 7 天）

每次都看 `delta applied`。全 13 個成功後，每日 5am cron 會自動接手，
不用再手動觸發。

---

## 若 npm 增量仍失敗（D1 已確認穩定的前提下）

那才證明**不是 reset 閃爍**，而是 delta 推送模式本身對這個大 D1 太重。
候選解法（依序考慮）：

1. **縮小 push 批次**：`scripts/push-to-d1.sh` 的 `per=150`（約 line 392）
   改小到 `per=25` 或更小，讓每個 `d1 execute` 請求更輕。

2. **改用 `wrangler d1 import`**：D1 有專用批量 import API，比逐批
   `d1 execute --file` 更適合大量寫入、較不易撞單請求 CPU 上限。
   需改寫 `push-to-d1.sh` 的 delta 套用步驟。

3. **N+1 架構重構**（packages 自然主鍵）：消除 affected/FTS 每筆的
   `(SELECT id FROM packages WHERE eco+name)` 子查詢。這是真實的技術債，
   但要改 schema + ~18 處查詢（queries.ts/insights.ts）+ 重灌 D1。
   只有在確認 N+1 是實際瓶頸後才值得投入。

---

## 已完成 / 已在 main 的東西（供參考，不用重做）

- 增量 OSV ingest 功能完整實作並合併進 main（14 commits）
- 手動觸發增量的選項（`incremental` input）已加入 workflow
- 所有程式在 throwaway D1 上驗證通過（C1 id 碰撞、C2 FTS rowid、sentinel 分批都修好且驗證）
- 231 測試 + tsc 綠

**尚未驗證的唯一一件事**：增量 delta 推**正式（大）D1** 是否順利 —— 卡在 D1 目前不穩。
這張卡就是為了完成這最後一哩。
