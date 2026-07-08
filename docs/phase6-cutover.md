# Phase 6 — Cloudflare Cutover Runbook

Go-live steps to move VulnScope from fly.io to Cloudflare Workers + D1.
Code is merged to `main`; prod D1 `vulnscope` is created
(id `9cdd7df2-6e0e-4586-a3e8-bc5dc7736f78`) and `wrangler.jsonc` points at it.

## Prereqs (done)
- [x] Branch merged to main (217 tests + tsc green)
- [x] Prod D1 `vulnscope` created
- [x] `wrangler.jsonc` DB binding → `vulnscope`
- [x] Full seed SQLite built at `scratch-phase0/vulnscope.sqlite` (74,280 CVEs, 292 MB)

## Step 1 — Enable Workers Paid (you, in Cloudflare dashboard)
Cold seed writes ~677k row-units; free D1 is 100k/day. Workers Paid ($5/mo,
includes 50M writes/mo) lets it complete in one shot. **You can downgrade
back to free after seeding** — steady-state daily deltas are tiny.

Dashboard → Workers & Pages → Plans → enable **Workers Paid**.

## Step 2 — Cold-seed prod D1 (one command, after Paid is on)
```bash
cd ~/Desktop/Yansiang/cve_list
SQLITE_FILE=scratch-phase0/vulnscope.sqlite bash scripts/push-to-d1.sh vulnscope full
```
Verify:
```bash
wrangler d1 execute vulnscope --remote --command="SELECT count(*) FROM vulnerabilities"   # expect 74280
wrangler d1 execute vulnscope --remote --command="SELECT count(*) FROM vulns_fts"          # expect 74280
wrangler d1 execute vulnscope --remote --command="SELECT name FROM packages_fts WHERE packages_fts MATCH 'log4' LIMIT 3"
```

## Step 3 — Deploy the Worker
```bash
NEXT_PUBLIC_SITE_URL=https://<your-domain> pnpm deploy   # opennextjs-cloudflare build && deploy
```

> **Deploy gotchas (learned the hard way, 2026-07-08):**
> 1. **Always pass `NEXT_PUBLIC_SITE_URL`** on the deploy command line. `next build`
>    reads `.env.local`, which typically carries `http://localhost:3000` for dev —
>    without the override, production canonical/hreflang metadata silently points
>    at localhost (SEO poison, invisible unless you view source).
> 2. **Verify the version actually serves.** `pnpm deploy` may print
>    `Current Version ID: <id>` but leave it *uploaded, not routed* (output says
>    "Deployed vulnscope triggers" instead of a routes line). Check with
>    `wrangler deployments list`; if the latest deployment predates your upload:
>    `wrangler versions deploy <version-id>@100% -y`
> 3. **KV populate can 403.** The deploy's populate-cache step bulk-writes to the
>    `NEXT_INC_CACHE_KV` namespace; some networks get an HTML 403 (Cloudflare edge
>    challenge, has a Ray ID — not a token problem) which aborts the whole deploy.
>    Workaround: temporarily disable `incrementalCache` in `open-next.config.ts`
>    (see git history) or deploy from another network. The KV cache is a
>    second-layer optimization; the site is fully functional without it.

Note the `*.workers.dev` URL it prints. Smoke test:
```bash
curl -s https://<worker-url>/en/cve/CVE-2021-44228 | grep -i "log4j"   # data renders
curl -sI https://<worker-url>/en/search | grep -i cache-control          # no-store (not cached)
```

## Step 4 — Set the ingest secret (GitHub repo)
GitHub → repo Settings → Secrets and variables → Actions → New secret:
- Name: `CLOUDFLARE_API_TOKEN`
- Value: a Cloudflare API token with **D1 edit** scope (My Profile → API Tokens → Create).
Then trigger a manual ingest to confirm the pipeline: Actions → "Ingest → D1" → Run workflow (delta).

## Step 5 — Point the domain (Cloudflare)
Workers & Pages → your Worker → Settings → Domains & Routes → Add custom domain
→ your domain. Cloudflare provisions HTTPS automatically.
Add the edge Cache Rule from `docs/edge-caching.md` (Caching → Cache Rules).
Set `.env`/deploy `NEXT_PUBLIC_SITE_URL=https://<domain>` and redeploy.

## Step 6 — Downgrade to free (optional, after seed confirmed)
Once seeded and stable, downgrade Workers Paid → Free. Steady-state daily
KEV/EPSS deltas stay under the 100k/day write cap. Cost returns to $0.

## Step 7 — Decommission fly.io (after a few stable days)
```bash
fly apps destroy vulnscope-tw
```
Keep `deploy/oracle/` in the repo as a fallback if the D1 path ever needs it.

## Rollback
If anything breaks, fly.io is still live until Step 7. Just don't cut DNS
(Step 5) until the Worker smoke tests pass.
