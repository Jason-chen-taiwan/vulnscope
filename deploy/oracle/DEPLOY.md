# 部署到 Oracle Cloud「Always Free」VM

把 VulnScope 的 web + worker + Postgres 全部跑在**一台永久免費**的 Oracle VM 上,取代 fly.io($0/月)。

> ⚠️ **先讀這段風險**:Oracle 免費 VM 若 7 天內 CPU 95 百分位 < 20% 可能被回收;偶爾也會無預警停用。你的 worker 每天跑 1–2h ingest 會拉高 CPU,天然降低被回收機率;再加上 `backup.sh` 每日備份,被回收時幾分鐘就能重建。**別把它當唯一資料來源** —— 幸好 CVE 資料本來就能重新 ingest。

---

## 1. 註冊 Oracle Cloud + 開一台 VM

1. 到 <https://www.oracle.com/cloud/free/> 註冊(要驗證信用卡,**不扣款**)。選離你近的 region(台灣選 **Japan Central (Osaka)** 或 **Singapore**)。
2. 建立 Instance:**Compute → Instances → Create Instance**
   - Image:**Ubuntu 22.04**(Canonical Ubuntu)
   - Shape:**Ampere (ARM) `VM.Standard.A1.Flex`**,設 **2 OCPU / 12 GB**(2026/6/15 起免費上限)。
     - 若 A1 顯示「out of capacity」,多換幾個時段/AD 重試,或先用 AMD `VM.Standard.E2.1.Micro`(1/8 vCPU,較小但也是 Always Free)撐著。
   - **存好 SSH private key**(建立時下載)。
3. **開放 3000 port**:VCN → Security List → 加 **Ingress Rule**:Source `0.0.0.0/0`,TCP,Dest port `3000`。(Cloudflare 會從外部連到這個 port。)

---

## 2. 連上 VM,裝 Docker

```bash
ssh -i /path/to/your-key ubuntu@<VM_PUBLIC_IP>

# Docker + compose plugin
sudo apt-get update && sudo apt-get install -y ca-certificates curl git
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker ubuntu
# Ubuntu 的 iptables 預設會擋掉 Oracle Security List 允許的埠,補一條:
sudo iptables -I INPUT 6 -p tcp --dport 3000 -j ACCEPT
sudo netfilter-persistent save 2>/dev/null || sudo apt-get install -y iptables-persistent
exit   # 重新登入讓 docker 群組生效
```

重新 `ssh` 進來。

---

## 3. 取得程式碼 + 設定

```bash
git clone https://github.com/<你的帳號>/<repo>.git cve_list
cd cve_list

cp deploy/oracle/env.example deploy/oracle/.env
nano deploy/oracle/.env          # 填 POSTGRES_PASSWORD / NEXT_PUBLIC_SITE_URL / ADMIN_TOKEN 等
```

> **Pro tier**:若這台要含 Pro 功能,確保 `git clone` 出來的 checkout 裡有 `pro/` 目錄(私有 repo)。沒有的話 build 會自動 fallback 到 `pro-stub`(OSS-only,Pro 路由 404),站台仍正常運作。

---

## 4. 啟動

```bash
docker compose -f deploy/oracle/docker-compose.oracle.yml up -d --build
```

第一次會 build image + 跑 migrate(建 schema),再啟動 web / worker。查看:

```bash
docker compose -f deploy/oracle/docker-compose.oracle.yml ps
docker compose -f deploy/oracle/docker-compose.oracle.yml logs -f web
curl http://localhost:3000/api/health
```

瀏覽器開 `http://<VM_PUBLIC_IP>:3000` 應該看得到站台。

---

## 5. 資料(不用搬,worker 會自己抓)

**什麼都不用做。** worker 容器啟動後約 **10 秒**就會自動跑第一次 full refresh(`src/lib/scheduler.ts`),把 KEV / OSV / EPSS 最新資料灌進空的 DB,之後每 24h 一次。第一次跑約 **1–2 小時**,期間站台可正常瀏覽(只是資料逐步補齊)。

看進度:
```bash
docker compose -f deploy/oracle/docker-compose.oracle.yml logs -f worker
# log 出現 "[scheduler] refresh done in ..." 就代表第一輪灌完了
```

想立刻手動再觸發一次(可選):
```bash
curl -XPOST "http://localhost:3000/api/v1/admin/refresh?token=$ADMIN_TOKEN"
```

---

## 6. 每日備份(重要 —— 防被回收)

```bash
mkdir -p ~/backups
crontab -e
# 加這行(每天 05:00 dump,保留 7 天):
0 5 * * *  /home/ubuntu/cve_list/deploy/oracle/backup.sh >> /home/ubuntu/vulnscope-backup.log 2>&1
```

**強烈建議**再把備份推到 off-box(VM 被回收時備份不會一起消失)。Cloudflare R2 免費 10 GB:
1. `sudo apt-get install -y rclone && rclone config`,建一個名為 `r2` 的 remote(用 R2 的 S3 相容金鑰)。
2. 把 `backup.sh` 底部 `rclone copy … r2:` 那行取消註解。

---

## 7. 綁網域 + HTTPS(Cloudflare DNS 指到 VM IP)

你的網域 DNS 在 Cloudflare 管,用最少步驟接:讓 Cloudflare 指到 VM 的 IP,HTTPS 由 Cloudflare 那層處理。

1. **加 DNS 記錄**
   - Cloudflare 後台 → 你的網域 → **DNS → Records → Add record**
   - Type `A`,Name 填 `@`(或 `www` / 你要的子網域),IPv4 填 **VM 的公開 IP**
   - **Proxy status 設「Proxied」(橘色雲)** —— 這樣訪客連到的是 Cloudflare 的 HTTPS,VM 的真實 IP 也被隱藏。

2. **設 SSL 模式 + 導到 3000 port**
   - Cloudflare 預設從 443 連來,但你的 app 在 3000。有兩個做法擇一:
     - **(簡單)** SSL/TLS → Overview → 設 **Flexible**;再到 **Rules → Origin Rules** 建一條把連入導到 origin port `3000`。
     - **(更簡單,免 Origin Rule)** 直接在 VM 上把 web 發佈到 80 port:把 compose 裡 web 的 `ports:` 改成 `"80:3000"`,Oracle Security List + iptables 改開 80。這樣 Cloudflare(Flexible)預設就走 80,不用額外規則。
   - SSL 模式 **Flexible** 代表「訪客↔Cloudflare 是 HTTPS,Cloudflare↔VM 是 http」。夠用且不用在 VM 弄憑證。

3. 把 `.env` 的 `NEXT_PUBLIC_SITE_URL` 設成 `https://你的網域`,重建 web:
   ```bash
   docker compose -f deploy/oracle/docker-compose.oracle.yml up -d --build web
   ```
   開 `https://你的網域` 應該就看得到站台。

> **想更安全再升級**:把 SSL 模式從 Flexible 換成 Full,那時 CF↔VM 這段需要憑證。最省事是裝一張 **Cloudflare Origin Certificate**(CF 免費簽、15 年效期)到 VM 的反代;或改用第 §4 提過的 Tunnel。現在先 Flexible 跑起來即可,之後要升級跟我說。

---

## 常用維護指令

```bash
# 更新程式(git pull 後重建)
cd ~/cve_list && git pull && \
  docker compose -f deploy/oracle/docker-compose.oracle.yml up -d --build

# 看 worker ingest 進度
docker compose -f deploy/oracle/docker-compose.oracle.yml logs -f worker

# 手動備份一次
./deploy/oracle/backup.sh
```

---

## 之後清掉 fly.io

站台在 Oracle 上確認正常、資料也搬好、DNS 也切過去之後,再:
```bash
fly apps destroy vulnscope-tw
```
(先確認 Oracle 這邊穩定跑幾天再砍 fly,才有退路。)
