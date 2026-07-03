#!/usr/bin/env bash
# Daily Postgres backup for the Oracle VM.
#
# Oracle "Always Free" VMs can be reclaimed (7-day <20% CPU) or, rarely,
# suspended without warning. The CVE data is re-ingestible, but a nightly
# dump means you rebuild in minutes instead of re-running the 1-2h ingest.
#
# Install as a cron job on the VM (see DEPLOY.md), e.g.:
#   0 5 * * *  /home/ubuntu/cve_list/deploy/oracle/backup.sh >> /var/log/vulnscope-backup.log 2>&1
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/home/ubuntu/backups}"
KEEP_DAYS="${KEEP_DAYS:-7}"
CONTAINER="${CONTAINER:-vulnscope-postgres}"
DB_USER="${DB_USER:-vulnscope}"
DB_NAME="${DB_NAME:-vulnscope}"

mkdir -p "$BACKUP_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$BACKUP_DIR/vulnscope-$STAMP.sql.gz"

echo "[$(date)] dumping $DB_NAME -> $OUT"
docker exec "$CONTAINER" pg_dump -U "$DB_USER" -d "$DB_NAME" --no-owner \
  | gzip > "$OUT"

echo "[$(date)] done ($(du -h "$OUT" | cut -f1)); pruning >$KEEP_DAYS days"
find "$BACKUP_DIR" -name 'vulnscope-*.sql.gz' -mtime +"$KEEP_DAYS" -delete

# Optional: push off-box to Cloudflare R2 (free 10 GB) so a VM loss
# doesn't take the backups with it. Uncomment and configure rclone first
# (rclone config -> "r2" remote). See DEPLOY.md.
# rclone copy "$OUT" r2:vulnscope-backups/ && echo "[$(date)] uploaded to R2"
