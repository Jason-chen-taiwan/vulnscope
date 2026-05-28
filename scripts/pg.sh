#!/usr/bin/env bash
# Local Postgres helper — uses Homebrew postgresql@16 directly (no Docker required).
# Cluster lives in ./.pgdata/, listens on port 55432.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PGDATA="$ROOT/.pgdata"
PORT=55432
PGBIN="/opt/homebrew/opt/postgresql@16/bin"
LOGFILE="$ROOT/.pgdata/postgres.log"
DBNAME="vulnscope"
DBUSER="vulnscope"
DBPASS="vulnscope"

export PATH="$PGBIN:$PATH"

cmd_init() {
  if [ -d "$PGDATA" ] && [ -f "$PGDATA/PG_VERSION" ]; then
    echo "[pg] cluster already exists at $PGDATA"
    return
  fi
  # If dir exists but isn't a cluster (e.g. failed prior init), wipe it
  if [ -d "$PGDATA" ]; then rm -rf "$PGDATA"; fi
  mkdir -p "$PGDATA"
  local PWF
  PWF="$(mktemp)"
  echo "$DBPASS" > "$PWF"
  initdb -D "$PGDATA" -U "$DBUSER" --pwfile="$PWF" --auth-local=trust --auth-host=md5 --encoding=UTF8 --locale=C
  rm -f "$PWF"
  cat >> "$PGDATA/postgresql.conf" <<EOF
port = $PORT
listen_addresses = '127.0.0.1'
unix_socket_directories = '$PGDATA'
EOF
}

cmd_start() {
  cmd_init
  if pg_ctl -D "$PGDATA" status > /dev/null 2>&1; then
    echo "[pg] already running on port $PORT"
  else
    pg_ctl -D "$PGDATA" -l "$LOGFILE" start
    # wait for accept connections
    for i in 1 2 3 4 5 6 7 8 9 10; do
      pg_isready -h "$PGDATA" -p $PORT > /dev/null 2>&1 && break
      sleep 0.5
    done
  fi
  # Use unix socket (-h $PGDATA) for admin tasks — local trust auth, no password
  if ! psql -h "$PGDATA" -p $PORT -U "$DBUSER" -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='$DBNAME'" | grep -q 1; then
    createdb -h "$PGDATA" -p $PORT -U "$DBUSER" "$DBNAME"
  fi
  psql -h "$PGDATA" -p $PORT -U "$DBUSER" -d "$DBNAME" -c "CREATE EXTENSION IF NOT EXISTS pg_trgm; CREATE EXTENSION IF NOT EXISTS btree_gin;" > /dev/null
  echo "[pg] ready: postgres://$DBUSER:$DBPASS@127.0.0.1:$PORT/$DBNAME"
}

cmd_stop() {
  pg_ctl -D "$PGDATA" stop -m fast || true
}

cmd_psql() {
  psql -h "$PGDATA" -p $PORT -U "$DBUSER" -d "$DBNAME" "$@"
}

case "${1:-}" in
  init)  cmd_init ;;
  start) cmd_start ;;
  stop)  cmd_stop ;;
  psql)  shift; cmd_psql "$@" ;;
  *) echo "usage: $0 {init|start|stop|psql}" >&2; exit 1 ;;
esac
