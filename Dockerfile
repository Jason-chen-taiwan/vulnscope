# Multi-stage Dockerfile for VulnScope.
# Result: ~70-100MB image with standalone Next.js + tsx for ingest scripts.
#
# Build requires BuildKit (Fly enables this automatically). The Pro
# tier (private repo) is fetched at build time via a deploy-key SSH
# secret mount; nothing about the key ever lands in an image layer.
# Self-hosters who build without the secret get an OSS-only image
# that silently 404s the Pro routes (next.config.ts aliases @pro/*
# to ./pro-stub/ when ./pro is missing).

# ---------- deps ----------
FROM node:22-alpine AS deps
WORKDIR /app
RUN apk add --no-cache libc6-compat
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
# pnpm 11 hard-fails when ANY transitive dep has an unapproved postinstall
# script. The documented escape hatch for non-interactive environments
# is `--config.dangerouslyAllowAllBuilds=true`; fall back to
# `--ignore-scripts` if the installed pnpm version rejects that flag.
RUN corepack enable && \
    (pnpm install --frozen-lockfile --config.dangerouslyAllowAllBuilds=true \
     || pnpm install --frozen-lockfile --ignore-scripts)

# ---------- pro ----------
# Optional stage: pulls the private vulnscope-pro repo into /pro using
# an SSH deploy key passed via `--secret id=pro_deploy_key_b64`.
# Without the secret (= self-host build), the folder is left empty
# and the builder's webpack alias falls through to ./pro-stub.
FROM alpine/git AS pro
WORKDIR /work
RUN apk add --no-cache openssh-client
RUN mkdir -p /root/.ssh && ssh-keyscan github.com >> /root/.ssh/known_hosts
# Cache-bust per build so we always pull the latest vulnscope-pro tip
# even when the deploy key + script haven't changed.
ARG PRO_CACHEBUST=0
RUN echo "Pro cachebust: $PRO_CACHEBUST"
RUN --mount=type=secret,id=pro_deploy_key_b64,target=/run/secrets/pro_deploy_key_b64,mode=0400 \
    set -e; \
    if [ -s /run/secrets/pro_deploy_key_b64 ]; then \
      # Base64 round-trip: `fly deploy --build-secret` strips trailing
      # whitespace and padding inconsistently. Strip remaining
      # whitespace and pad to a multiple of 4 before decoding.
      tr -d '[:space:]' < /run/secrets/pro_deploy_key_b64 > /tmp/k.b64; \
      LEN=$(wc -c < /tmp/k.b64); \
      MOD=$(( LEN % 4 )); \
      [ "$MOD" -ne 0 ] && printf '%*s' $((4 - MOD)) '' | tr ' ' '=' >> /tmp/k.b64 || true; \
      base64 -d /tmp/k.b64 > /root/.ssh/id_ed25519; \
      chmod 600 /root/.ssh/id_ed25519; \
      git clone --depth 1 git@github.com:Jason-chen-taiwan/vulnscope-pro.git pro; \
      rm -rf pro/.git /root/.ssh/id_ed25519 /tmp/k.b64; \
      echo "[pro] Pro repo cloned ($(ls pro | wc -l) entries)"; \
    else \
      mkdir -p pro; \
      echo "[pro] No deploy key — OSS-only image (webpack will use ./pro-stub)" > pro/.empty; \
    fi

# ---------- builder ----------
FROM node:22-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# Pro tier (private repo, cloned in the pro stage). When the file
# pro/auth/config.ts exists, next.config.ts's webpack alias resolves
# @pro/* to ./pro/. Otherwise it falls through to ./pro-stub/. Either
# way the resulting bundle is self-contained — no runtime resolution
# tricks, no dynamic imports, no per-package node_modules splicing.
COPY --from=pro /work/pro ./pro
RUN corepack enable && pnpm build

# ---------- runner ----------
FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
# unzip is required by scripts/ingest/osv.ts; tini gives clean signal handling
RUN apk add --no-cache unzip tini && \
    addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs
# Standalone Next.js output (configured in next.config.ts). Standalone
# already includes any external deps listed in serverExternalPackages
# (e.g. better-auth, @polar-sh/sdk) under ./node_modules, so there is
# nothing else to splice.
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
RUN mkdir -p ./public
# Ingest scripts + their deps for the daily refresh runtime
COPY --from=builder --chown=nextjs:nodejs /app/scripts ./scripts
COPY --from=builder --chown=nextjs:nodejs /app/drizzle ./drizzle
COPY --from=builder --chown=nextjs:nodejs /app/src/db ./src/db
COPY --from=builder --chown=nextjs:nodejs /app/src/lib ./src/lib
COPY --from=builder --chown=nextjs:nodejs /app/messages ./messages
USER nextjs
EXPOSE 3000
ENV PORT=3000 HOSTNAME=0.0.0.0
ENTRYPOINT ["tini", "--"]
CMD ["node", "server.js"]
