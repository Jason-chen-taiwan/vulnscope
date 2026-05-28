# Multi-stage Dockerfile for VulnScope.
# Result: ~250MB image with standalone Next.js + tsx for ingest scripts.

# ---------- deps ----------
FROM node:22-alpine AS deps
WORKDIR /app
RUN apk add --no-cache libc6-compat
# Copy lockfile + package manifests
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
# pnpm 11 hard-fails when ANY transitive dep has an unapproved postinstall
# script. In Docker we can't run the interactive `pnpm approve-builds`,
# and the workspace-file allowlist isn't honoured reliably across runs.
# `--config.dangerouslyAllowAllBuilds=true` is the documented escape hatch
# for non-interactive environments; falls back to `--ignore-scripts` if
# that flag is rejected by the installed pnpm version.
RUN corepack enable && \
    (pnpm install --frozen-lockfile --config.dangerouslyAllowAllBuilds=true \
     || pnpm install --frozen-lockfile --ignore-scripts)

# ---------- builder ----------
FROM node:22-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
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
# Standalone Next.js output (configured in next.config.ts)
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
# /app/public may or may not exist (we don't ship any static assets today).
# Ensure the directory exists either way so future static files can land here.
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
