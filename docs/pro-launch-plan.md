# VulnScope Pro — 7-day launch plan

This document is public on purpose. The OSS core stays MIT forever. A
small set of hosted-only features (auth, billing, watchlists, email
alerts) live in a separate private repo and run only on
[vulnscope.dev](https://vulnscope.dev). Self-hosters keep the full
open-source feature set; the hosted Pro tier pays for ops and CVE alert
delivery.

This is the Open Core model used by Plausible, Cal.com, PostHog,
Sentry, and Supabase.

## Goal

7 days from spec to first paying customer. $9/mo, single tier, single
killer feature: **watchlist + daily email when a new CVE hits a package
you care about.**

The bar for "this works" is one human paying once. Not $1k MRR.

## Day-by-day

### Day 1 — Auth + billing scaffolding

- Add Clerk (Google + GitHub OAuth, email magic link as fallback).
- Add `users` table with `clerk_user_id`, `stripe_customer_id`,
  `subscription_status`, `subscription_tier`.
- Stripe Checkout session for a single Pro plan ($9/mo).
- Stripe webhook → write `subscription_status` on
  `customer.subscription.created|updated|deleted`.
- Stripe Customer Portal link from /settings for cancel/update card.

Routes added (private):
- `/settings`
- `/api/stripe/checkout`
- `/api/stripe/webhook`
- `/api/stripe/portal`

### Day 2 — `/pricing` page + free/Pro gating

- Public `/pricing` page on the OSS web app (one section, three columns:
  Self-host / Free hosted / Pro $9).
- Server helper `requirePro(userId)` for Pro-only routes.
- Free tier limits: watchlist up to 3 packages, no email alerts, public
  API rate limited per-IP.

### Day 3 — Watchlist schema + API

- `watchlists` table: `id, user_id, ecosystem, package_name, created_at`.
- Composite unique on `(user_id, ecosystem, package_name)`.
- `POST /api/v1/watchlist` add, `DELETE /api/v1/watchlist/:id` remove,
  `GET /api/v1/watchlist` list with latest CVE per row.

### Day 4 — Watchlist UI

- ⭐ button on `/package/{ecosystem}/{name}` — toggles watch state for
  signed-in users.
- `/dashboard/watchlist` — list view, last CVE date, KEV/EPSS badges.
- Free users see "3/3 used — upgrade for unlimited" once they hit limit.

### Day 5 — Email alerts cron

- Resend integration (free tier handles ~100 daily-digest users).
- Cron: every day 09:00 UTC, for each Pro user, query
  `vulnerabilities` joined to `watchlists` where
  `published_at > last_sent_at`. Send one email per user with all hits.
- React Email template: package name, CVE id, severity, KEV/EPSS, fix
  version, deep link to /cve/:id.
- Track `last_sent_at` per `(user_id, watchlist_id)`.

### Day 6 — CLI upsell + landing CTA

- CLI banner: after scan, if any findings, print:
  ```
  Want email alerts when new CVEs hit your packages?
  https://vulnscope.dev/pro
  ```
- Suppressible with `--quiet` or `VULNSCOPE_NO_BANNER=1`.
- Landing page header: add "Pro" link to /pricing.

### Day 7 — Launch

- Dev.to post: "I built a CVE watchlist for indie devs in 1 weekend."
- Show HN: "Show HN: VulnScope Pro — $9/mo CVE watchlist with KEV+EPSS."
- Cross-post to X, LinkedIn, /r/programming, /r/devops.
- Reach out to 10 people who've already starred the repo with a
  personal "want a free month of Pro?" message.

## Success / kill criteria

- **Continue** if: 1+ paid signup, or 30+ Pro waitlist email signups
  within 7 days of launch.
- **Pivot** if: 0 paid signups and < 10 waitlist signups after 14 days.
  Pivot = revisit pricing, messaging, or whether email-alert is the
  right killer feature.

## What stays open source

Everything in this repo today, plus any new ingest source, ecosystem,
CLI flag, or web-app feature that doesn't require an account. The OSS
self-host experience must keep getting better, not worse.

## What is closed source

Code that depends on an authenticated user, a Stripe subscription, or
sends transactional email on behalf of the hosted service. Self-hosters
who want similar features can either build their own or run the OSS
core with their own cron + mail stack.
