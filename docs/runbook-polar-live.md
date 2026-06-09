# Runbook: Cut Polar billing from sandbox to live

Use when flipping vulnscope.dev's Pro billing from Polar sandbox
(test mode) to Polar production.

Assumes sandbox end-to-end is already working: sign in → /pricing
→ checkout → Polar sandbox pays → webhook fires →
`users.subscriptionStatus = 'active'` → /dashboard shows Pro.

The code stays the same. Only env vars + Polar dashboard config
change. Plus one DB migration (`0012_webhook_events.sql`) if not
already applied in production.

## What "live" requires from us

| Env var | Sandbox value | Live value |
|---|---|---|
| `POLAR_ACCESS_TOKEN` | `polar_oat_...` (from sandbox dashboard) | `polar_oat_...` (from live dashboard) |
| `POLAR_API_URL` | `https://sandbox-api.polar.sh` | `https://api.polar.sh` |
| `POLAR_WEBHOOK_SECRET` | sandbox webhook secret | live webhook secret |
| `NEXT_PUBLIC_POLAR_PRODUCT_PRO_MONTHLY` | sandbox product UUID | **live product UUID (different!)** |

The four are independent secrets in Fly. All four need to flip
together — a half-cut state (live token + sandbox product) means
checkout creates a session against a product that doesn't exist
and the user sees a 502 from `/api/v1/billing/checkout`.

## Pre-flight (do once, before cut)

1. **Polar live account**: confirm `polar.sh` (not sandbox) account
   exists, KYC passed, Stripe Connect Express payout connected.
2. **Live product**: in the Polar live dashboard, create the Pro
   product. Copy its UUID.
   - Must match the same recurring interval as sandbox (monthly).
   - Pricing in the currency you committed to (USD).
3. **Live webhook endpoint**: in the Polar live dashboard →
   Settings → Webhooks → New endpoint.
   - URL: `https://vulnscope.dev/api/v1/billing/webhook`
   - Events to subscribe: `subscription.created`,
     `subscription.updated`, `subscription.canceled`,
     `subscription.revoked`, `subscription.active`,
     `order.created`
   - Copy the generated signing secret. This is the *live*
     `POLAR_WEBHOOK_SECRET`. **Once you click away it's hidden** —
     paste it into Fly immediately.
4. **DB migration**: confirm `webhook_events` table exists in prod.
   ```bash
   fly ssh console -a vulnscope-tw -C 'psql $DATABASE_URL -c "\d webhook_events"'
   ```
   If not present, apply `pro/schema/0012_webhook_events.sql` (the
   ensure-schema path picks it up on the next worker boot, or run
   it directly).

## Cut to live (5 minutes)

Do these in order. Step 4 is the irreversible point.

1. **Set live Fly secrets** (does NOT restart the app):
   ```bash
   fly secrets set -a vulnscope-tw --stage \
     POLAR_API_URL=https://api.polar.sh \
     POLAR_ACCESS_TOKEN='polar_oat_LIVE_TOKEN_HERE' \
     POLAR_WEBHOOK_SECRET='LIVE_WEBHOOK_SECRET_HERE' \
     NEXT_PUBLIC_POLAR_PRODUCT_PRO_MONTHLY=LIVE_PRODUCT_UUID
   ```
   `--stage` queues without deploying. Lets you verify all four are
   set before triggering a restart.

2. **Verify staged secrets**:
   ```bash
   fly secrets list -a vulnscope-tw | grep POLAR
   ```
   All four lines should show recent timestamps.

3. **Capture rollback values** (so you can flip back if step 4–7
   misbehaves). Copy the current sandbox values from your local
   `.env.local` or 1Password into a scratch file you can paste in
   one shot. Don't skip this — recovering sandbox keys from Polar
   dashboard takes 10+ minutes.

4. **Deploy** (this is the irreversible step):
   ```bash
   fly deploy -a vulnscope-tw
   ```
   Fly restarts both `web` and `worker` machines with new secrets.

5. **Smoke test the live checkout**:
   - Open https://vulnscope.dev/pricing in a fresh incognito window
     (no logged-in cookies).
   - Sign in with a real account.
   - Click upgrade → Polar checkout loads at `polar.sh` (not
     `sandbox.polar.sh`). Verify URL.
   - Use a real card with $0.50 charge or your own card. Polar
     does not have a public test-card mode for live keys.
   - Complete checkout.
   - Browser redirects to `/dashboard?welcome=1`.

6. **Verify webhook fired**:
   ```bash
   fly logs -a vulnscope-tw | grep '\[polar\]'
   ```
   Expect to see `subscription.created` and `order.created` log
   lines within ~10s of checkout completion.

7. **Verify DB state**:
   ```bash
   fly ssh console -a vulnscope-tw -C \
     'psql $DATABASE_URL -c "
        SELECT id, subscription_status, subscription_tier,
               polar_customer_id, current_period_end
          FROM users WHERE email = '\''your-test-email@example.com'\''"'
   ```
   `subscription_status='active'`, `subscription_tier='pro'`,
   `current_period_end` ≈ +1 month from now.

8. **Verify idempotency log**:
   ```bash
   fly ssh console -a vulnscope-tw -C \
     'psql $DATABASE_URL -c "
        SELECT event_id, event_type, processed_status, received_at
          FROM webhook_events
         ORDER BY received_at DESC LIMIT 5"'
   ```
   Should show your fresh `subscription.created` row with
   `processed_status='ok'`.

## After the cut

- **Refund your own test payment** from the Polar dashboard if it
  was a real charge.
- **Monitor for ~24 hours**: any `processed_status='error'` or
  `unmapped` rows in `webhook_events` need investigation. Query:
  ```sql
  SELECT * FROM webhook_events
   WHERE processed_status IN ('error', 'unmapped')
     AND received_at > now() - interval '24 hours';
  ```
- **Update the sandbox webhook endpoint** in the Polar sandbox
  dashboard to point somewhere harmless (e.g. webhook.site) so
  stray sandbox events don't 404 us.

## Rollback (if something is broken)

If the smoke test at step 5–7 fails and you need to revert before
real users hit the broken state:

```bash
fly secrets set -a vulnscope-tw \
  POLAR_API_URL=https://sandbox-api.polar.sh \
  POLAR_ACCESS_TOKEN='SANDBOX_TOKEN_FROM_STEP_3' \
  POLAR_WEBHOOK_SECRET='SANDBOX_SECRET_FROM_STEP_3' \
  NEXT_PUBLIC_POLAR_PRODUCT_PRO_MONTHLY=SANDBOX_PRODUCT_UUID
```

Fly automatically redeploys when you skip `--stage`. ~30 seconds
later /pricing → checkout flow uses sandbox again.

**If a real user already paid before you rolled back**: their
Polar live subscription exists but our `users.subscriptionStatus`
won't have been updated (sandbox webhook can't see live events).
Manually:

1. Look them up in Polar live dashboard, get their
   `polar_customer_id` and `polar_subscription_id`.
2. UPDATE the row by hand:
   ```sql
   UPDATE users
      SET subscription_status='active',
          subscription_tier='pro',
          polar_customer_id='<live_customer_id>',
          polar_subscription_id='<live_subscription_id>',
          current_period_end=now() + interval '30 days'
    WHERE id='<their_user_id>';
   ```
3. Refund or comp them as policy demands.

## Things this runbook does NOT cover

- **Tax / VAT**: Polar handles as Merchant of Record.
- **Invoices**: Polar emails receipts automatically. Taiwan
  統一發票 is not covered — separate decision.
- **Subscription cancellation flow**: already wired via Polar's
  customer portal (`customerPortalUrl()` in `pro/billing/polar.ts`).
- **Dunning / failed payments**: Polar retries cards on its side
  and emits `subscription.past_due` events. Our handler stores the
  status but does not yet send a "your card failed" email.
- **Sandbox → live data migration**: there are no sandbox users
  worth migrating — sandbox subscriptions are test data only.
