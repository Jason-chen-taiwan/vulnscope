# pro-stub

OSS-mode replacement for the private `pro/` directory. When this
codebase is cloned and built without the hosted Pro tier (no
`./pro` folder on disk), `next.config.ts` aliases `@pro/*` here. Every
function exported is a safe no-op:

- `getCurrentUser()` returns `null`
- `requirePro()` throws `ProAccessError`
- `auth.handler()` returns an HTTP 404
- `createCheckoutSession()` / `handlePolarWebhook()` throw
- All schema tables export empty placeholders so Drizzle migrations
  on the OSS side stay introspectable

This is the public-facing contract for the Pro tier. The real
implementation lives in
[github.com/Jason-chen-taiwan/vulnscope-pro](https://github.com/Jason-chen-taiwan/vulnscope-pro)
(private) and follows exactly the same export surface.

You don't need to use these files. If you want to build your own
Pro tier on top of a self-host, re-implement them in `./pro` with the
same signatures and the build will pick yours up instead.
