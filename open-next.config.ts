import { defineCloudflareConfig } from "@opennextjs/cloudflare";

// ponytail: KV incrementalCache temporarily disabled — KV bulk PUT gets edge-403'd
// from this network, blocking every deploy. Re-enable (see git history) once the
// 403 is resolved; runtime falls back to no-op cache (same as pre-Phase-2).
export default defineCloudflareConfig();
