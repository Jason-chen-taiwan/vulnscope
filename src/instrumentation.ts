/**
 * Next.js calls register() exactly once per server process. The actual
 * boot work lives in instrumentation-node.ts because Next bundles
 * THIS file for BOTH runtimes (nodejs + edge), and statically traces
 * every reachable import — even ones behind a runtime guard. Importing
 * scheduler/ensure-schema directly here pulled unzipper → fs-extra
 * into the Edge bundle, which has no Node `path`/`fs` and failed the
 * production build.
 *
 * The `-node` suffix file is loaded by Next ONLY in the Node.js
 * runtime, so its transitive imports never enter the Edge graph.
 */
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    await import("./instrumentation-node");
  }
}
