/**
 * OSS-mode stub for the Polar webhook handler. Returns 404 so the
 * route compiles and any stray webhook callbacks to a self-host
 * cleanly bounce back.
 */
import "server-only";

export async function handlePolarWebhook(_req: Request): Promise<Response> {
  return new Response("Pro tier not enabled", { status: 404 });
}
