import createMiddleware from "next-intl/middleware";
import { routing } from "./i18n/routing";

export default createMiddleware(routing);

export const config = {
  // Skip API routes, the static asset routes (icons + OG image),
  // _next internals, and any file extension.
  matcher: ["/((?!api|_next|.*\\..*).*)"],
};
