import createMiddleware from "next-intl/middleware";
import { routing } from "./i18n/routing";

export default createMiddleware(routing);

export const config = {
  // Excludes /api (route handlers), /feed (route handlers), /_next, and
  // any path with a file extension (static assets).
  matcher: ["/((?!api|feed|_next|.*\\..*).*)"],
};
