import { createNavigation } from "next-intl/navigation";
import { routing } from "./routing";

// Use these in place of `next/link` and `next/navigation` inside the
// localized app so paths get the active locale prefix automatically.
export const { Link, redirect, usePathname, useRouter, getPathname } =
  createNavigation(routing);
