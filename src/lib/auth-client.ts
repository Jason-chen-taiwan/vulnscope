/**
 * Better Auth client SDK. Used by Client Components to call
 * /api/auth/* without hand-rolling fetch.
 *
 * "use client" plus the components that import this being either
 * client components or dynamically loaded with `ssr: false` keeps
 * createAuthClient() out of the server bundle (it touches React
 * internals at module init that don't exist on the server).
 */
"use client";

import { createAuthClient } from "better-auth/react";

export const authClient = createAuthClient();
export const { signIn, signOut, useSession } = authClient;
