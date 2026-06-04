/**
 * Better Auth client SDK. Used by Client Components to call
 * /api/auth/* without hand-rolling fetch.
 *
 * Initialized with no baseURL because every call is same-origin (the
 * /api/auth/[...all] route handler proxies into pro/auth/config.ts on
 * our own server). When PRO_ENABLED=0 / self-host, the routes 404 and
 * useSession() returns null.
 */
"use client";

import { createAuthClient } from "better-auth/react";

export const authClient = createAuthClient();
export const { signIn, signOut, useSession } = authClient;
