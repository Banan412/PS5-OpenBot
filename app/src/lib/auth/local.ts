import { queryOptions } from "@tanstack/react-query";
import type { LocalSignInValues } from "@/components/auth/local-sign-in";

type LocalAuthStatus = {
  enabled: true;
  setupRequired: boolean;
  setupAvailable: boolean;
  setupCodeRequired: boolean;
};

/** The endpoint is specific to this port. Other OpenBot servers may not have it. */
export async function readLocalAuthStatus(
  signal?: AbortSignal,
): Promise<LocalAuthStatus | null> {
  try {
    const response = await fetch("/api/port/auth/status", {
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal,
    });
    if (!response.ok) return null;
    const data: unknown = await response.json();
    if (
      !data ||
      typeof data !== "object" ||
      !("enabled" in data) ||
      data.enabled !== true ||
      !("setupRequired" in data) ||
      typeof data.setupRequired !== "boolean"
    )
      return null;
    return {
      enabled: true,
      setupRequired: data.setupRequired,
      setupAvailable: "setupAvailable" in data && data.setupAvailable === true,
      setupCodeRequired:
        !("setupCodeRequired" in data) || data.setupCodeRequired !== false,
    };
  } catch {
    return null;
  }
}

export function localAuthStatusQueryOptions() {
  return queryOptions({
    queryKey: ["local-auth", "status"] as const,
    queryFn: ({ signal }) => readLocalAuthStatus(signal),
    staleTime: 0,
    retry: false,
  });
}

/** A successful response sets an HttpOnly session cookie; no secret is stored in JavaScript. */
export async function localSignIn(
  values: LocalSignInValues,
  setup: boolean,
): Promise<void> {
  const body = setup
    ? {
        email: values.email,
        password: values.password,
        name: values.name,
        setupToken: values.setupCode,
      }
    : { email: values.email, password: values.password };
  const response = await fetch(`/api/port/auth/${setup ? "setup" : "login"}`, {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (response.status !== 204) throw new Error("Local sign-in failed");
}

/** Revoke the server-side session before clearing the browser's account state. */
export async function localSignOut(): Promise<void> {
  const response = await fetch("/api/port/auth/logout", {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  if (response.status !== 204) throw new Error("Signing out did not finish. Try again.");
}
