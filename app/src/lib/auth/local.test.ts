import { afterEach, expect, test } from "bun:test";
import { localSignIn, localSignOut, readLocalAuthStatus } from "./local";

const originalFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = originalFetch;
});

test("local sign-out revokes the session and rejects a failure", async () => {
  let request: RequestInit | undefined;
  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    expect(String(url)).toBe("/api/port/auth/logout");
    request = init;
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;
  await localSignOut();
  expect(request?.method).toBe("POST");
  expect(request?.credentials).toBe("same-origin");
  globalThis.fetch = (async () => new Response(null, { status: 503 })) as unknown as typeof fetch;
  await expect(localSignOut()).rejects.toThrow();
});

test("local sign-in is enabled only by an explicit valid status", async () => {
  for (const data of [
    { enabled: false, setupRequired: true },
    { enabled: true },
    {},
    "html",
  ]) {
    globalThis.fetch = (async () =>
      Response.json(data)) as unknown as typeof fetch;
    expect(await readLocalAuthStatus()).toBeNull();
  }
  globalThis.fetch = (async () =>
    new Response("missing", { status: 404 })) as unknown as typeof fetch;
  expect(await readLocalAuthStatus()).toBeNull();
  globalThis.fetch = (async () =>
    Response.json({
      enabled: true,
      setupRequired: true,
    })) as unknown as typeof fetch;
  expect(await readLocalAuthStatus()).toEqual({
    enabled: true,
    setupRequired: true,
    setupAvailable: false,
    setupCodeRequired: true,
  });
  globalThis.fetch = (async () =>
    Response.json({
      enabled: true,
      setupRequired: true,
      setupAvailable: true,
    })) as unknown as typeof fetch;
  expect(await readLocalAuthStatus()).toEqual({
    enabled: true,
    setupRequired: true,
    setupAvailable: true,
    setupCodeRequired: true,
  });
});

test("setup and login send only the expected data and require a 204", async () => {
  const requests: { url: string; init: RequestInit }[] = [];
  globalThis.fetch = (async (
    url: string | URL | Request,
    init?: RequestInit,
  ) => {
    requests.push({ url: String(url), init: init ?? {} });
    return new Response(null, { status: 204 });
  }) as unknown as typeof fetch;
  await localSignIn(
    {
      email: "test@example.com",
      password: "secret",
      name: "Test",
      setupCode: "code",
    },
    true,
  );
  await localSignIn(
    {
      email: "test@example.com",
      password: "secret",
      name: "ignored",
      setupCode: "ignored",
    },
    false,
  );
  expect(requests.map((r) => r.url)).toEqual([
    "/api/port/auth/setup",
    "/api/port/auth/login",
  ]);
  expect(JSON.parse(String(requests[0].init.body))).toEqual({
    email: "test@example.com",
    password: "secret",
    name: "Test",
    setupToken: "code",
  });
  expect(JSON.parse(String(requests[1].init.body))).toEqual({
    email: "test@example.com",
    password: "secret",
  });
  expect(requests[0].init.credentials).toBe("same-origin");
  globalThis.fetch = (async () =>
    new Response(null, { status: 200 })) as unknown as typeof fetch;
  await expect(
    localSignIn({ email: "test@example.com", password: "secret" }, false),
  ).rejects.toThrow();
});
