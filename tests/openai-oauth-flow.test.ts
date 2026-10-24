import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createServer } from "node:http";
import { test } from "node:test";
import { createOpenAICredentials, type OpenAIOAuthCredential } from "../src/store/openai-credentials.ts";
import { createOpenAIOAuth, OpenAIOAuthError } from "../src/server/openai-oauth-flow.ts";

const issuer = "https://auth.openai.com";
const time = 1_800_000_000_000;
const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const wrongPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...pair.publicKey.export({ format: "jwk" }), kid: "key-one", alg: "RS256", use: "sig" };
function jwt(claims: Record<string, unknown>, wrongSignature = false): string {
	const head = Buffer.from(JSON.stringify({ alg: "RS256", kid: "key-one" })).toString("base64url");
	const body = Buffer.from(JSON.stringify({ iss: issuer, sub: "subject-one", aud: "oaiapp_one", exp: time / 1000 + 3600, iat: time / 1000, email: "same@example.test", ...claims })).toString("base64url");
	return `${head}.${body}.${sign("RSA-SHA256", Buffer.from(`${head}.${body}`), wrongSignature ? wrongPair.privateKey : pair.privateKey).toString("base64url")}`;
}
function json(body: unknown, status = 200): Response { return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }); }
function makeFixture() {
	const directory = fs.mkdtempSync(path.join(os.tmpdir(), "lh-oauth-flow-"));
	const store = createOpenAICredentials({ directory, encryptionKey: randomBytes(32) });
	const requests: { url: string; body?: URLSearchParams }[] = [];
	const f = {
		store, requests,
		authorization: undefined as URL | undefined,
		claims: {} as Record<string, unknown>,
		wrongSignature: false,
		tokenResponse: undefined as ((body: URLSearchParams) => Response | Promise<Response>) | undefined,
		onOpen: undefined as ((url: URL) => Promise<void>) | undefined,
		revokeResponse: undefined as (() => Response | Promise<Response>) | undefined,
		callback: async (url: URL, parameters: Record<string, string> = {}) => {
			const callback = new URL(url.searchParams.get("redirect_uri")!);
			callback.search = new URLSearchParams({ code: "one-time-code", state: url.searchParams.get("state")!, client_id: "oaiapp_one", ...parameters }).toString();
			return fetch(callback);
		},
		cleanup: () => fs.rmSync(directory, { recursive: true, force: true }),
	};
	const mockFetch: typeof fetch = async (input, init) => {
		const url = String(input);
		const body = init?.body instanceof URLSearchParams ? init.body : undefined;
		requests.push({ url, body });
		if (url.endsWith("openid-configuration")) return json({ issuer, authorization_endpoint: `${issuer}/api/accounts/authorize`, token_endpoint: `${issuer}/api/accounts/oauth/token`, jwks_uri: `${issuer}/.well-known/jwks.json`, revocation_endpoint: `${issuer}/oauth/revoke` });
		if (url.endsWith("jwks.json")) return json({ keys: [jwk] });
		if (url.endsWith("/oauth/revoke")) return f.revokeResponse ? f.revokeResponse() : new Response(null, { status: 200 });
		assert.ok(url.endsWith("/oauth/token"));
		assert.equal(body?.get("client_id"), "oaiapp_one");
		assert.equal(body?.get("resource"), "https://api.openai.com/v1");
		if (f.tokenResponse) return f.tokenResponse(body!);
		assert.equal(body?.get("grant_type"), "authorization_code");
		assert.equal(body?.get("redirect_uri"), f.authorization!.searchParams.get("redirect_uri"));
		assert.equal(createHash("sha256").update(body!.get("code_verifier")!).digest("base64url"), f.authorization!.searchParams.get("code_challenge"));
		assert.equal(f.store.readState().accounts[0]!.clientId, "oaiapp_one", "registration is durable before code exchange");
		return json({ access_token: "access-one", refresh_token: "refresh-one", token_type: "Bearer", expires_in: 3600, scope: "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct", id_token: jwt({ nonce: f.authorization!.searchParams.get("nonce"), ...f.claims }, f.wrongSignature) });
	};
	const openBrowser = async (raw: string) => {
		const url = new URL(raw); f.authorization = url;
		assert.equal(url.origin, issuer);
		assert.equal(url.searchParams.get("code_challenge_method"), "S256");
		assert.match(url.searchParams.get("ext_agent_host_id")!, /^urn:uuid:/);
		if (f.onOpen) await f.onOpen(url);
		else { const response = await f.callback(url); assert.equal(response.status, 200); }
	};
	const auth = createOpenAIOAuth({ store, fetch: mockFetch, now: () => time, callbackPort: 0, openBrowser });
	return { ...f, auth, controls: f, mockFetch, openBrowser };
}

test("new sign-in validates identity, saves the issued registration before exchange and enables the selected account", async () => {
	const f = makeFixture();
	try {
		const credential = await f.auth.login();
		assert.equal(credential.subject, "subject-one");
		assert.equal(credential.clientId, "oaiapp_one");
		assert.equal(f.controls.authorization!.searchParams.get("client_id"), "dynamic_agent_client");
		assert.equal(f.controls.authorization!.searchParams.get("agent_name_hint"), "LearnHarness");
		const saved = f.store.readState();
		assert.equal(saved.mode, "oauth");
		assert.equal(saved.activeAccountId, saved.accounts[0]!.id);
		assert.deepEqual(saved.accounts[0]!.credential, credential);
	} finally { f.cleanup(); }
});

test("returning sign-in reuses client and host, retains login hints, and accepts an omitted callback client ID", async () => {
	const f = makeFixture();
	try {
		const first = await f.auth.login();
		const state = f.store.readState();
		const oldState = f.controls.authorization!.searchParams.get("state");
		f.controls.onOpen = async (url) => {
			assert.equal(url.searchParams.get("client_id"), "oaiapp_one");
			assert.equal(url.searchParams.get("agent_name_hint"), null);
			assert.equal(url.searchParams.get("ext_agent_host_id"), `urn:uuid:${state.installationId}`);
			assert.equal(url.searchParams.get("id_token_hint"), first.idToken);
			assert.equal(url.searchParams.get("login_hint"), "same@example.test");
			assert.notEqual(url.searchParams.get("state"), oldState);
			assert.equal((await f.controls.callback(url, { client_id: "" })).status, 200);
		};
		await f.auth.login(state.activeAccountId);
		assert.equal(f.store.readState().accounts.length, 1);
	} finally { f.cleanup(); }
});

test("returning sign-in omits an oversized ID-token hint to respect Windows browser URL limits", async () => {
	const f = makeFixture();
	try {
		await f.auth.login();
		await f.store.transaction((state) => { state.accounts[0]!.credential!.idToken = "long-signed-id-token-".repeat(200); });
		f.controls.onOpen = async (url) => {
			assert.ok(url.href.length <= 2081);
			assert.equal(url.searchParams.has("id_token_hint"), false);
			assert.equal(url.searchParams.get("client_id"), "oaiapp_one");
			assert.equal(url.searchParams.get("login_hint"), "same@example.test");
			assert.equal((await f.controls.callback(url)).status, 200);
		};
		await f.auth.login(f.store.readState().activeAccountId);
	} finally { f.cleanup(); }
});

test("invalid JWT signature, issuer, audience, expiry, nonce and changed account identity never replace the active tokens", async () => {
	for (const variant of ["signature", "issuer", "audience", "expiry", "nonce", "identity"] as const) {
		const f = makeFixture();
		try {
			await f.auth.login();
			const before = f.store.readState();
			f.controls.wrongSignature = variant === "signature";
			f.controls.claims = variant === "issuer" ? { iss: "https://attacker.invalid" } : variant === "audience" ? { aud: "oaiapp_someone_else" } : variant === "expiry" ? { exp: time / 1000 - 60 } : variant === "nonce" ? { nonce: "wrong-nonce" } : variant === "identity" ? { sub: "different-person" } : {};
			await assert.rejects(f.auth.login(before.activeAccountId), (error: unknown) => error instanceof OpenAIOAuthError && ["invalid_id_token", "identity_mismatch"].includes(error.code));
			assert.deepEqual(f.store.readState(), before, variant);
		} finally { f.cleanup(); }
	}
});

test("callbacks with mismatched state cannot cancel or complete a legitimate login", async () => {
	const f = makeFixture();
	try {
		f.controls.onOpen = async (url) => {
			assert.equal((await f.controls.callback(url, { state: "attacker-state", error: "access_denied" })).status, 400);
			assert.equal((await f.controls.callback(url)).status, 200);
		};
		assert.equal((await f.auth.login()).access, "access-one");
	} finally { f.cleanup(); }
});

test("a cancelled or denied login does not register credentials and closes the listener", async () => {
	for (const cancellation of ["abort", "denial"] as const) {
		const f = makeFixture();
		const controller = new AbortController();
		try {
			f.controls.onOpen = async (url) => {
				if (cancellation === "abort") controller.abort();
				else assert.equal((await f.controls.callback(url, { error: "access_denied" })).status, 400);
			};
			await assert.rejects(f.auth.login(undefined, controller.signal), (error: unknown) => error instanceof OpenAIOAuthError && ["cancelled", "access_denied"].includes(error.code));
			assert.equal(f.store.readState().accounts.length, 0);
			await assert.rejects(fetch(f.controls.authorization!.searchParams.get("redirect_uri")!));
		} finally { f.cleanup(); }
	}
});

test("registration survives expired authorization code and can be reauthorized with the issued client ID", async () => {
	const f = makeFixture();
	try {
		f.controls.tokenResponse = () => json({ error: "invalid_grant", error_description: "secret-do-not-surface" }, 400);
		await assert.rejects(f.auth.login(), (error: unknown) => error instanceof OpenAIOAuthError && error.code === "invalid_grant" && !error.message.includes("secret-do-not-surface"));
		const state = f.store.readState();
		assert.equal(state.accounts[0]!.clientId, "oaiapp_one");
		assert.equal(state.accounts[0]!.credential, undefined);
		assert.equal(state.mode, "api_key");
		f.controls.tokenResponse = undefined;
		await f.auth.login(state.accounts[0]!.id);
		assert.equal(f.controls.authorization!.searchParams.get("client_id"), "oaiapp_one");
		assert.equal(f.store.readState().accounts.length, 1);
	} finally { f.cleanup(); }
});

test("cancellation after code exchange preserves registration and never activates its credentials", async () => {
	const f = makeFixture();
	const controller = new AbortController();
	try {
		f.controls.tokenResponse = () => {
			controller.abort();
			return json({ access_token: "cancelled-access", refresh_token: "cancelled-refresh", expires_in: 3600, scope: "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct", id_token: jwt({ nonce: f.controls.authorization!.searchParams.get("nonce") }) });
		};
		await assert.rejects(f.auth.login(undefined, controller.signal));
		const state = f.store.readState();
		assert.equal(state.accounts[0]!.clientId, "oaiapp_one");
		assert.equal(state.accounts[0]!.credential, undefined);
		assert.equal(state.mode, "api_key");
		assert.equal(state.activeAccountId, undefined);
	} finally { f.cleanup(); }
});

test("identity-only permission is retained without pretending ChatGPT plan use was granted", async () => {
	const f = makeFixture();
	try {
		f.controls.tokenResponse = () => json({ access_token: "identity-access", refresh_token: "identity-refresh", expires_in: 3600, scope: "openid profile email offline_access", id_token: jwt({ nonce: f.controls.authorization!.searchParams.get("nonce") }) });
		const credential = await f.auth.login();
		assert.ok(!credential.scopes.includes("chatgpt.tokens.use.direct"));
		assert.equal(f.store.readState().accounts[0]!.subject, "subject-one");
		await f.auth.login(f.store.readState().activeAccountId);
		assert.equal(f.controls.authorization!.searchParams.get("prompt"), "consent");
	} finally { f.cleanup(); }
});

test("refresh uses saved client, omits scope, preserves omitted identity and scope, and reports terminal errors safely", async () => {
	const f = makeFixture();
	try {
		const old = await f.auth.login();
		f.controls.tokenResponse = (body) => {
			assert.equal(body.get("grant_type"), "refresh_token");
			assert.equal(body.get("refresh_token"), old.refresh);
			assert.equal(body.has("scope"), false);
			return json({ access_token: "rotated-access", refresh_token: "rotated-refresh", expires_in: 7200 });
		};
		const next = await f.auth.refresh(old);
		assert.equal(next.refresh, "rotated-refresh");
		assert.equal(next.idToken, old.idToken);
		assert.deepEqual(next.scopes, old.scopes);
		assert.equal(next.expires, time + 7200_000);
		f.controls.tokenResponse = () => json({ error: "refresh_token_reused", error_description: "do-not-log-this-token" }, 400);
		await assert.rejects(f.auth.refresh(next), (error: unknown) => error instanceof OpenAIOAuthError && error.terminal && error.code === "refresh_token_reused" && !error.message.includes("do-not-log"));
		assert.equal(f.store.readState().accounts[0]!.credential!.access, old.access, "refresh only returns a value; caller persists it under its lock");
	} finally { f.cleanup(); }
});

test("refresh rejects an ID token for a different subject", async () => {
	const f = makeFixture();
	try {
		const old = await f.auth.login();
		f.controls.tokenResponse = () => json({ access_token: "rotated", refresh_token: "new-refresh", expires_in: 3600, id_token: jwt({ sub: "another-person" }) });
		await assert.rejects(f.auth.refresh(old), (error: unknown) => error instanceof OpenAIOAuthError && error.code === "identity_mismatch");
	} finally { f.cleanup(); }
});

test("revocation accepts empty 200, retries temporary failure, and reports unconfirmed remote revocation", async () => {
	const f = makeFixture();
	try {
		const credential = await f.auth.login();
		let attempts = 0;
		f.controls.revokeResponse = () => ++attempts === 1 ? new Response(null, { status: 503 }) : new Response(null, { status: 200 });
		assert.equal(await f.auth.revoke(credential), true);
		assert.equal(attempts, 2);
		const call = f.requests.find((item) => item.url.endsWith("/oauth/revoke"))!;
		assert.equal(call.body!.get("token"), credential.refresh);
		assert.equal(call.body!.get("token_type_hint"), "refresh_token");
		f.controls.revokeResponse = () => { throw new Error("private-network-detail"); };
		assert.equal(await f.auth.revoke(credential), false);
	} finally { f.cleanup(); }
});

test("occupied callback port selects another loopback port without changing callback path", async () => {
	const f = makeFixture();
	const occupied = createServer();
	await new Promise<void>((resolve) => occupied.listen(0, "127.0.0.1", resolve));
	const address = occupied.address();
	assert.ok(address && typeof address !== "string");
	try {
		const auth = createOpenAIOAuth({ store: f.store, fetch: f.mockFetch, now: () => time, callbackPort: address.port, openBrowser: f.openBrowser });
		await auth.login();
		const callback = new URL(f.controls.authorization!.searchParams.get("redirect_uri")!);
		assert.equal(callback.hostname, "127.0.0.1");
		assert.equal(callback.pathname, "/auth/callback");
		assert.notEqual(Number(callback.port), address.port);
	} finally { occupied.close(); f.cleanup(); }
});
