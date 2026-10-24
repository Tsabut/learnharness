import { createHash, createPublicKey, randomBytes, randomUUID, timingSafeEqual, verify, type JsonWebKey } from "node:crypto";
import { createServer, type Server } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import type { OpenAIAccount, OpenAICredentials, OpenAIOAuthCredential } from "../store/openai-credentials.ts";

const ISSUER = "https://auth.openai.com";
const RESOURCE = "https://api.openai.com/v1";
const SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
const CALLBACK_PATH = "/auth/callback";
const TERMINAL_REFRESH_ERRORS = new Set(["invalid_grant", "invalid_refresh_token", "token_expired", "refresh_token_expired", "refresh_token_invalidated", "refresh_token_reused"]);

export class OpenAIOAuthError extends Error {
	readonly safeMessage: string;
	readonly terminal: boolean;
	constructor(readonly code: string, message: string, readonly status?: number, readonly requestId?: string) {
		super(message);
		this.name = "OpenAIOAuthError";
		this.safeMessage = message;
		this.terminal = TERMINAL_REFRESH_ERRORS.has(code);
	}
}

interface Discovery {
	issuer: string;
	authorization_endpoint: string;
	token_endpoint: string;
	jwks_uri: string;
	revocation_endpoint: string;
}
type Identity = { issuer: string; subject: string; email?: string };
type Jwk = JsonWebKey & { kid?: string; alg?: string; use?: string };

function fail(code: string, message: string): never { throw new OpenAIOAuthError(code, message); }
function secretEqual(actual: string | null, expected: string): boolean {
	if (!actual) return false;
	const a = Buffer.from(actual);
	const b = Buffer.from(expected);
	return a.length === b.length && timingSafeEqual(a, b);
}
function tokenString(value: unknown, field: string): string {
	if (typeof value !== "string" || !value.trim()) fail("invalid_token_response", `OpenAI returned an incomplete token response (${field}). Try signing in again.`);
	return value;
}
function jsonObject(value: unknown): Record<string, unknown> {
	if (!value || typeof value !== "object" || Array.isArray(value)) fail("invalid_response", "OpenAI returned an invalid response. Try again.");
	return value as Record<string, unknown>;
}
function trustedEndpoint(value: unknown): string {
	if (typeof value !== "string") fail("invalid_discovery", "OpenAI sign-in configuration is unavailable. Try again later.");
	const url = new URL(value);
	if (url.origin !== ISSUER || url.username || url.password || url.hash) fail("invalid_discovery", "OpenAI sign-in configuration could not be verified.");
	return url.href;
}
function safeCode(value: unknown): string | undefined {
	return typeof value === "string" && /^[a-z][a-z0-9_]{0,99}$/.test(value) ? value : undefined;
}

export interface OpenAIOAuth {
	login(accountId?: string, signal?: AbortSignal): Promise<OpenAIOAuthCredential>;
	refresh(credential: OpenAIOAuthCredential, signal?: AbortSignal): Promise<OpenAIOAuthCredential>;
	revoke(credential: OpenAIOAuthCredential, signal?: AbortSignal): Promise<boolean>;
}

/** Protocol-only implementation. Tokens, PKCE, callbacks and authorization URLs never reach renderer status. */
export function createOpenAIOAuth(options: {
	store: OpenAICredentials;
	openBrowser: (url: string) => void | Promise<void>;
	fetch?: typeof fetch;
	now?: () => number;
	callbackPort?: number;
}): OpenAIOAuth {
	const request = options.fetch ?? fetch;
	const now = options.now ?? Date.now;
	let discoveryPromise: Promise<Discovery> | undefined;
	let jwks: { keys: Jwk[]; expires: number } | undefined;
	async function fetchJson(url: string, init?: RequestInit): Promise<Record<string, unknown>> {
		let response: Response;
		try { response = await request(url, { ...init, redirect: "error", signal: init?.signal ? AbortSignal.any([init.signal, AbortSignal.timeout(15_000)]) : AbortSignal.timeout(15_000) }); }
		catch {
			if (init?.signal?.aborted) throw new OpenAIOAuthError("cancelled", "ChatGPT sign-in was cancelled.");
			throw new OpenAIOAuthError("network_error", "OpenAI could not be reached. Check your connection and try again.");
		}
		const text = await response.text();
		let body: Record<string, unknown> = {};
		try { if (text.length <= 2_000_000 && text) body = jsonObject(JSON.parse(text)); } catch { /* never expose response text */ }
		if (!response.ok) {
			const nested = body.error && typeof body.error === "object" ? body.error as Record<string, unknown> : undefined;
			const code = safeCode(body.error) ?? safeCode(nested?.code) ?? "oauth_http_error";
			const rawId = response.headers.get("x-request-id") ?? response.headers.get("openai-request-id");
			const requestId = rawId && /^[a-zA-Z0-9_-]{1,200}$/.test(rawId) ? rawId : undefined;
			throw new OpenAIOAuthError(code,
				TERMINAL_REFRESH_ERRORS.has(code) ? "Your ChatGPT session has ended. Sign in again." :
					code === "invalid_client" ? "OpenAI rejected this ChatGPT client registration. Check the app configuration." :
						`OpenAI could not complete authorization (HTTP ${response.status}). Try again later.`, response.status, requestId);
		}
		if (!text || text.length > 2_000_000 || !Object.keys(body).length) fail("invalid_response", "OpenAI returned an invalid response. Try again.");
		return body;
	}
	async function discovery(): Promise<Discovery> {
		if (!discoveryPromise) {
			discoveryPromise = fetchJson(`${ISSUER}/.well-known/openid-configuration`).then((body) => {
				if (body.issuer !== ISSUER) fail("invalid_discovery", "OpenAI's identity issuer could not be verified.");
				return { issuer: ISSUER, authorization_endpoint: trustedEndpoint(body.authorization_endpoint), token_endpoint: trustedEndpoint(body.token_endpoint), jwks_uri: trustedEndpoint(body.jwks_uri), revocation_endpoint: trustedEndpoint(body.revocation_endpoint) };
			}).catch((error) => { discoveryPromise = undefined; throw error; });
		}
		return discoveryPromise;
	}
	async function identity(idToken: string, clientId: string, nonce?: string, signal?: AbortSignal): Promise<Identity> {
		const parts = idToken.split(".");
		if (parts.length !== 3) fail("invalid_id_token", "OpenAI's identity token could not be verified. Sign in again.");
		let header: Record<string, unknown>, claims: Record<string, unknown>;
		try { header = jsonObject(JSON.parse(Buffer.from(parts[0]!, "base64url").toString("utf8"))); claims = jsonObject(JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8"))); }
		catch { fail("invalid_id_token", "OpenAI's identity token could not be verified. Sign in again."); }
		if (header.alg !== "RS256" || typeof header.kid !== "string" || !header.kid) fail("invalid_id_token", "OpenAI's identity token uses an unsupported signing key.");
		const config = await discovery();
		async function loadKeys(): Promise<Jwk[]> {
			const body = await fetchJson(config.jwks_uri, { signal });
			if (!Array.isArray(body.keys)) fail("invalid_jwks", "OpenAI's identity signing keys are unavailable. Try again later.");
			const keys = body.keys.filter((key): key is Jwk => !!key && typeof key === "object");
			jwks = { keys, expires: now() + 5 * 60_000 };
			return keys;
		}
		let keys = jwks && jwks.expires > now() ? jwks.keys : await loadKeys();
		let key = keys.find((candidate) => candidate.kid === header.kid);
		if (!key) { keys = await loadKeys(); key = keys.find((candidate) => candidate.kid === header.kid); }
		if (!key || key.kty !== "RSA" || (key.use !== undefined && key.use !== "sig") || (key.alg !== undefined && key.alg !== "RS256")) fail("invalid_id_token", "OpenAI's identity signing key could not be verified.");
		let valid = false;
		try { valid = verify("RSA-SHA256", Buffer.from(`${parts[0]}.${parts[1]}`), createPublicKey({ key, format: "jwk" }), Buffer.from(parts[2]!, "base64url")); } catch { /* invalid key or signature */ }
		const seconds = now() / 1000;
		const audience = claims.aud;
		const audienceValid = audience === clientId || (Array.isArray(audience) && audience.includes(clientId) && (audience.length === 1 || claims.azp === clientId));
		if (!valid || claims.iss !== config.issuer || !audienceValid || (claims.azp !== undefined && claims.azp !== clientId) ||
			typeof claims.exp !== "number" || !Number.isFinite(claims.exp) || claims.exp <= seconds - 5 ||
			typeof claims.iat !== "number" || !Number.isFinite(claims.iat) || claims.iat > seconds + 5 ||
			(claims.nbf !== undefined && (typeof claims.nbf !== "number" || !Number.isFinite(claims.nbf) || claims.nbf > seconds + 5)) ||
			typeof claims.sub !== "string" || !claims.sub || (nonce !== undefined && !secretEqual(typeof claims.nonce === "string" ? claims.nonce : null, nonce))) {
			fail("invalid_id_token", "OpenAI's identity token could not be verified. Sign in again.");
		}
		return { issuer: config.issuer, subject: claims.sub, ...(typeof claims.email === "string" ? { email: claims.email } : {}) };
	}
	async function token(body: URLSearchParams, signal?: AbortSignal): Promise<Record<string, unknown>> {
		return fetchJson((await discovery()).token_endpoint, { method: "POST", headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded" }, body, signal });
	}
	async function credentialFromResponse(body: Record<string, unknown>, clientId: string, previous?: OpenAIOAuthCredential, nonce?: string, signal?: AbortSignal): Promise<OpenAIOAuthCredential> {
		const access = tokenString(body.access_token, "access_token");
		const refresh = body.refresh_token === undefined && previous ? previous.refresh : tokenString(body.refresh_token, "refresh_token");
		if (typeof body.expires_in !== "number" || !Number.isFinite(body.expires_in) || body.expires_in <= 0 ||
			(body.token_type !== undefined && String(body.token_type).toLowerCase() !== "bearer")) fail("invalid_token_response", "OpenAI returned invalid token expiry or type. Sign in again.");
		const scopes = body.scope === undefined && previous ? [...previous.scopes] : tokenString(body.scope, "scope").trim().split(/\s+/);
		const idToken = body.id_token === undefined && previous ? previous.idToken : tokenString(body.id_token, "id_token");
		// A refresh may omit the ID token; do not re-check expiry of a retained login hint.
		const verified = body.id_token === undefined && previous ? { issuer: previous.issuer, subject: previous.subject, email: previous.email } : await identity(idToken, clientId, nonce, signal);
		if (previous && (verified.issuer !== previous.issuer || verified.subject !== previous.subject)) fail("identity_mismatch", "OpenAI returned a different ChatGPT account. The existing connection was preserved.");
		return { type: "oauth", access, refresh, expires: now() + body.expires_in * 1000, clientId, scopes, idToken, ...verified };
	}
	async function callbackListener(state: string, existingClientId: string | undefined, signal: AbortSignal): Promise<{ server: Server; redirectUri: string; result: Promise<{ code: string; clientId: string }> }> {
		let resolveResult!: (value: { code: string; clientId: string }) => void;
		let rejectResult!: (error: unknown) => void;
		const result = new Promise<{ code: string; clientId: string }>((resolve, reject) => { resolveResult = resolve; rejectResult = reject; });
		void result.catch(() => {});
		let settled = false;
		const server = createServer((req, res) => {
			res.setHeader("Content-Type", "text/html; charset=utf-8");
			res.setHeader("Cache-Control", "no-store");
			res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'");
			const url = new URL(req.url ?? "/", "http://127.0.0.1");
			if (req.method !== "GET" || url.pathname !== CALLBACK_PATH) { res.writeHead(404).end("Not found."); return; }
			if (settled || !secretEqual(url.searchParams.get("state"), state)) { res.writeHead(400).end("This sign-in could not be verified. Return to LearnHarness and retry."); return; }
			if (url.searchParams.has("error")) {
				settled = true;
				res.writeHead(400).end("ChatGPT was not connected. Return to LearnHarness.");
				rejectResult(new OpenAIOAuthError(safeCode(url.searchParams.get("error")) ?? "authorization_denied", "ChatGPT authorization was declined. You can try again from settings."));
				return;
			}
			const code = url.searchParams.get("code");
			const returnedClientId = url.searchParams.get("client_id")?.trim();
			const clientId = returnedClientId || existingClientId;
			if (!code || !clientId || clientId === "dynamic_agent_client" || (existingClientId && clientId !== existingClientId)) {
				res.writeHead(400).end("The authorization callback was incomplete. Return to LearnHarness and retry.");
				return;
			}
			settled = true;
			res.writeHead(200).end("<!doctype html><html><head><title>LearnHarness</title></head><body><p>Authorization received. Return to LearnHarness to finish connecting ChatGPT.</p></body></html>");
			resolveResult({ code, clientId });
		});
		const abort = () => { settled = true; rejectResult(new OpenAIOAuthError("cancelled", "ChatGPT sign-in was cancelled or timed out.")); server.close(); server.closeAllConnections(); };
		signal.addEventListener("abort", abort, { once: true });
		server.once("close", () => signal.removeEventListener("abort", abort));
		async function listen(port: number): Promise<void> {
			await new Promise<void>((resolve, reject) => {
				const error = (err: Error) => { server.removeListener("listening", listening); reject(err); };
				const listening = () => { server.removeListener("error", error); resolve(); };
				server.once("error", error);
				server.once("listening", listening);
				server.listen(port, "127.0.0.1");
			});
		}
		try {
			signal.throwIfAborted();
			try { await listen(options.callbackPort ?? 1455); }
			catch (error) {
				if (!(error && typeof error === "object" && "code" in error && error.code === "EADDRINUSE")) throw error;
				await listen(0);
			}
			if (signal.aborted) { abort(); throw new OpenAIOAuthError("cancelled", "ChatGPT sign-in was cancelled."); }
		} catch (error) { signal.removeEventListener("abort", abort); server.close(); throw error; }
		server.on("error", () => rejectResult(new OpenAIOAuthError("callback_error", "The local ChatGPT callback listener failed. Try signing in again.")));
		const address = server.address();
		if (!address || typeof address === "string") fail("callback_error", "The local ChatGPT callback listener could not start.");
		return { server, redirectUri: `http://127.0.0.1:${address.port}${CALLBACK_PATH}`, result };
	}
	return {
		async login(accountId, callerSignal) {
			const signal = callerSignal ? AbortSignal.any([callerSignal, AbortSignal.timeout(10 * 60_000)]) : AbortSignal.timeout(10 * 60_000);
			const state = await options.store.ensure();
			let account: OpenAIAccount | undefined = accountId ? state.accounts.find((item) => item.id === accountId) : undefined;
			if (accountId && !account) fail("unknown_account", "The selected ChatGPT account no longer exists. Select an account again.");
			const config = await discovery();
			const verifier = randomBytes(64).toString("base64url");
			const challenge = createHash("sha256").update(verifier).digest("base64url");
			const oauthState = randomBytes(32).toString("base64url");
			const nonce = randomBytes(32).toString("base64url");
			const callback = await callbackListener(oauthState, account?.clientId, signal);
			try {
				const authorization = new URL(config.authorization_endpoint);
				authorization.search = new URLSearchParams({ client_id: account?.clientId ?? "dynamic_agent_client", ext_agent_host_id: `urn:uuid:${state.installationId}`, response_type: "code", redirect_uri: callback.redirectUri, resource: RESOURCE, scope: SCOPES, state: oauthState, nonce, code_challenge: challenge, code_challenge_method: "S256" }).toString();
				if (!account) authorization.searchParams.set("agent_name_hint", "LearnHarness");
				if (account?.credential?.idToken) authorization.searchParams.set("id_token_hint", account.credential.idToken);
				if (account?.email) authorization.searchParams.set("login_hint", account.email);
				// Explicitly retrying a grant without plan-use permission requests consent.
				if (account?.credential && !account.credential.scopes.includes("chatgpt.tokens.use.direct")) authorization.searchParams.set("prompt", "consent");
				// shell.openExternal has a 2081-character URL limit on Windows. Hints are optional.
				if (authorization.href.length > 2081) authorization.searchParams.delete("id_token_hint");
				if (authorization.href.length > 2081) authorization.searchParams.delete("login_hint");
				if (authorization.href.length > 2081) fail("authorization_url_too_long", "The ChatGPT authorization URL could not be opened. Try adding a new account.");
				await options.openBrowser(authorization.href);
				const returned = await callback.result;
				signal.throwIfAborted();
				if (!account) {
					account = await options.store.transaction((current) => {
						const existing = current.accounts.find((item) => item.clientId === returned.clientId);
						if (existing) return structuredClone(existing);
						const registration: OpenAIAccount = { id: randomUUID(), clientId: returned.clientId };
						current.accounts.push(registration);
						return structuredClone(registration);
					}, { signal });
				}
				const body = await token(new URLSearchParams({ grant_type: "authorization_code", client_id: returned.clientId, code: returned.code, code_verifier: verifier, redirect_uri: callback.redirectUri, resource: RESOURCE }), signal);
				const credential = await credentialFromResponse(body, returned.clientId, undefined, nonce, signal);
				if (account.subject && (credential.subject !== account.subject || credential.issuer !== account.issuer)) fail("identity_mismatch", "OpenAI returned a different ChatGPT account. The existing connection was preserved.");
				signal.throwIfAborted();
				const registrationId = account.id;
				await options.store.transaction((current) => {
					signal.throwIfAborted();
					const selected = current.accounts.find((item) => item.id === registrationId);
					if (!selected || selected.clientId !== credential.clientId || (selected.subject && (selected.subject !== credential.subject || selected.issuer !== credential.issuer))) fail("identity_mismatch", "The ChatGPT account registration changed. Sign in again.");
					Object.assign(selected, { credential, issuer: credential.issuer, subject: credential.subject, email: credential.email });
					current.activeAccountId = selected.id;
					current.mode = "oauth";
				}, { signal });
				return credential;
			} finally { callback.server.close(); callback.server.closeAllConnections(); }
		},
		async refresh(credential, signal) {
			const body = await token(new URLSearchParams({ grant_type: "refresh_token", client_id: credential.clientId, refresh_token: credential.refresh, resource: RESOURCE }), signal);
			return credentialFromResponse(body, credential.clientId, credential, undefined, signal);
		},
		async revoke(credential, signal) {
			try {
				const endpoint = (await discovery()).revocation_endpoint;
				for (let attempt = 0; attempt < 3; attempt++) {
					try {
						const response = await request(endpoint, { method: "POST", redirect: "error", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token: credential.refresh, token_type_hint: "refresh_token", client_id: credential.clientId }), signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(10_000)]) : AbortSignal.timeout(10_000) });
						await response.body?.cancel();
						if (response.status === 200) return true;
						if (response.status < 500) return false;
					} catch { if (signal?.aborted) return false; }
					if (attempt < 2) await delay(250 * 2 ** attempt, undefined, { signal });
				}
			} catch { /* caller reports unconfirmed remote revocation after local sign-out */ }
			return false;
		},
	};
}
