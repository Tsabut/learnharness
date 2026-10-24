import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";
import { createModels, normalizeContext, type AssistantMessage, type AssistantMessageEvent, type CredentialStore, type Provider } from "@earendil-works/pi-ai";
import { openaiProvider } from "@earendil-works/pi-ai/providers/openai";
import { AssistantMessageEventStream } from "@earendil-works/pi-ai/utils/event-stream";
import { createOpenAICredentials, type OpenAIAccount, type OpenAICredentials, type OpenAIOAuthCredential } from "../src/store/openai-credentials.ts";
import { OpenAIOAuthError, type OpenAIOAuth } from "../src/server/openai-oauth-flow.ts";
import { createOpenAIAuthService, parseOpenAIAuthAction, strictSubscriptionStream, validOpenAIAuthRequest } from "../src/server/openai-auth.ts";
import { scopePiRequests } from "../src/agent/models.ts";

const base = openaiProvider() as Provider;
const models = base.getModels().slice(0, 2);
assert.equal(models.length, 2);

function token(suffix: string): OpenAIOAuthCredential {
	return { type: "oauth", access: `private-access-${suffix}`, refresh: `private-refresh-${suffix}`, expires: Date.now() + 3600_000, idToken: `private-id-token-${suffix}`, clientId: `oaiapp_private_${suffix}`, scopes: ["openid", "chatgpt.tokens.use.direct"], issuer: "https://auth.openai.com", subject: `private-subject-${suffix}`, email: "same@example.test" };
}
function account(suffix: string): OpenAIAccount {
	const credential = token(suffix);
	return { id: `account-${suffix}`, clientId: credential.clientId, issuer: credential.issuer, subject: credential.subject, email: credential.email, credential };
}
async function fixture() {
	const directory = fs.mkdtempSync(path.join(os.tmpdir(), "lh-oauth-service-"));
	const store = createOpenAICredentials({ directory, encryptionKey: randomBytes(32) });
	await store.transaction((state) => { state.accounts = [account("a"), account("b")]; state.activeAccountId = "account-a"; state.mode = "oauth"; });
	const calls: { url: string; access: string | null }[] = [];
	const controls = {
		keyPresent: false,
		refreshCount: 0,
		revokeConfirmed: true,
		login: undefined as OpenAIOAuth["login"] | undefined,
		refresh: undefined as OpenAIOAuth["refresh"] | undefined,
		fetch: undefined as typeof fetch | undefined,
	};
	const flow: OpenAIOAuth = {
		async login(accountId, signal) {
			if (controls.login) return controls.login(accountId, signal);
			const selectedId = accountId ?? "account-a";
			return store.transaction((state) => {
				state.mode = "oauth"; state.activeAccountId = selectedId;
				return state.accounts.find((item) => item.id === selectedId)!.credential!;
			});
		},
		async refresh(credential, signal) {
			controls.refreshCount++;
			return controls.refresh ? controls.refresh(credential, signal) : { ...credential, access: "fresh-private-access", refresh: "fresh-private-refresh", expires: Date.now() + 3600_000 };
		},
		async revoke() { return controls.revokeConfirmed; },
	};
	const mockFetch: typeof fetch = async (input, init) => {
		if (controls.fetch) return controls.fetch(input, init);
		const url = String(input);
		const access = new Headers(init?.headers).get("Authorization");
		calls.push({ url, access });
		assert.equal(url, "https://api.openai.com/v1/models");
		const selectedModel = access === "Bearer private-access-b" ? models[1]! : models[0]!;
		return new Response(JSON.stringify({ models: [
			{ slug: selectedModel.id, display_name: `Account model ${selectedModel.id}`, visibility: "list" },
			{ slug: selectedModel.id, display_name: "Duplicate must be dropped", visibility: "list" },
			{ slug: "hidden-model", display_name: "Hidden", visibility: "hide" },
		] }), { status: 200, headers: { "content-type": "application/json" } });
	};
	const create = (adapter: OpenAICredentials = store) => createOpenAIAuthService({ store: adapter, flow, fetch: mockFetch, apiKeyPresent: () => controls.keyPresent, resolveAccess: async () => { const state = store.readState(); return state.accounts.find((item) => item.id === state.activeAccountId)?.credential?.access; } });
	const service = create();
	const collection = (provider = service.provider()) => {
		const collection = createModels({ credentials: service.credentials, authContext: { env: async (name) => controls.keyPresent && name === "OPENAI_API_KEY" ? "sk-explicit-test-api-key" : undefined, fileExists: async () => false } });
		collection.setProvider(provider);
		return scopePiRequests(collection, service.requestSignal);
	};
	return { store, service, controls, calls, flow, create, collection, cleanup: () => fs.rmSync(directory, { recursive: true, force: true }) };
}
async function settled(service: ReturnType<typeof createOpenAIAuthService>) {
	for (let attempt = 0; attempt < 200 && service.status().loginPending; attempt++) await delay(5);
	assert.equal(service.status().loginPending, false, "controller login settles");
	return service.status();
}
function message(stopReason: AssistantMessage["stopReason"] = "stop"): AssistantMessage {
	return { role: "assistant", content: [{ type: "text", text: "mock answer" }], api: "openai-responses", provider: "openai", model: models[0]!.id, timestamp: Date.now(), stopReason, usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } } };
}
async function* events(items: AssistantMessageEvent[]) { yield* items; }
async function collect(source: AsyncIterable<AssistantMessageEvent>) { const result: AssistantMessageEvent[] = []; for await (const event of source) result.push(event); return result; }

test("OAuth authorizes without API keys, resolves through Models, and sends the same bearer token to account model discovery", async () => {
	const f = await fixture();
	try {
		assert.equal(f.service.status().apiKeyPresent, false);
		assert.equal(f.service.authorized(), true);
		const auth = await f.collection().getAuth("openai");
		assert.equal(auth?.auth.apiKey, "private-access-a");
		assert.equal(auth?.source, "OAuth");
		await f.service.refreshModels();
		assert.deepEqual(f.service.availableModels(models).map((model) => model.id), [models[0]!.id]);
		assert.equal(f.calls[0]!.access, "Bearer private-access-a");
		assert.equal(f.service.availableModels(models)[0]!.name, `Account model ${models[0]!.id}`);
	} finally { f.cleanup(); }
});

test("explicit API-key mode resolves only the API key and retains saved OAuth registrations", async () => {
	const f = await fixture();
	try {
		f.controls.keyPresent = true;
		const collection = f.collection();
		assert.equal((await collection.getAuth("openai"))?.source, "OAuth");
		await f.service.act({ action: "mode", mode: "api_key" });
		const auth = await collection.getAuth("openai");
		assert.equal(auth?.auth.apiKey, "sk-explicit-test-api-key");
		assert.notEqual(auth?.source, "OAuth");
		assert.equal(f.store.readState().accounts[0]!.credential!.access, "private-access-a");
		assert.equal(f.service.availableModels(models).length, 2);
		assert.equal(f.calls.length, 0);
	} finally { f.cleanup(); }
});

test("an OAuth bearer resolved before switching to API-key mode never dispatches to the base provider", async () => {
	const f = await fixture();
	try {
		f.controls.keyPresent = true;
		let dispatches = 0;
		const fake: Provider = { ...base, streamSimple: () => { dispatches++; const stream = new AssistantMessageEventStream(); stream.push({ type: "done", reason: "stop", message: message() }); stream.end(); return stream; } };
		const wrapped = f.service.provider(fake);
		const oldAuth = await f.collection(wrapped).getAuth("openai");
		await f.service.act({ action: "mode", mode: "api_key" });
		const result = await wrapped.streamSimple(models[0]!, normalizeContext({ messages: [] }), { apiKey: oldAuth!.auth.apiKey }).result();
		assert.ok(["error", "aborted"].includes(result.stopReason));
		assert.equal(dispatches, 0);
	} finally { f.cleanup(); }
});

test("identity-only grant cannot authorize, resolve inference auth or fetch models even when an API key is available", async () => {
	const f = await fixture();
	try {
		f.controls.keyPresent = true;
		await f.store.transaction((state) => { state.accounts[0]!.credential!.scopes = ["openid", "profile", "email"]; });
		assert.equal(f.service.authorized(), false);
		assert.match(f.service.status().message!, /permission.*plan.*not granted/i);
		await assert.rejects(f.collection().getAuth("openai"));
		await f.service.refreshModels();
		assert.equal(f.calls.length, 0);
		assert.deepEqual(f.service.availableModels(models), []);
	} finally { f.cleanup(); }
});

test("account switch replaces the catalog and prevents an old in-flight response from publishing into the new account", async () => {
	const f = await fixture();
	try {
		let release!: () => void;
		const pending = new Promise<void>((resolve) => { release = resolve; });
		let requestStarted!: () => void;
		const entered = new Promise<void>((resolve) => { requestStarted = resolve; });
		f.controls.fetch = async (_input, init) => {
			const access = new Headers(init?.headers).get("Authorization");
			if (access === "Bearer private-access-a") { requestStarted(); await pending; }
			return new Response(JSON.stringify({ models: [{ slug: access === "Bearer private-access-a" ? models[0]!.id : models[1]!.id, visibility: "list", display_name: access }] }));
		};
		const old = f.service.refreshModels();
		await entered;
		await f.service.act({ action: "select", accountId: "account-b" });
		assert.deepEqual(f.service.availableModels(models).map((model) => model.id), [models[1]!.id]);
		release(); await old;
		assert.deepEqual(f.service.availableModels(models).map((model) => model.id), [models[1]!.id]);
		assert.equal(f.service.status().activeAccountId, "account-b");
	} finally { f.cleanup(); }
});

test("a stale model-list 401 for account A cannot replace account B's connected status", async () => {
	const f = await fixture();
	try {
		let release!: () => void;
		const wait = new Promise<void>((resolve) => { release = resolve; });
		let entered!: () => void;
		const started = new Promise<void>((resolve) => { entered = resolve; });
		f.controls.fetch = async (_input, init) => {
			if (new Headers(init?.headers).get("Authorization") === "Bearer private-access-a") { entered(); await wait; return new Response("not accepted", { status: 401 }); }
			return new Response(JSON.stringify({ models: [{ slug: models[1]!.id, display_name: "Account B", visibility: "list" }] }));
		};
		const stale = f.service.refreshModels().then(() => false, () => true);
		await started;
		await f.service.act({ action: "select", accountId: "account-b" });
		release(); assert.equal(await stale, true);
		assert.equal(f.service.status().state, "connected");
		assert.equal(f.service.status().message, undefined);
		assert.equal(f.service.status().activeAccountId, "account-b");
		assert.deepEqual(f.service.availableModels(models).map((model) => model.id), [models[1]!.id]);
	} finally { f.cleanup(); }
});

test("status JSON exposes account labels and connection state without tokens, client IDs, installation ID or identity subjects", async () => {
	const f = await fixture();
	try {
		const state = f.store.readState();
		const encoded = JSON.stringify(f.service.status());
		for (const selected of state.accounts) {
			for (const secret of [selected.clientId, selected.subject!, selected.credential!.access, selected.credential!.refresh, selected.credential!.idToken]) assert.ok(!encoded.includes(secret), `status must omit ${secret}`);
		}
		assert.ok(!encoded.includes(state.installationId));
		assert.equal(f.service.status().accounts.length, 2);
		assert.notEqual(f.service.status().accounts[0]!.label, f.service.status().accounts[1]!.label, "same-email registrations have distinct labels");
	} finally { f.cleanup(); }
});

test("controller serializes concurrent login requests, cancels the pending flow and keeps previous credentials", async () => {
	const f = await fixture();
	try {
		let entered!: () => void;
		const started = new Promise<void>((resolve) => { entered = resolve; });
		f.controls.login = async (_id, signal) => {
			entered();
			return new Promise((_resolve, reject) => signal!.addEventListener("abort", () => reject(new OpenAIOAuthError("cancelled", "Cancelled.")), { once: true }));
		};
		const before = f.store.readState();
		const first = f.service.act({ action: "login" });
		const concurrent = f.service.act({ action: "login" });
		await assert.rejects(concurrent, /Finish or cancel/);
		assert.equal((await first).loginPending, true);
		await started;
		await assert.rejects(f.service.act({ action: "login" }), /Finish or cancel/);
		await assert.rejects(f.service.act({ action: "mode", mode: "api_key" }), /Finish or cancel/);
		assert.equal((await f.service.act({ action: "cancel" })).loginPending, false);
		assert.deepEqual(f.store.readState(), before);
	} finally { f.cleanup(); }
});

test("successful controller login activates OAuth without a key and refreshes the account catalog", async () => {
	const f = await fixture();
	try {
		await f.service.act({ action: "mode", mode: "api_key" });
		await f.service.act({ action: "login", accountId: "account-b" });
		const status = await settled(f.service);
		assert.equal(status.state, "connected");
		assert.equal(status.apiKeyPresent, false);
		assert.equal(status.activeAccountId, "account-b");
		assert.equal(status.mode, "oauth");
		assert.deepEqual(f.service.availableModels(models).map((model) => model.id), [models[1]!.id]);
	} finally { f.cleanup(); }
});

test("concurrent Models auth resolution rotates a session exactly once and durably writes the replacement", async () => {
	const f = await fixture();
	try {
		await f.store.transaction((state) => { state.accounts[0]!.credential!.expires = Date.now() - 1; });
		f.controls.refresh = async (credential) => { await delay(20); return { ...credential, access: "durable-replacement", refresh: "durable-refresh", expires: Date.now() + 3600_000 }; };
		const collection = f.collection();
		const result = await Promise.all([collection.getAuth("openai"), collection.getAuth("openai")]);
		assert.deepEqual(result.map((auth) => auth?.auth.apiKey), ["durable-replacement", "durable-replacement"]);
		assert.equal(f.controls.refreshCount, 1);
		assert.equal(f.store.readState().accounts[0]!.credential!.refresh, "durable-refresh");
		assert.equal(f.store.readState().accounts[0]!.credential!.accountId, "account-a", "provider-private metadata is safe to preserve in the encrypted record");
	} finally { f.cleanup(); }
});

test("request generation is captured before an expired-account refresh waits for the lock, so selecting B cannot authorize A's request as B", { timeout: 10_000 }, async () => {
	for (const operation of ["getAuth", "streamSimple"] as const) {
		const f = await fixture();
		let release!: () => void;
		try {
			await f.store.transaction((state) => { state.accounts[0]!.credential!.expires = Date.now() - 1; });
			// Both accounts can serve this model: a missing generation guard would actually dispatch B.
			f.controls.fetch = async () => new Response(JSON.stringify({ models: [{ slug: models[0]!.id, display_name: "Shared model", visibility: "list" }] }));
			const waitForRelease = new Promise<void>((resolve) => { release = resolve; });
			let signalEntered!: () => void;
			const entered = new Promise<void>((resolve) => { signalEntered = resolve; });
			let signalDrained!: () => void;
			const drained = new Promise<void>((resolve) => { signalDrained = resolve; });
			let readAccount: unknown;
			let waitSignal: AbortSignal | undefined;
			const delayed: CredentialStore = {
				read: async (...args) => { const current = await f.service.credentials.read(...args); readAccount = current?.type === "oauth" ? current.accountId : undefined; return current; },
				list: (...args) => f.service.credentials.list(...args),
				delete: (...args) => f.service.credentials.delete(...args),
				modify: async (provider, mutate, options) => {
					waitSignal = options?.signal;
					signalEntered();
					await waitForRelease;
					try { return await f.service.credentials.modify(provider, mutate, options); }
					finally { signalDrained(); }
				},
			};
			let baseCalls = 0;
			const fake: Provider = { ...base, streamSimple: () => { baseCalls++; const stream = new AssistantMessageEventStream(); stream.push({ type: "done", reason: "stop", message: message() }); stream.end(); return stream; } };
			const raw = createModels({ credentials: delayed, authContext: { env: async () => undefined, fileExists: async () => false } });
			raw.setProvider(f.service.provider(fake));
			const collection = scopePiRequests(raw, f.service.requestSignal);
			// Attach rejection handling immediately; selecting B aborts the old request synchronously.
			const outcome = operation === "getAuth"
				? collection.getAuth("openai").then((value) => ({ value, rejected: false }), () => ({ value: undefined, rejected: true }))
				: collection.streamSimple(models[0]!, { messages: [] }).result().then((value) => ({ value, rejected: false }), () => ({ value: undefined, rejected: true }));
			await entered;
			assert.equal(readAccount, "account-a");
			assert.equal(waitSignal?.aborted, false);
			await f.service.act({ action: "select", accountId: "account-b" });
			assert.equal(f.store.readState().activeAccountId, "account-b", "B wins the store mutation before A's refresh callback enters");
			assert.equal(waitSignal?.aborted, true, "the refresh lock wait remains bound to the original account generation");
			release();
			const completed = await outcome;
			await drained;
			if (operation === "getAuth") assert.equal(completed.rejected, true, "A's request cannot resolve B's bearer");
			else {
				const result = completed.value as AssistantMessage | undefined;
				assert.ok(completed.rejected || (result && ["aborted", "error"].includes(result.stopReason)));
			}
			assert.equal(f.controls.refreshCount, 0, "no refresh runs using B's token set for the old request");
			assert.equal(baseCalls, 0, "the old request never reaches inference dispatch");
			assert.equal(f.service.status().state, "connected");
		} finally { release?.(); f.cleanup(); }
	}
});

test("failed login does not expose upstream errors or authorization URLs in status", async () => {
	const f = await fixture();
	try {
		f.controls.login = async () => { throw new Error("https://auth.openai.com/authorize?id_token_hint=private-id-token&access=private-access"); };
		await f.service.act({ action: "login" });
		const status = await settled(f.service);
		assert.equal(status.state, "error");
		assert.ok(!JSON.stringify(status).includes("id_token_hint"));
		assert.ok(!JSON.stringify(status).includes("private-access"));
		assert.match(status.message!, /API key was not used/);
	} finally { f.cleanup(); }
});

test("terminal refresh clears only the matching account tokens, retains registration and cannot fall back to an available API key", async () => {
	const f = await fixture();
	try {
		f.controls.keyPresent = true;
		await f.store.transaction((state) => { state.accounts[0]!.credential!.expires = Date.now() - 1; });
		f.controls.refresh = async () => { throw new OpenAIOAuthError("invalid_grant", "Your session ended."); };
		const collection = f.collection();
		await assert.rejects(collection.getAuth("openai"));
		const state = f.store.readState();
		assert.equal(state.accounts[0]!.clientId, "oaiapp_private_a");
		assert.equal(state.accounts[0]!.credential, undefined);
		assert.equal(state.accounts[1]!.credential!.access, "private-access-b");
		assert.equal(state.mode, "oauth");
		assert.equal(await collection.getAuth("openai"), undefined);
		assert.equal(f.service.authorized(), false);
		assert.equal(f.service.status().state, "reauth_required");
	} finally { f.cleanup(); }
});

test("a terminal failure from an older rotation cannot clear a newer replacement token set", async () => {
	const f = await fixture();
	try {
		let replaced = false;
		const adapter: OpenAICredentials = {
			...f.store,
			async transaction<T>(mutate: Parameters<OpenAICredentials["transaction"]>[0], operation?: { signal?: AbortSignal }): Promise<T> {
				try { return await f.store.transaction(mutate, operation) as T; }
				catch (error) {
					if (!replaced) { replaced = true; await f.store.transaction((state) => { state.accounts[0]!.credential!.refresh = "newer-rotation"; }); }
					throw error;
				}
			},
		};
		const service = f.create(adapter);
		await assert.rejects(service.credentials.modify("openai", async () => { throw new OpenAIOAuthError("invalid_grant", "Old session ended."); }));
		assert.equal(f.store.readState().accounts[0]!.credential!.refresh, "newer-rotation");
		assert.equal(service.status().state, "connected");
		assert.equal(service.status().message, undefined);
	} finally { f.cleanup(); }
});

test("temporary refresh failure preserves credentials and confirmed subscription mode", async () => {
	const f = await fixture();
	try {
		await f.store.transaction((state) => { state.accounts[0]!.credential!.expires = Date.now() - 1; });
		const before = f.store.readState();
		f.controls.refresh = async () => { throw new OpenAIOAuthError("network_error", "Temporarily unavailable."); };
		await assert.rejects(f.collection().getAuth("openai"));
		assert.deepEqual(f.store.readState(), before);
	} finally { f.cleanup(); }
});

test("logout preserves registration and tells the user when remote revocation was not confirmed", async () => {
	const f = await fixture();
	try {
		f.controls.revokeConfirmed = false;
		const status = await f.service.act({ action: "logout" });
		assert.match(status.message!, /revocation could not be confirmed/i);
		assert.match(status.message!, /ChatGPT settings/);
		assert.equal(f.store.readState().accounts[0]!.credential, undefined);
		assert.equal(f.store.readState().accounts[0]!.clientId, "oaiapp_private_a");
		assert.equal(f.store.readState().accounts[1]!.credential!.access, "private-access-b");
		assert.equal(f.service.authorized(), false);
	} finally { f.cleanup(); }
});

test("strict subscription stream fails on EOF, iterator failure or non-completed done and preserves completed/error terminal events", async () => {
	const partial: AssistantMessageEvent = { type: "text_delta", contentIndex: 0, delta: "mock", partial: message("pending") };
	const eof = strictSubscriptionStream(events([partial]), () => false, models[0]);
	assert.equal((await collect(eof)).at(-1)!.type, "error");
	assert.equal((await eof.result()).stopReason, "error");
	const done: AssistantMessageEvent = { type: "done", reason: "stop", message: message() };
	const incomplete = strictSubscriptionStream(events([done]), () => false, models[0]);
	assert.equal((await collect(incomplete)).at(-1)!.type, "error");
	const complete = strictSubscriptionStream(events([partial, done]), () => true, models[0]);
	assert.equal((await collect(complete)).at(-1)!.type, "done");
	assert.equal((await complete.result()).stopReason, "stop");
	const upstreamError: AssistantMessageEvent = { type: "error", reason: "error", error: { ...message("error"), errorMessage: "subscription_sharing_usage_limit_exceeded" } };
	const failed = strictSubscriptionStream(events([upstreamError]), () => false, models[0]);
	assert.deepEqual(await collect(failed), [upstreamError]);
	async function* throws(): AsyncGenerator<AssistantMessageEvent> { yield partial; throw new Error("private upstream text"); }
	const interrupted = strictSubscriptionStream(throws(), () => false, models[0]);
	const failures = await collect(interrupted);
	assert.equal(failures.at(-1)!.type, "error");
	assert.ok(!JSON.stringify(failures).includes("private upstream text"));
});

test("OAuth provider enforces store=false/stream=true, completed terminal event and cancellation on account change", async () => {
	const f = await fixture();
	try {
		await f.service.refreshModels();
		let payload: unknown;
		let runSignal: AbortSignal | undefined;
		const fake: Provider = { ...base, streamSimple: (model, _context, options) => {
			const output = new AssistantMessageEventStream();
			runSignal = options?.signal;
			void (async () => {
				payload = await options?.onPayload?.({ store: true, stream: false, model: model.id, input: [] }, model);
				await options?.onProviderStreamEvent?.({ type: "response.completed" }, model);
				output.push({ type: "done", reason: "stop", message: message() }); output.end();
			})();
			return output;
		} };
		const collection = f.collection(f.service.provider(fake));
		const result = await collection.streamSimple(models[0]!, { messages: [] }).result();
		assert.equal(result.stopReason, "stop");
		assert.deepEqual(payload, { store: false, stream: true, model: models[0]!.id, input: [] });
		assert.equal(runSignal?.aborted, false);
		await f.service.act({ action: "select", accountId: "account-b" });
		assert.equal(runSignal?.aborted, true);
	} finally { f.cleanup(); }
});

test("auth mutation schema only permits known actions, bounded account IDs and explicit modes", () => {
	assert.deepEqual(parseOpenAIAuthAction({ action: "login", accountId: "saved", access: "secret" }), { action: "login", accountId: "saved" });
	assert.deepEqual(parseOpenAIAuthAction({ action: "mode", mode: "oauth" }), { action: "mode", mode: "oauth" });
	assert.deepEqual(parseOpenAIAuthAction({ action: "cancel" }), { action: "cancel" });
	assert.deepEqual(parseOpenAIAuthAction({ action: "acknowledge_plan" }), { action: "acknowledge_plan" });
	assert.deepEqual(parseOpenAIAuthAction({ action: "retry_usage" }), { action: "retry_usage" });
	for (const invalid of [null, [], "login", { action: "delete-all" }, { action: "mode", mode: "ambient" }, { action: "select", accountId: 1 }, { action: "login", accountId: "x".repeat(101) }, { action: "logout", accountId: {} }]) assert.equal(parseOpenAIAuthAction(invalid), undefined);
});

test("the first plan notice is persisted per registration without aborting a lesson or returning account secrets", async () => {
	const f = await fixture();
	try {
		assert.equal(f.service.status().planWelcomeRequired, true);
		const before = f.service.requestSignal();
		const acknowledged = await f.service.act({ action: "acknowledge_plan" });
		assert.equal(acknowledged.planWelcomeRequired, false);
		assert.equal(before.aborted, false, "dismissing informational UI must not interrupt inference");
		assert.equal(f.create().status().planWelcomeRequired, false, "acknowledgement survives reopening the vault");
		await f.service.act({ action: "logout" });
		await f.store.transaction(state => { state.accounts[0]!.credential = token("a"); });
		assert.equal(f.service.status().planWelcomeRequired, false, "reconnect retains the acknowledged registration");
		await f.service.act({ action: "select", accountId: "account-b" });
		assert.equal(f.service.status().planWelcomeRequired, true, "a distinct registration has its own notice");
		await f.service.act({ action: "mode", mode: "api_key" });
		assert.equal(f.service.status().planWelcomeRequired, false);
		const publicState = JSON.stringify(f.service.status());
		for (const secret of ["private-access", "private-refresh", "private-id-token", "oaiapp_private", "private-subject"]) assert.ok(!publicState.includes(secret));
	} finally { f.cleanup(); }
});

test("pre-stream subscription limit pauses inference until explicit retry, with no API-key fallback or automatic SDK retry", async () => {
	const f = await fixture();
	try {
		f.controls.keyPresent = true;
		await f.service.refreshModels();
		let requests = 0;
		const denied: typeof fetch = async () => {
			requests++;
			return Response.json({ error: { code: "subscription_sharing_usage_limit_exceeded", message: "Plan or app limit reached", type: "rate_limit_error" } }, { status: 429 });
		};
		const collection = f.collection();
		assert.equal((await collection.streamSimple(models[0]!, { messages: [] }, { fetch: denied }).result()).stopReason, "error");
		assert.equal(requests, 1);
		assert.equal(f.service.status().usageLimit, "limit_reached");
		assert.equal(f.service.status().authorized, true, "usage is distinct from authorization");
		const blocked = await collection.streamSimple(models[0]!, { messages: [] }, { fetch: denied }).result();
		assert.match(blocked.errorMessage!, /Manage usage/);
		assert.equal(requests, 1, "a subsequent turn never reaches the Responses endpoint");
		await f.service.act({ action: "acknowledge_plan" });
		assert.equal(f.service.status().usageLimit, "limit_reached", "welcome dismissal cannot bypass a usage limit");
		await f.service.act({ action: "retry_usage" });
		assert.equal(f.service.status().usageLimit, undefined);
		await collection.streamSimple(models[0]!, { messages: [] }, { fetch: denied }).result();
		assert.equal(requests, 2, "manual retry permits exactly one fresh attempt");
		assert.equal(f.service.mode(), "oauth");
		assert.ok(f.store.readState().accounts[0]!.credential);
	} finally { f.cleanup(); }
});

test("exact streamed usage errors drive the recovery UI and stale account errors cannot affect a new selection", async () => {
	for (const [code,expected] of [["subscription_sharing_usage_limit_exceeded", "limit_reached"], ["subscription_sharing_usage_unavailable", "unavailable"]] as const) {
		const f = await fixture();
		try {
			await f.service.refreshModels();
			let staleEvent: (() => Promise<void>) | undefined;
			const fake: Provider = { ...base, streamSimple: (model,_context,options) => {
				const stream = new AssistantMessageEventStream();
				const emit = async () => { await options?.onProviderStreamEvent?.({ type: "response.failed", response: { error: { code } } }, model); };
				staleEvent = emit;
				void emit().then(() => { stream.push({ type: "error", reason: "error", error: { ...message("error"), errorMessage: code } }); stream.end(); });
				return stream;
			} };
			const result = await f.collection(f.service.provider(fake)).streamSimple(models[0]!, { messages: [] }).result();
			assert.equal(result.stopReason, "error");
			assert.equal(f.service.status().usageLimit, expected);
			assert.equal(f.service.status().state, "connected");
			await f.service.act({ action: "select", accountId: "account-b" });
			assert.equal(f.service.status().usageLimit, undefined);
			await staleEvent!();
			assert.equal(f.service.status().usageLimit, undefined, "account A's late event cannot mark B as limited");
		} finally { f.cleanup(); }
	}
});

test("OAuth mutation requests require exact localhost origin, matching Host and JSON, rejecting cross-site and DNS rebinding", () => {
	const request = (url = "http://127.0.0.1:3000/api/openai-auth", overrides: Record<string, string> = {}) => new Request(url, { method: "POST", headers: { origin: "http://127.0.0.1:3000", host: "127.0.0.1:3000", "content-type": "application/json", "sec-fetch-site": "same-origin", ...overrides }, body: "{}" });
	assert.equal(validOpenAIAuthRequest(request()), true);
	assert.equal(validOpenAIAuthRequest(request("http://localhost:3000/api/auth/openai")), true, "Next's internal hostname may differ from the public loopback Host");
	assert.equal(validOpenAIAuthRequest(request("http://localhost:3000/api/auth/openai", { host: "127.0.0.1:4000", origin: "http://127.0.0.1:4000" })), true, "Origin is checked against the public authority, not the reconstructed Next URL");
	assert.equal(validOpenAIAuthRequest(request(undefined, { host: "127.0.0.1:4000" })), false, "a different loopback Origin is not trusted");
	assert.equal(validOpenAIAuthRequest(request(undefined, { "content-type": "application/json; charset=utf-8" })), true);
	const invalidHeaders: Record<string, string>[] = [{ origin: "https://attacker.test" }, { origin: "null" }, { origin: "" }, { host: "attacker.test" }, { "content-type": "text/plain" }, { "sec-fetch-site": "cross-site" }, { "sec-fetch-site": "same-site" }];
	for (const overrides of invalidHeaders) assert.equal(validOpenAIAuthRequest(request(undefined, overrides)), false);
	assert.equal(validOpenAIAuthRequest(request("http://attacker.test/api/openai-auth", { origin: "http://attacker.test", host: "attacker.test" })), false);
});
