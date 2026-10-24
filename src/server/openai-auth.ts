/** OpenAI auth composition: the desktop vault, provider policy and client-safe control surface. */
import path from "node:path";
import { createHash, randomUUID } from "node:crypto";
import {
	InMemoryCredentialStore, lazyStream,
	type Api, type Credential, type CredentialStore, type Model, type Provider,
	type AssistantMessage, type AssistantMessageEvent, type SimpleStreamOptions,
} from "@earendil-works/pi-ai";
import { AssistantMessageEventStream } from "@earendil-works/pi-ai/utils/event-stream";
import { openaiProvider } from "@earendil-works/pi-ai/providers/openai";
import { PATHS } from "../../config.ts";
import { configurePiModelsAuth, piModels } from "../agent/models.ts";
import type { OpenAIAuthAction, OpenAIAuthStatus, OpenAIAuthMode } from "../core/openai-auth.ts";
import { createOpenAICredentials, type OpenAIAuthState, type OpenAIOAuthCredential } from "../store/openai-credentials.ts";
import { createOpenAIOAuth, OpenAIOAuthError } from "./openai-oauth-flow.ts";
import { normalizeOpenAIPlanRequest } from "./openai-plan-request.ts";

type Vault = ReturnType<typeof createOpenAICredentials>;
type Flow = ReturnType<typeof createOpenAIOAuth>;

/** Authorization URLs (which can include id_token_hint) travel only over the private parent/child IPC channel. */
export function openOAuthBrowser(url: string): Promise<void> {
	return new Promise((resolve, reject) => {
		if (!process.send || !process.connected) {
			reject(new Error("Open the desktop app to sign in with ChatGPT. The secure browser bridge is unavailable in this server."));
			return;
		}
		const id = randomUUID();
		const cleanup = () => { clearTimeout(timer); process.off("message", onMessage); process.off("disconnect", onDisconnect); };
		const onDisconnect = () => { cleanup(); reject(new Error("The desktop connection closed. Reopen the app and try again.")); };
		const onMessage = (message: unknown) => {
			if (!message || typeof message !== "object") return;
			const value = message as Record<string, unknown>;
			if (value.type !== "lh:oauth-open-result" || value.id !== id) return;
			cleanup();
			if (value.ok === true) resolve();
			else reject(new Error("The system browser could not be opened. Try signing in again."));
		};
		const timer = setTimeout(() => { cleanup(); reject(new Error("The desktop browser did not respond. Reopen the app and try again.")); }, 15_000);
		process.on("message", onMessage);
		process.once("disconnect", onDisconnect);
		process.send({ type: "lh:oauth-open", id, url }, (error) => { if (error) { cleanup(); reject(new Error("The secure desktop browser bridge failed.")); } });
	});
}

function terminalOAuthError(error: unknown): OpenAIOAuthError | undefined {
	let current = error;
	for (let depth = 0; current instanceof Error && depth < 5; depth++, current = current.cause) {
		if (current instanceof OpenAIOAuthError && current.terminal) return current;
	}
	return undefined;
}

function safeFailure(error: unknown): string {
	if (error instanceof OpenAIOAuthError) return error.safeMessage;
	// Never expose upstream bodies, token validation details or authorization URLs.
	if (error instanceof Error && /secure browser bridge is unavailable/.test(error.message)) return error.message;
	if (error instanceof Error && /encryption|secure storage|vault key/i.test(error.message)) return "Secure credential storage is unavailable. Open the desktop app under the same operating-system account and try again.";
	return "ChatGPT could not be connected. Check your connection and try again. Your API key was not used.";
}

export function strictSubscriptionStream(source: AsyncIterable<AssistantMessageEvent>, completed: () => boolean, model?: Model<Api>): AssistantMessageEventStream {
	const result = new AssistantMessageEventStream();
	let last: AssistantMessage = {
		role: "assistant", content: [], api: model?.api ?? "openai-responses", provider: "openai", model: model?.id ?? "unknown", timestamp: Date.now(), stopReason: "error",
		usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
	};
	const fail = () => {
		const error = { ...last, stopReason: "error" as const, errorMessage: "ChatGPT response did not complete. Please retry; no API-key fallback was used." };
		result.push({ type: "error", reason: "error", error });
		result.end(error);
	};
	void (async () => {
		let terminal = false;
		try {
			for await (const event of source) {
				if ("partial" in event) last = event.partial;
				if (event.type === "done") last = event.message;
				if (event.type === "error") last = event.error;
				if (event.type === "done" && !completed()) {
					fail();
					return;
				}
				if (event.type === "done" || event.type === "error") terminal = true;
				result.push(event);
			}
			if (!terminal) fail();
			else result.end(last);
		} catch {
			fail();
		}
	})();
	return result;
}

export interface OpenAIAuthServiceOptions {
	store: Vault;
	flow?: Flow;
	openBrowser?: (url: string) => Promise<void>;
	fetch?: typeof fetch;
	now?: () => number;
	/** Tests supply this instead of reading the user's process environment. */
	apiKeyPresent?: () => boolean;
	resolveAccess?: (signal?: AbortSignal) => Promise<string | undefined>;
}

export function createOpenAIAuthService(options: OpenAIAuthServiceOptions) {
	const store = options.store;
	const flow = options.flow ?? createOpenAIOAuth({ store, openBrowser: options.openBrowser ?? openOAuthBrowser, fetch: options.fetch });
	const request = options.fetch ?? globalThis.fetch;
	const now = options.now ?? Date.now;
	const fallback = new InMemoryCredentialStore();
	let pending: AbortController | undefined;
	let pendingResult: Promise<void> | undefined;
	let changing = false;
	let usageLimit: OpenAIAuthStatus["usageLimit"];
	let lifecycle = new AbortController();
	const invalidateRequests = () => { lifecycle.abort(); lifecycle = new AbortController(); usageLimit = undefined; };
	// Remember only token digests, so an already-resolved OAuth request can never
	// become an API-key request if the mode changes before provider dispatch.
	const issuedOAuth = new Map<string, { accountId: string; generation: AbortController }>();
	const tokenDigest = (token: string) => createHash("sha256").update(token).digest("hex");
	let stateError: { reauth: boolean; message: string } | undefined;
	let recoveryAPIKey = false;
	let cached: { account: string; at: number; models: Array<{ slug: string; name: string }> } | undefined;
	let modelRefresh: { account: string; generation: AbortController; promise: Promise<void> } | undefined;
	const apiKeyPresent = options.apiKeyPresent ?? (() => !!process.env.OPENAI_API_KEY);
	const state = (): OpenAIAuthState => recoveryAPIKey ? { version: 1, installationId: "", mode: "api_key", accounts: [] } : store.readState();
	const account = (record = state()) => record.accounts.find((entry) => entry.id === record.activeAccountId);
	const mode = (): OpenAIAuthMode => state().mode;
	const authorized = () => {
		if (changing || stateError?.reauth) return false;
		const record = state();
		return record.mode === "api_key" ? apiKeyPresent() : !!account(record)?.credential?.scopes.includes("chatgpt.tokens.use.direct");
	};
	const status = (): OpenAIAuthStatus => {
		try {
			const record = state();
			const selected = account(record);
			const allowed = authorized();
			return {
				provider: "openai", mode: record.mode, authorized: allowed, apiKeyPresent: apiKeyPresent(),
				state: pending ? "pending" : stateError ? stateError.reauth ? "reauth_required" : "error" : allowed ? "connected" : record.mode === "oauth" && selected ? "reauth_required" : "disconnected",
				accounts: record.accounts.map((entry, index) => ({ id: entry.id, label: `${entry.email ?? "ChatGPT account"} · ${index + 1}`, connected: !!entry.credential })),
				activeAccountId: record.activeAccountId, loginPending: !!pending,
				planWelcomeRequired: record.mode === "oauth" && allowed && selected?.planUsageAcknowledged !== true,
				...(record.mode === "oauth" && allowed && usageLimit ? { usageLimit } : {}),
				...(stateError ? { message: stateError.message } : record.mode === "oauth" && selected?.credential && !allowed ? { message: "ChatGPT sign-in succeeded, but permission to use your plan was not granted. Reconnect and allow ChatGPT plan usage." } : {}),
			};
		} catch {
			return { provider: "openai", mode: "oauth", state: "error", authorized: false, apiKeyPresent: apiKeyPresent(), accounts: [], loginPending: !!pending, message: "The protected credential store could not be opened. Use the same operating-system account that created it." };
		}
	};

	const credentials: CredentialStore = {
		async read(provider, operation) {
			operation?.signal?.throwIfAborted();
			if (provider !== "openai") return fallback.read(provider, operation);
			const record = state();
			const selected = account(record);
			return record.mode === "oauth" && selected?.credential ? { ...selected.credential, accountId: selected.id } : undefined;
		},
		async list(operation) {
			const other = await fallback.list(operation);
			return await this.read("openai", operation) ? [...other, { providerId: "openai", type: "oauth" as const }] : other;
		},
		async modify(provider, mutate, operation) {
			if (provider !== "openai") return fallback.modify(provider, mutate, operation);
			let failedAccount: string | undefined;
			let failedRefresh: string | undefined;
			try {
				return await store.transaction(async (record) => {
					const selected = account(record);
				if (changing || record.mode !== "oauth" || !selected?.credential) return undefined;
					failedAccount = selected.id;
					failedRefresh = selected.credential.refresh;
					const next = await mutate({ ...selected.credential, accountId: selected.id });
					if (next?.type === "oauth") selected.credential = next as OpenAIOAuthCredential;
					return selected.credential ? { ...selected.credential, accountId: selected.id } : undefined;
				}, operation);
			} catch (error) {
				if (terminalOAuthError(error)) {
					const clearedActive = await store.transaction((record) => {
						const selected = record.accounts.find((entry) => entry.id === failedAccount);
						if (selected && selected.credential?.refresh === failedRefresh) {
							delete selected.credential;
							return record.activeAccountId === selected.id && record.mode === "oauth";
						}
						return false;
					});
					if (clearedActive) {
						stateError = { reauth: true, message: "Your ChatGPT session expired or was disconnected. Sign in again to continue." };
						cached = undefined;
					}
				}
				throw error;
			}
		},
		async delete(provider, operation) {
			if (provider !== "openai") return fallback.delete(provider, operation);
			await store.transaction((record) => { const selected = account(record); if (selected) delete selected.credential; }, operation);
		},
	};

	async function refreshModels(force = false, signal?: AbortSignal): Promise<void> {
		const record = state();
		const selected = account(record);
		if (record.mode !== "oauth" || !selected?.credential?.scopes.includes("chatgpt.tokens.use.direct")) { cached = undefined; return; }
		if (!force && cached?.account === selected.id && now() - cached.at < 60_000) return;
		if (modelRefresh?.account === selected.id && modelRefresh.generation === lifecycle) return modelRefresh.promise;
		const selectedId = selected.id;
		const generation = lifecycle;
		const isCurrent = () => generation === lifecycle && mode() === "oauth" && account()?.id === selectedId;
		const promise = (async () => {
			try {
				const access = options.resolveAccess ? await options.resolveAccess(signal) : (await piModels().getAuth("openai", { signal }))?.auth.apiKey;
				if (!access) throw new Error("Not connected");
				const response = await request("https://api.openai.com/v1/models", { headers: { Authorization: `Bearer ${access}` }, signal: AbortSignal.any([...(signal ? [signal] : []), generation.signal, AbortSignal.timeout(15_000)]), redirect: "error" });
				if (!response.ok) {
					if (isCurrent()) {
						if (response.status === 401) stateError = { reauth: true, message: "ChatGPT did not accept this session. Sign in again or check app access in ChatGPT settings." };
						else stateError = { reauth: false, message: `ChatGPT models are unavailable (HTTP ${response.status}). Check app permissions and your connection, then retry.` };
					}
					throw new Error("ChatGPT model discovery failed");
				}
				const data: unknown = await response.json();
				if (!data || typeof data !== "object" || !Array.isArray((data as { models?: unknown }).models)) throw new Error("Invalid account model catalog");
				const rows = (data as { models: unknown[] }).models;
				const seen = new Set<string>();
				const models: Array<{ slug: string; name: string }> = [];
				for (const row of rows) {
					if (!row || typeof row !== "object") continue;
					const value = row as Record<string, unknown>;
					if (value.visibility !== "list" || typeof value.slug !== "string" || seen.has(value.slug)) continue;
					seen.add(value.slug);
					models.push({ slug: value.slug, name: typeof value.display_name === "string" ? value.display_name : value.slug });
				}
				if (isCurrent()) {
					cached = { account: selectedId, at: now(), models };
					stateError = undefined;
				}
			} catch (error) {
				if (isCurrent() && !stateError) stateError = { reauth: false, message: "The ChatGPT model list could not be refreshed. Check your connection and retry." };
				throw error;
			}
		})();
		modelRefresh = { account: selectedId, generation, promise };
		try { await promise; } finally { if (modelRefresh?.promise === promise) modelRefresh = undefined; }
	}

	function availableModels(base: readonly Model<Api>[]): Model<Api>[] {
		if (mode() !== "oauth") return [...base];
		if (cached?.account !== account()?.id) return [];
		const byId = new Map(base.map((model) => [model.id, model]));
		return (cached?.models ?? []).flatMap((row) => { const model = byId.get(row.slug); return model ? [{ ...model, name: row.name }] : []; });
	}

	function provider(base = openaiProvider() as Provider): Provider {
		const apiKey = base.auth.apiKey!;
		const auth: Provider["auth"] = {
			apiKey: {
				...apiKey,
				check: async (input) => changing || mode() === "oauth" ? undefined : apiKey.check ? apiKey.check(input) : (await apiKey.resolve(input)) ? { type: "api_key" } : undefined,
				resolve: async (input) => changing || mode() === "oauth" ? undefined : apiKey.resolve(input),
			},
			oauth: {
				name: "OpenAI (ChatGPT subscription)", isSubscription: true, loginLabel: "Continue with ChatGPT",
				login: async (interaction) => flow.login(undefined, interaction.signal),
				refresh: (credential, signal) => flow.refresh(credential as OpenAIOAuthCredential, signal),
				toAuth: async (credential) => {
					const current = account();
					if (changing || mode() !== "oauth" || !current?.credential?.scopes.includes("chatgpt.tokens.use.direct") || current.id !== credential.accountId) throw new Error("The active ChatGPT account changed or plan usage is disabled. Reconnect or retry your request.");
					issuedOAuth.set(tokenDigest(credential.access), { accountId: current.id, generation: lifecycle });
					return { apiKey: credential.access };
				},
			},
		};
		function subscription(model: Model<Api>, run: (wrapped: SimpleStreamOptions) => AsyncIterable<AssistantMessageEvent>, streamOptions: SimpleStreamOptions = {}) {
			const stamp = streamOptions.apiKey ? issuedOAuth.get(tokenDigest(streamOptions.apiKey)) : undefined;
			if (!stamp && mode() !== "oauth") return run(streamOptions) as AssistantMessageEventStream;
			const generation = stamp?.generation ?? lifecycle;
			const signal = streamOptions.signal ? AbortSignal.any([streamOptions.signal, generation.signal]) : generation.signal;
			return lazyStream(model, async () => {
				signal.throwIfAborted();
				if (usageLimit) throw new Error(usageLimit === "limit_reached"
					? "ChatGPT plan usage limit reached. Manage usage in ChatGPT settings, then choose Try again."
					: "ChatGPT plan usage is temporarily unavailable. Try again later; your connection is preserved.");
				await refreshModels(false, signal);
				const selected = account();
				if (!stamp || changing || generation !== lifecycle || mode() !== "oauth" || !selected?.credential || selected.id !== stamp.accountId || selected.credential.access !== streamOptions.apiKey) throw new Error("The ChatGPT connection changed. Retry your request.");
				if (!availableModels(base.getModels()).some((entry) => entry.id === model.id)) throw new Error("This model is not available for the selected ChatGPT account. Choose a model in Settings → Models.");
				let completed = false;
				const observeUsageCode = (code: unknown) => {
					if (generation !== lifecycle || account()?.id !== stamp.accountId) return;
					if (code === "subscription_sharing_usage_limit_exceeded" || code === "subscription_sharing_workplace_individual_usage_limit_exceeded") usageLimit = "limit_reached";
					else if (code === "subscription_sharing_usage_unavailable") usageLimit = "unavailable";
				};
				const fetchRequest = streamOptions.fetch ?? request;
				const source = run({
					...streamOptions,
					signal,
					// No implicit SDK retries for a billable admission failure. A UI action
					// explicitly resumes requests after the user manages their plan usage.
					maxRetries: 0,
					fetch: async (input, init) => {
						const response = await fetchRequest(input, init);
						if (!response.ok) {
							try {
								const body = await response.clone().json() as { error?: { code?: unknown } };
								observeUsageCode(body?.error?.code);
							} catch { /* Plain admission diagnostics are not stable error codes. */ }
						}
						return response;
					},
					onPayload: async (payload, requestModel) => {
						const transformed = await streamOptions.onPayload?.(payload, requestModel);
						return normalizeOpenAIPlanRequest(transformed ?? payload);
					},
					onProviderStreamEvent: async (event, requestModel) => {
						if (event && typeof event === "object") {
							const type = (event as { type?: unknown }).type;
							if (type === "response.completed") completed = true;
							if (type === "response.failed") observeUsageCode((event as { response?: { error?: { code?: unknown } } }).response?.error?.code);
							if (type === "response.incomplete") throw new Error("ChatGPT returned an incomplete response. Retry or select another model.");
						}
						await streamOptions.onProviderStreamEvent?.(event, requestModel);
					},
				});
				return strictSubscriptionStream(source, () => completed, model);
			});
		}
		return {
			...base, auth,
			streamSimple: (model, context, streamOptions) => subscription(model, (wrapped) => base.streamSimple(model, context, wrapped), streamOptions),
			stream: ((model, context, streamOptions) => subscription(model, (wrapped) => base.stream(model, context, wrapped as never), streamOptions as SimpleStreamOptions)) as Provider["stream"],
		};
	}

	async function act(action: OpenAIAuthAction): Promise<OpenAIAuthStatus> {
		if (action.action === "cancel") {
			pending?.abort();
			await pendingResult;
			stateError = undefined;
			return status();
		}
		if (pending || changing) throw new Error("Finish or cancel the current ChatGPT connection change first.");
		if (action.action === "acknowledge_plan") {
			await store.transaction((record) => {
				const selected = account(record);
				if (record.mode === "oauth" && selected?.credential?.scopes.includes("chatgpt.tokens.use.direct")) selected.planUsageAcknowledged = true;
			});
			return status();
		}
		if (action.action === "retry_usage") {
			usageLimit = undefined;
			return status();
		}
		if (action.action === "login") {
			const controller = new AbortController();
			pending = controller;
			stateError = undefined;
			const timer = setTimeout(() => controller.abort(), 10 * 60_000);
			pendingResult = (async () => {
				try {
					await store.ensure();
					controller.signal.throwIfAborted();
					if (action.accountId && !state().accounts.some((entry) => entry.id === action.accountId)) throw new Error("Select a saved ChatGPT account.");
					await flow.login(action.accountId, controller.signal);
					recoveryAPIKey = false;
					invalidateRequests(); cached = undefined;
					await refreshModels(true, controller.signal);
				}
				catch (error) { if (!controller.signal.aborted) stateError = { reauth: !!terminalOAuthError(error), message: safeFailure(error) }; }
				finally { clearTimeout(timer); if (pending === controller) pending = undefined; }
			})();
			return status();
		}
		changing = true;
		invalidateRequests();
		try {
		if (action.action === "mode") {
			try {
				await store.transaction((record) => { record.mode = action.mode; });
				recoveryAPIKey = false;
			} catch (error) {
				// An explicit user choice can recover API-key use even if OS storage
				// is locked. Preserve the encrypted vault, and never select this automatically.
				if (action.mode !== "api_key") throw error;
				recoveryAPIKey = true;
			}
			cached = undefined;
			stateError = recoveryAPIKey ? { reauth: false, message: "API key mode is active for this session. Protected ChatGPT credentials were left unchanged; reconnect the vault before using OAuth." } : undefined;
		} else if (action.action === "select") {
			await store.transaction((record) => {
				if (!record.accounts.some((entry) => entry.id === action.accountId)) throw new Error("Select a saved ChatGPT account.");
				record.activeAccountId = action.accountId; record.mode = "oauth";
			});
			cached = undefined; stateError = undefined;
		} else if (action.action === "logout") {
			let confirmed = true;
			await store.transaction(async (record) => {
				const selected = record.accounts.find((entry) => entry.id === (action.accountId ?? record.activeAccountId));
				if (!selected) return;
				if (selected.credential) confirmed = await flow.revoke(selected.credential, AbortSignal.timeout(20_000));
				delete selected.credential;
			});
			cached = undefined;
			stateError = confirmed ? undefined : { reauth: false, message: "Signed out locally. Remote revocation could not be confirmed. Disconnect LearnHarness in ChatGPT settings to finish." };
		}
		} finally { changing = false; }
		if ((action.action === "mode" || action.action === "select") && mode() === "oauth" && authorized()) { try { await refreshModels(true); } catch { /* status carries safe recovery */ } }
		return status();
	}
	return { status, act, mode, authorized, credentials, provider, refreshModels, availableModels, store, requestSignal: () => lifecycle.signal };
}

export type OpenAIAuthService = ReturnType<typeof createOpenAIAuthService>;
const SERVICE_KEY = Symbol.for("lh.openaiAuthService");
export function openAIAuthService(): OpenAIAuthService {
	const root = globalThis as Record<symbol, OpenAIAuthService | undefined>;
	if (!root[SERVICE_KEY]) {
		const service = createOpenAIAuthService({ store: createOpenAICredentials({ directory: path.join(PATHS.data, "openai-auth") }) });
		// The vault owns a private copy now; render helpers must not inherit the unwrapped key.
		for (const name of Object.keys(process.env)) if (name.toUpperCase() === "LH_OAUTH_ENCRYPTION_KEY") delete process.env[name];
		root[SERVICE_KEY] = service;
		configurePiModelsAuth(service.credentials, service.provider(), service.requestSignal);
	}
	return root[SERVICE_KEY];
}

export function openAIAuthStatus(): OpenAIAuthStatus { return openAIAuthService().status(); }

/** Browser mutations require JSON from this exact app origin; reject cross-site and DNS-rebinding hosts. */
export function validOpenAIAuthRequest(request: Request): boolean {
	const target = new URL(request.url);
	if (!["127.0.0.1", "localhost", "[::1]"].includes(target.hostname)) return false;
	// Next standalone can reconstruct request.url with its internal localhost
	// hostname. The validated HTTP Host is the browser-facing authority.
	const host = request.headers.get("host") ?? target.host;
	let external: URL;
	try { external = new URL(`${target.protocol}//${host}`); } catch { return false; }
	if (!["127.0.0.1", "localhost", "[::1]"].includes(external.hostname) || external.username || external.password || external.pathname !== "/" || external.search || external.hash) return false;
	const origin = request.headers.get("origin");
	if (origin !== external.origin) return false;
	const site = request.headers.get("sec-fetch-site");
	return (!site || site === "same-origin") && request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase() === "application/json";
}

export function parseOpenAIAuthAction(input: unknown): OpenAIAuthAction | undefined {
	if (!input || typeof input !== "object" || Array.isArray(input)) return;
	const value = input as Record<string, unknown>;
	if (value.action === "cancel" || value.action === "acknowledge_plan" || value.action === "retry_usage") return { action: value.action };
	if (value.action === "mode" && (value.mode === "api_key" || value.mode === "oauth")) return { action: "mode", mode: value.mode };
	if (value.action === "select" && typeof value.accountId === "string" && value.accountId.length <= 100) return { action: "select", accountId: value.accountId };
	if ((value.action === "login" || value.action === "logout") && (value.accountId === undefined || (typeof value.accountId === "string" && value.accountId.length <= 100))) return { action: value.action, accountId: value.accountId as string | undefined };
}
