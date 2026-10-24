import React, { act } from "react";
(globalThis as Record<string, unknown>).React = React;

import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import { createRoot, type Root } from "react-dom/client";
import { renderToStaticMarkup } from "react-dom/server";
import { parseHTML } from "linkedom";
import { OpenAIAuthControls, OpenAIAuthSection } from "../components/settings/openai-auth-section.tsx";
import { OpenAIAuthProvider, ChatGPTPlanIndicator } from "../components/openai-auth.tsx";
import { OpenAIAuthServerSync } from "../components/openai-auth-sync.tsx";
import { ServerEventsProvider, type NotifySource } from "../components/server-events.tsx";
import { StatsBar } from "../components/stats-bar.tsx";
import { hasProviderAuthorization, strongKeyless } from "../components/setup-cta.tsx";
import { setupStage } from "../components/setup-dialog.tsx";
import { ModelMenuList } from "../components/settings/model-menu.tsx";
import { onSettingsSaved, notifySettingsSaved } from "../components/settings-signal.ts";
import type { ModelCatalogResponse, OpenAIAuthStatus } from "../src/core/index.ts";

const disconnected: OpenAIAuthStatus = {
	provider: "openai", mode: "oauth", state: "disconnected", authorized: false,
	apiKeyPresent: false, accounts: [], loginPending: false,
};
function html(status: OpenAIAuthStatus, error: string | null = null) {
	return renderToStaticMarkup(<OpenAIAuthControls status={status} busy={false} error={error} onAction={() => {}} onRetry={() => {}} apiKeyEditor={<input aria-label="API key fixture" />} />);
}

describe("OpenAI connection UI", () => {
	it("shows both explicit auth modes and keeps the API editor confined to API mode", () => {
		assert.match(html(disconnected), /API key/);
		assert.match(html(disconnected), /Continue with ChatGPT/);
		assert.match(html(disconnected), /\/branding\/chatgpt-logo-white\.svg/);
		assert.doesNotMatch(html(disconnected), /API key fixture/);
		assert.match(html({ ...disconnected, mode: "api_key" }), /API key fixture/);
		assert.match(html({ ...disconnected, mode: "api_key" }), /Add your OpenAI API key below/);
	});
	it("renders pending, reauth and recoverable errors without an auth URL or tokens", () => {
		const pending = html({ ...disconnected, state: "pending", loginPending: true });
		assert.match(pending, /Cancel sign-in/);
		assert.match(pending, /system browser/);
		assert.doesNotMatch(pending, /data-testid="openai-login"/);
		assert.match(html({ ...disconnected, state: "reauth_required" }), /Sign in again/);
		assert.match(html({ ...disconnected, state: "error", message: "Account access was revoked." }), /Account access was revoked/);
		assert.match(html(disconnected, "Could not connect. Try again."), /role="alert"/);
		assert.doesNotMatch(pending, /auth\.openai\.com|access_token|refresh_token|client_id|code_verifier/);
		assert.match(pending, /https:\/\/chatgpt.com\/settings\/usage/);
	});
	it("shows saved accounts in a native select and distinguishes reconnect from a new account", () => {
		const connected = html({ ...disconnected, state: "connected", authorized: true, activeAccountId: "one", accounts: [
			{ id: "one", label: "Personal", connected: true }, { id: "two", label: "Work", connected: false },
		] });
		assert.match(connected, /<select[^>]*aria-label="ChatGPT account"/);
		assert.match(connected, /Personal/);
		assert.match(connected, /Work \(sign-in required\)/);
		assert.match(connected, /Add account/);
		assert.match(connected, /Sign out/);
	});
	it("authorizes an OAuth-only provider and respects an explicit unauthorized mode over a stored key", () => {
		assert.equal(hasProviderAuthorization([], [], ["openai"]), true);
		assert.equal(hasProviderAuthorization([{ id: "OPENAI_API_KEY", info: null, present: true, masked: "masked", source: "file", shadowedByEnv: false }], [{ id: "openai", label: "OpenAI", envVar: "OPENAI_API_KEY" }], []), false);
		assert.equal(setupStage([{ id: "openai", keyPresent: false, authorized: true }]), "pickers");
		assert.equal(setupStage([{ id: "openai", keyPresent: true, authorized: false }]), "keys");
		const catalog = { slots: { strong: { model: { provider: "openai", id: "test" } } }, providers: [{ id: "openai", envVar: "OPENAI_API_KEY", keyPresent: false, authorized: true }] } as unknown as ModelCatalogResponse;
		assert.equal(strongKeyless(catalog), false);
		catalog.providers[0]!.authorized = false;
		catalog.providers[0]!.keyPresent = true;
		assert.equal(strongKeyless(catalog), true);
	});
	it("labels subscription models with the ChatGPT plan instead of an API price", () => {
		const markup = renderToStaticMarkup(<ModelMenuList effectiveId={undefined} onPick={() => {}} models={[{
			id: "gpt-fixture", name: "GPT fixture", provider: "openai", reasoning: true, input: ["text"], supportedLevels: ["low"],
			cost: { input: 10, output: 20, cacheRead: 0, cacheWrite: 0 }, contextWindow: 100000, maxTokens: 10000, billing: "subscription",
		}]} />);
		assert.match(markup, /ChatGPT plan/);
		assert.doesNotMatch(markup, /\$10|\$20/);
	});
});

const dom = parseHTML("<html><body></body></html>");
Object.assign(globalThis, {
	window: dom.window, document: dom.document, Element: dom.window.Element, HTMLElement: dom.window.HTMLElement,
	CustomEvent: dom.window.CustomEvent, IS_REACT_ACT_ENVIRONMENT: true,
});
const originalFetch = globalThis.fetch;
let root: Root | undefined;
let host: HTMLDivElement | undefined;
async function mount(children: React.ReactNode = <OpenAIAuthSection />, connect?: () => NotifySource) {
	host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
	await act(async () => { root!.render(connect ? <ServerEventsProvider connect={connect}><OpenAIAuthProvider>{children}</OpenAIAuthProvider></ServerEventsProvider> : <OpenAIAuthProvider>{children}</OpenAIAuthProvider>); });
}
async function click(testid: string) {
	const target = document.querySelector<HTMLElement>(`[data-testid="${testid}"]`);
	assert.ok(target, testid);
	await act(async () => { target.dispatchEvent(new dom.window.Event("click", { bubbles: true })); });
}
async function wait(milliseconds: number) {
	await act(async () => { await new Promise((resolve) => setTimeout(resolve, milliseconds)); });
}
afterEach(async () => {
	await act(async () => { root?.unmount(); }); root = undefined; host?.remove(); host = undefined; globalThis.fetch = originalFetch;
});

describe("OpenAI auth controller", () => {
	it("polls only during sign-in and notifies catalog readers when authorization changes", async () => {
		let reads = 0;
		const actions: unknown[] = [];
		let current = disconnected;
		globalThis.fetch = async (input, init) => {
			assert.equal(input, "/api/auth/openai");
			if (init?.method === "POST") {
				actions.push(JSON.parse(String(init.body)));
				current = { ...disconnected, state: "pending", loginPending: true };
				return Response.json(current);
			}
			reads++;
			if (current.loginPending) current = { ...disconnected, state: "connected", authorized: true, accounts: [{ id: "one", label: "Personal", connected: true }], activeAccountId: "one" };
			return Response.json(current);
		};
		let notifications = 0;
		const unsubscribe = onSettingsSaved((section) => { if (section === "keys") notifications++; });
		try {
			await mount(); await wait(1100); assert.equal(reads, 1, "idle auth has no timer");
			await click("openai-login"); assert.deepEqual(actions, [{ action: "login" }]);
			assert.match(host!.textContent!, /Waiting for sign-in/);
			await wait(1100); assert.match(host!.textContent!, /Connected/); assert.equal(reads, 2);
			await wait(1100); assert.equal(reads, 2, "polling stops after completion");
			assert.equal(notifications, 2, "pending and connected each refresh readers once");
		} finally { unsubscribe(); }
	});
	it("sends cancel and explicit mode actions without retrying through an API key", async () => {
		const actions: unknown[] = [];
		let current: OpenAIAuthStatus = { ...disconnected, state: "pending", loginPending: true, apiKeyPresent: true };
		globalThis.fetch = async (_input, init) => {
			if (init?.method === "POST") {
				const action = JSON.parse(String(init.body)); actions.push(action);
				current = { ...disconnected, apiKeyPresent: true, ...(action.action === "mode" ? { mode: action.mode } : {}) };
			}
			return Response.json(current);
		};
		await mount(); await click("openai-cancel"); await click("openai-mode-api_key");
		assert.deepEqual(actions, [{ action: "cancel" }, { action: "mode", mode: "api_key" }]);
		assert.match(host!.textContent!, /Using your OpenAI API key/);
	});
	it("selects saved accounts, reuses the selected profile for reconnect, and adds a separate account", async () => {
		const actions: unknown[] = [];
		let current: OpenAIAuthStatus = { ...disconnected, state: "connected", authorized: true, activeAccountId: "one", accounts: [
			{ id: "one", label: "Personal", connected: true }, { id: "two", label: "Work", connected: false },
		] };
		globalThis.fetch = async (_input, init) => {
			if (init?.method === "POST") {
				const action = JSON.parse(String(init.body)); actions.push(action);
				if (action.action === "select") current = { ...current, state: "reauth_required", authorized: false, activeAccountId: action.accountId };
				if (action.action === "login") {
					const id = action.accountId ?? "three";
					current = { ...current, activeAccountId: id, state: "connected", authorized: true, accounts: [...current.accounts.filter((account) => account.id !== id), { id, label: "Signed in", connected: true }] };
				}
				if (action.action === "logout") current = { ...current, state: "disconnected", authorized: false, accounts: current.accounts.map((account) => account.id === action.accountId ? { ...account, connected: false } : account) };
			}
			return Response.json(current);
		};
		await mount();
		const select = document.querySelector<HTMLSelectElement>('[data-testid="openai-account"]'); assert.ok(select);
		Object.defineProperty(select, "value", { configurable: true, value: "two" });
		await act(async () => { select.dispatchEvent(new dom.window.Event("change", { bubbles: true })); });
		await click("openai-login"); await click("openai-add-account"); await click("openai-logout");
		assert.deepEqual(actions, [{ action: "select", accountId: "two" }, { action: "login", accountId: "two" }, { action: "login" }, { action: "logout", accountId: "three" }]);
	});
	it("keeps the OAuth method selected when a request fails and offers retry", async () => {
		let writes = 0;
		globalThis.fetch = async (_input, init) => {
			if (init?.method === "POST") { writes++; return Response.json({ error: "System browser is unavailable. Try again." }, { status: 503 }); }
			return Response.json({ ...disconnected, apiKeyPresent: true });
		};
		await mount(); await click("openai-login");
		assert.equal(writes, 1);
		assert.equal(document.querySelector('[data-testid="openai-mode-oauth"]')?.getAttribute("aria-pressed"), "true");
		assert.match(host!.textContent!, /System browser is unavailable/);
		assert.ok(document.querySelector('[role="alert"]'));
	});
});

const connected: OpenAIAuthStatus = {
	...disconnected, state: "connected", authorized: true, activeAccountId: "one",
	accounts: [{ id: "one", label: "Personal", connected: true }],
};

describe("ChatGPT plan UX", () => {
	it("handles synchronous transport failure without a promise initialization error", async () => {
		globalThis.fetch = () => { throw new Error("Offline"); };
		await mount();
		assert.match(host!.textContent!, /Could not read the OpenAI connection/);
	});
	it("performs a fresh queued read after a mutation instead of reusing a stale in-flight GET", async () => {
		let reads = 0;
		let resolveOld!: (response: Response) => void;
		let resolveWrite!: (response: Response) => void;
		const old = new Promise<Response>((resolve) => { resolveOld = resolve; });
		const write = new Promise<Response>((resolve) => { resolveWrite = resolve; });
		const api: OpenAIAuthStatus = { ...connected, mode: "api_key", apiKeyPresent: true };
		globalThis.fetch = (_input, init) => {
			if (init?.method === "POST") return write;
			reads++;
			return reads === 2 ? old : Promise.resolve(Response.json(reads === 1 ? connected : api));
		};
		await mount();
		await act(async () => { notifySettingsSaved("keys"); });
		assert.equal(reads, 2);
		await click("openai-mode-api_key");
		await act(async () => { notifySettingsSaved("keys"); });
		await act(async () => { resolveWrite(Response.json(api)); });
		assert.equal(reads, 3, "the queued event fetches post-mutation truth");
		await act(async () => { resolveOld(Response.json(connected)); });
		assert.equal(document.querySelector('[data-testid="openai-mode-api_key"]')?.getAttribute("aria-pressed"), "true", "the older read cannot overwrite the chosen mode");
	});
	it("shares one status read and one welcome modal, and acknowledges once across reconnect and remount", async () => {
		let current = { ...connected, planWelcomeRequired: true };
		let reads = 0;
		const actions: unknown[] = [];
		globalThis.fetch = async (_input, init) => {
			if (init?.method === "POST") {
				assert.equal(init.signal, undefined, "acknowledging does not abort a running lesson");
				const action = JSON.parse(String(init.body)); actions.push(action);
				if (action.action === "acknowledge_plan") current = { ...current, planWelcomeRequired: false };
				if (action.action === "logout") current = { ...current, authorized: false, state: "disconnected", accounts: [{ id: "one", label: "Personal", connected: false }] };
				if (action.action === "login") current = { ...current, ...connected };
			} else reads++;
			return Response.json(current);
		};
		await mount(<><OpenAIAuthSection /><OpenAIAuthSection /><ChatGPTPlanIndicator provider="openai" /></>);
		assert.equal(reads, 1);
		assert.equal(document.querySelectorAll('[data-testid="chatgpt-plan-welcome"]').length, 1);
		assert.match(document.querySelector('[data-testid="chatgpt-plan-welcome"]')!.textContent!, /You're using your ChatGPT plan/);
		await click("chatgpt-plan-got-it");
		assert.equal(document.querySelector('[data-testid="chatgpt-plan-welcome"]'), null);
		await click("openai-logout"); await click("openai-login");
		assert.equal(document.querySelector('[data-testid="chatgpt-plan-welcome"]'), null, "returning account has no repeat welcome");
		await act(async () => { root!.unmount(); }); root = undefined; host!.remove();
		await mount();
		assert.equal(document.querySelector('[data-testid="chatgpt-plan-welcome"]'), null, "acknowledgement is read from the server after remount");
		assert.equal(actions.filter((action) => (action as { action: string }).action === "acknowledge_plan").length, 1);
	});
	it("lets Escape dismiss the first-sign-in message through the same persisted acknowledgement", async () => {
		let current = { ...connected, planWelcomeRequired: true };
		const actions: unknown[] = [];
		globalThis.fetch = async (_input, init) => {
			if (init?.method === "POST") { actions.push(JSON.parse(String(init.body))); current = { ...current, planWelcomeRequired: false }; }
			return Response.json(current);
		};
		await mount();
		await act(async () => {
			const event = new dom.window.Event("keydown", { bubbles: true, cancelable: true });
			Object.assign(event, { key: "Escape" }); document.dispatchEvent(event);
		});
		assert.deepEqual(actions, [{ action: "acknowledge_plan" }]);
		assert.equal(document.querySelector('[data-testid="chatgpt-plan-welcome"]'), null);
	});
	it("shows plan use before the first turn only for the chosen OpenAI model and updates on mode switches", async () => {
		let current = { ...connected, apiKeyPresent: true };
		let provider = "openai";
		globalThis.fetch = async (input, init) => {
			if (input === "/api/auth/openai") {
				if (init?.method === "POST") { const action = JSON.parse(String(init.body)); current = { ...current, mode: action.mode }; }
				return Response.json(current);
			}
			if (input === "/api/settings") return Response.json({ settings: { models: { strong: { model: { provider, id: "fixture" } } } } });
			assert.equal(input, "/api/models");
			return Response.json({ models: [], providers: [], slots: { strong: null, cheap: null, vision: null }, defaults: null, rolePins: {} });
		};
		await mount(<><OpenAIAuthSection /><StatsBar turns={[]} /></>);
		assert.equal(document.querySelector('[data-testid="stats-summary"]'), null, "this is the pre-chat view");
		assert.match(document.querySelector('[data-testid="chatgpt-plan-indicator"]')!.textContent!, /Using ChatGPT plan/);
		assert.equal(document.querySelector('[data-testid="chatgpt-plan-indicator"] a')?.getAttribute("href"), "https://chatgpt.com/settings/usage");
		await click("openai-mode-api_key");
		assert.equal(document.querySelector('[data-testid="chatgpt-plan-indicator"]'), null, "API-key mode never claims subscription usage");
		await click("openai-mode-oauth");
		assert.ok(document.querySelector('[data-testid="chatgpt-plan-indicator"]'));
		provider = "openrouter";
		await act(async () => { notifySettingsSaved("models"); });
		assert.equal(document.querySelector('[data-testid="chatgpt-plan-indicator"]'), null, "a different provider never claims ChatGPT plan usage");
	});
	it("makes Manage usage primary for limits and clears the gate only on an explicit retry", async () => {
		let current: OpenAIAuthStatus = { ...connected, usageLimit: "limit_reached" };
		const actions: unknown[] = [];
		globalThis.fetch = async (_input, init) => {
			if (init?.method === "POST") { actions.push(JSON.parse(String(init.body))); current = { ...connected }; }
			return Response.json(current);
		};
		await mount(<ChatGPTPlanIndicator provider="openai" />);
		const limit = document.querySelector('[data-testid="chatgpt-usage-limit"]'); assert.ok(limit);
		assert.match(limit.textContent!, /Usage limit reached/);
		const primary = limit.querySelector('a[data-testid="chatgpt-manage-usage"]'); assert.ok(primary);
		assert.match(primary.getAttribute("class")!, /bg-foreground/);
		assert.equal(primary.getAttribute("href"), "https://chatgpt.com/settings/usage");
		await act(async () => { window.dispatchEvent(new dom.window.Event("focus")); });
		assert.deepEqual(actions, [], "returning from Manage usage only refreshes status");
		assert.ok(document.querySelector('[data-testid="chatgpt-usage-limit"]'));
		await click("chatgpt-retry-usage");
		assert.deepEqual(actions, [{ action: "retry_usage" }]);
		assert.equal(document.querySelector('[data-testid="chatgpt-usage-limit"]'), null);
		assert.doesNotMatch(host!.textContent!, /Buy|API key|switch/i);
	});
	it("refreshes on coalesced server completion and channel reconnect without adding idle polls", async () => {
		let current: OpenAIAuthStatus = connected;
		let reads = 0;
		globalThis.fetch = async () => { reads++; return Response.json(current); };
		const listeners = new Map<string, (raw: string) => void>();
		let reopen = () => {};
		const connect = (): NotifySource => ({ close() {}, onOpen(callback) { reopen = callback; }, onEvent(name, callback) { listeners.set(name, callback); } });
		await mount(<><OpenAIAuthServerSync /><ChatGPTPlanIndicator provider="openai" /></>, connect);
		assert.equal(reads, 1);
		current = { ...connected, usageLimit: "unavailable" };
		await act(async () => { listeners.get("turn-settled")!('{"chatId":"fixture"}'); listeners.get("jobs-changed")!('{}'); });
		await wait(300);
		assert.equal(reads, 2, "related notifications share one status request");
		assert.match(host!.textContent!, /ChatGPT plan usage unavailable/);
		current = connected;
		await act(async () => { reopen(); });
		assert.equal(reads, 3);
		assert.equal(document.querySelector('[data-testid="chatgpt-usage-limit"]'), null);
	});
});
