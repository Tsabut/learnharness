"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import type { OpenAIAuthAction, OpenAIAuthStatus } from "@/src/core";
import { notifySettingsSaved, useSettingsSaved } from "@/components/settings-signal";
import { useBackdropDismiss } from "@/components/backdrop-dismiss";
import { ChatGPTLogo, ManageChatGPTUsage } from "@/components/chatgpt-brand";

interface OpenAIAuthContextValue {
	status: OpenAIAuthStatus | null;
	busy: boolean;
	error: string | null;
	refresh: () => Promise<void>;
	act: (action: OpenAIAuthAction) => Promise<boolean>;
}
const OpenAIAuthContext = createContext<OpenAIAuthContextValue>({ status: null, busy: false, error: null, refresh: async () => {}, act: async () => false });
export function useOpenAIAuth() { return useContext(OpenAIAuthContext); }

function authorizationSnapshot(status: OpenAIAuthStatus): string {
	return JSON.stringify([status.mode, status.state, status.authorized, status.apiKeyPresent, status.activeAccountId, status.accounts]);
}

/** One connection read, transaction and pending-login poll per app window.
 * Ordinary idle state has no timer. Credentials and authorization URLs stay
 * on the server and desktop process. */
export function OpenAIAuthProvider({ children }: { children: ReactNode }) {
	const [status, setStatus] = useState<OpenAIAuthStatus | null>(null);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const current = useRef<OpenAIAuthStatus | null>(null);
	const mounted = useRef(false);
	const notifying = useRef(false);
	const mutating = useRef(false);
	const request = useRef(0);
	const inflight = useRef<Promise<void> | null>(null);
	const refreshAfterMutation = useRef(false);
	const apply = useCallback((next: OpenAIAuthStatus) => {
		const previous = current.current;
		current.current = next;
		setStatus(next);
		setError(null);
		if (previous && authorizationSnapshot(previous) !== authorizationSnapshot(next)) {
			notifying.current = true;
			try { notifySettingsSaved("keys"); } finally { notifying.current = false; }
		}
	}, []);
	const refresh = useCallback((): Promise<void> => {
		if (mutating.current) { refreshAfterMutation.current = true; return Promise.resolve(); }
		if (inflight.current) return inflight.current;
		const id = ++request.current;
		const read = async () => {
			try {
				const response = await fetch("/api/auth/openai", { cache: "no-store" });
				if (!response.ok) throw new Error("OpenAI connection unavailable");
				const next = await response.json() as OpenAIAuthStatus;
				if (mounted.current && id === request.current) apply(next);
			} catch {
				if (mounted.current && id === request.current) setError("Could not read the OpenAI connection. Try again.");
			}
		};
		const promise = read().finally(() => { if (inflight.current === promise) inflight.current = null; });
		inflight.current = promise;
		return promise;
	}, [apply]);
	useEffect(() => {
		mounted.current = true;
		void refresh();
		return () => { mounted.current = false; request.current++; inflight.current = null; };
	}, [refresh]);
	useSettingsSaved((section) => { if (section === "keys" && !notifying.current) void refresh(); });
	useEffect(() => {
		const focus = () => { if (current.current?.mode === "oauth") void refresh(); };
		window.addEventListener("focus", focus);
		return () => window.removeEventListener("focus", focus);
	}, [refresh]);
	useEffect(() => {
		if (!status?.loginPending) return;
		let stopped = false;
		let timer: ReturnType<typeof setTimeout>;
		const poll = async () => { await refresh(); if (!stopped) timer = setTimeout(poll, 1000); };
		timer = setTimeout(poll, 1000);
		return () => { stopped = true; clearTimeout(timer); };
	}, [status?.loginPending, refresh]);
	const act = useCallback(async (action: OpenAIAuthAction): Promise<boolean> => {
		if (mutating.current) return false;
		mutating.current = true;
		setBusy(true);
		setError(null);
		const id = ++request.current;
		inflight.current = null; // a pre-mutation read cannot satisfy the next refresh
		try {
			const response = await fetch("/api/auth/openai", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(action) });
			const body = await response.json() as OpenAIAuthStatus & { error?: string };
			if (!response.ok) throw new Error(body.error ?? "Could not update the OpenAI connection. Try again.");
			if (mounted.current && id === request.current) apply(body);
			return true;
		} catch (failure) {
			if (mounted.current && id === request.current) setError(failure instanceof Error ? failure.message : "Could not update the OpenAI connection. Try again.");
			return false;
		} finally {
			mutating.current = false;
			if (mounted.current) {
				setBusy(false);
				if (refreshAfterMutation.current) { refreshAfterMutation.current = false; void refresh(); }
			}
		}
	}, [apply, refresh]);
	const value = useMemo(() => ({ status, busy, error, refresh, act }), [status, busy, error, refresh, act]);
	return <OpenAIAuthContext.Provider value={value}>{children}<ChatGPTPlanWelcome /></OpenAIAuthContext.Provider>;
}

export function ChatGPTUsageLimit({ status, busy, onRetry }: { status: OpenAIAuthStatus; busy: boolean; onRetry: () => void }) {
	if (status.mode !== "oauth" || !status.usageLimit) return null;
	return <div className="flex min-w-0 flex-col gap-2 rounded-sm border border-border p-2 text-left text-xs" role="alert" data-testid="chatgpt-usage-limit">
		<div className="flex items-center gap-1.5 font-medium text-foreground"><ChatGPTLogo />{status.usageLimit === "limit_reached" ? "Usage limit reached" : "ChatGPT plan usage unavailable"}</div>
		<p className="text-muted-foreground">Review your ChatGPT plan or this app’s usage limit in ChatGPT settings, then try again.</p>
		<div className="flex flex-wrap items-center gap-3"><ManageChatGPTUsage primary /><button type="button" disabled={busy} onClick={onRetry} data-testid="chatgpt-retry-usage" className="text-xs text-muted-foreground underline underline-offset-2 hover:text-foreground disabled:opacity-40">Try again</button></div>
	</div>;
}

/** The chosen model, rather than the account connection alone, determines
 * whether the composer claims to use the ChatGPT plan. */
export function ChatGPTPlanIndicator({ provider }: { provider?: string }) {
	const { status, busy, act } = useOpenAIAuth();
	if (provider !== "openai" || status?.mode !== "oauth" || (!status.authorized && !status.usageLimit)) return null;
	return <div className="flex max-w-full flex-col items-end gap-1" data-testid="chatgpt-plan-indicator">
		{status.authorized && <div className="flex flex-wrap items-center justify-end gap-x-2 gap-y-1 text-[10px] text-muted-foreground"><ChatGPTLogo /><span>Using ChatGPT plan</span><ManageChatGPTUsage /></div>}
		<ChatGPTUsageLimit status={status} busy={busy} onRetry={() => void act({ action: "retry_usage" })} />
	</div>;
}

function ChatGPTPlanWelcome() {
	const { status, busy, error, act } = useOpenAIAuth();
	const open = status?.mode === "oauth" && status.authorized && status.planWelcomeRequired === true;
	const panel = useRef<HTMLDivElement>(null);
	const previousFocus = useRef<HTMLElement | null>(null);
	const acknowledge = useCallback(() => { if (!busy) void act({ action: "acknowledge_plan" }); }, [busy, act]);
	const acknowledgeRef = useRef(acknowledge);
	acknowledgeRef.current = acknowledge;
	const dismiss = useBackdropDismiss(acknowledge);
	useEffect(() => {
		if (!open) return;
		previousFocus.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
		panel.current?.querySelector<HTMLButtonElement>('[data-testid="chatgpt-plan-got-it"]')?.focus();
		const keydown = (event: KeyboardEvent) => {
			if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); acknowledgeRef.current(); }
			if (event.key === "Tab") {
				const focusable = [...(panel.current?.querySelectorAll<HTMLElement>('button:not([disabled]),a[href]') ?? [])];
				const first = focusable[0], last = focusable.at(-1);
				if (!focusable.includes(document.activeElement as HTMLElement)) { event.preventDefault(); first?.focus(); }
				else if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
				else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
			}
		};
		document.addEventListener("keydown", keydown, true);
		return () => { document.removeEventListener("keydown", keydown, true); previousFocus.current?.focus(); };
	}, [open]);
	if (!open) return null;
	return createPortal(<div className="fixed inset-0 z-[70] flex items-center justify-center bg-background/80 p-4" data-testid="chatgpt-plan-welcome-backdrop" {...dismiss}>
		<div ref={panel} role="dialog" aria-modal="true" aria-labelledby="chatgpt-plan-welcome-title" aria-describedby="chatgpt-plan-welcome-description" data-testid="chatgpt-plan-welcome" className="flex w-[420px] max-w-full flex-col gap-4 rounded-md border border-border bg-card p-6 shadow-xl">
			<div className="flex items-center justify-between"><ChatGPTLogo /><button type="button" disabled={busy} onClick={acknowledge} aria-label="Dismiss ChatGPT plan message" className="text-muted-foreground hover:text-foreground disabled:opacity-40">✕</button></div>
			<h2 id="chatgpt-plan-welcome-title" className="text-base font-semibold text-foreground">You're using your ChatGPT plan</h2>
			<p id="chatgpt-plan-welcome-description" className="text-sm text-muted-foreground">Eligible AI requests in LearnHarness use your ChatGPT plan or credits balance. Manage usage and limits in ChatGPT settings. API keys remain a separate, explicitly selected payment method.</p>
			<ManageChatGPTUsage />
			{error && <p role="alert" className="text-xs text-red-500">{error}</p>}
			<button type="button" disabled={busy} onClick={acknowledge} data-testid="chatgpt-plan-got-it" className="rounded-sm border border-foreground bg-foreground px-3 py-2 text-sm font-medium text-background hover:opacity-85 disabled:opacity-40">{busy ? "Saving…" : "Got it"}</button>
		</div>
	</div>, document.body);
}
