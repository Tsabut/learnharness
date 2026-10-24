"use client";

import type { ReactNode } from "react";
import type { OpenAIAuthAction, OpenAIAuthStatus } from "@/src/core";
import { useOpenAIAuth, ChatGPTUsageLimit } from "@/components/openai-auth";
import { ContinueWithChatGPTButton, ManageChatGPTUsage } from "@/components/chatgpt-brand";

const BUTTON = "rounded-sm border border-border bg-background px-2 py-1 font-ui text-xs text-foreground transition-colors hover:border-muted-foreground/50 disabled:cursor-not-allowed disabled:opacity-40";

/** Pure view shared by setup and settings. Browser authorization is opened
 * by the desktop process; URLs and credentials never enter this component. */
export function OpenAIAuthControls({
	status, busy, error, onAction, onRetry, apiKeyEditor,
}: {
	status: OpenAIAuthStatus | null;
	busy: boolean;
	error: string | null;
	onAction: (action: OpenAIAuthAction) => void;
	onRetry: () => void;
	apiKeyEditor?: ReactNode;
}) {
	const pending = status?.loginPending === true;
	const active = status?.accounts.find((account) => account.id === status.activeAccountId);
	const labels: Record<OpenAIAuthStatus["state"], string> = {
		disconnected: "Not connected",
		pending: "Waiting for sign-in in your browser…",
		connected: "Connected",
		reauth_required: "Sign in again to continue",
		error: "Connection error",
	};
	return (
		<div className="flex min-w-0 flex-col gap-2 py-1.5" data-testid="openai-auth">
			<div className="flex flex-wrap items-center justify-between gap-2">
				<span className="font-ui text-xs text-foreground">OpenAI</span>
				<span className="text-xs text-muted-foreground" role="status" data-testid="openai-auth-status">
					{status ? labels[status.state] : error ? "Connection unavailable" : "Loading connection…"}
				</span>
			</div>
			{status && (
				<>
					<div className="flex flex-wrap gap-1.5" role="group" aria-label="OpenAI sign-in method">
						{([ ["api_key", "API key"], ["oauth", "ChatGPT plan"] ] as const).map(([mode, label]) => (
							<button key={mode} type="button" className={BUTTON} aria-pressed={status.mode === mode}
								data-testid={`openai-mode-${mode}`} disabled={busy || pending}
								onClick={() => onAction({ action: "mode", mode })}>
								{label}{status.mode === mode && <span aria-hidden> ✓</span>}
							</button>
						))}
					</div>
					{status.mode === "api_key" ? (
						<>
							<p className="text-xs text-muted-foreground">{status.apiKeyPresent ? "Using your OpenAI API key." : "Add your OpenAI API key below."}</p>
							{apiKeyEditor}
							<p className="text-xs text-muted-foreground">You can also use your ChatGPT plan for eligible AI requests. OpenAI API key requests are billed separately.</p>
							<div><ContinueWithChatGPTButton data-testid="openai-login" disabled={busy || pending} onClick={() => onAction({ action: "login", ...(status.activeAccountId ? { accountId: status.activeAccountId } : {}) })} /></div>
						</>
					) : (
						<>
							{status.accounts.length > 0 && (
								<label className="flex min-w-0 flex-col gap-1 text-xs text-muted-foreground">
									Saved account
									<select aria-label="ChatGPT account" data-testid="openai-account" value={status.activeAccountId ?? ""}
										disabled={busy || pending} onChange={(event) => onAction({ action: "select", accountId: event.target.value })}
										className="h-8 w-full min-w-0 rounded-sm border border-border bg-background px-1.5 text-xs text-foreground">
										{!status.activeAccountId && <option value="" disabled>Choose an account…</option>}
										{status.accounts.map((account) => <option key={account.id} value={account.id}>{account.label}{account.connected ? "" : " (sign-in required)"}</option>)}
									</select>
								</label>
							)}
							<div className="flex flex-wrap gap-2">
								{pending ? (
									<button type="button" className={BUTTON} data-testid="openai-cancel" disabled={busy} onClick={() => onAction({ action: "cancel" })}>Cancel sign-in</button>
								) : (
									<>
										{(!active?.connected || !status.authorized) && <ContinueWithChatGPTButton data-testid="openai-login" disabled={busy}
											onClick={() => onAction({ action: "login", ...(status.activeAccountId ? { accountId: status.activeAccountId } : {}) })}>
										</ContinueWithChatGPTButton>}
										{status.accounts.length > 0 && <button type="button" className={BUTTON} data-testid="openai-add-account" disabled={busy} onClick={() => onAction({ action: "login" })}>Add account</button>}
										{active?.connected && <button type="button" className={BUTTON} data-testid="openai-logout" disabled={busy} onClick={() => onAction({ action: "logout", accountId: active.id })}>Sign out</button>}
									</>
									)}
							</div>
							<p className="text-xs text-muted-foreground">{pending ? "Complete sign-in in the system browser. This window will update automatically." : "Eligible requests use your ChatGPT plan or credits balance. OpenAI API key requests are billed separately and require selecting API key."}</p>
							<ManageChatGPTUsage />
							<ChatGPTUsageLimit status={status} busy={busy} onRetry={() => onAction({ action: "retry_usage" })} />
						</>
					)}
					{status.message && <p className="break-words text-xs text-muted-foreground" data-testid="openai-auth-message">{status.message}</p>}
				</>
			)}
			{error && <div className="flex flex-wrap items-center gap-2"><p role="alert" className="break-words text-xs text-red-500">{error}</p><button type="button" className={BUTTON} disabled={busy} onClick={onRetry}>Retry</button></div>}
		</div>
	);
}

export function OpenAIAuthSection({ apiKeyEditor }: { apiKeyEditor?: ReactNode }) {
	const { status, busy, error, act, refresh } = useOpenAIAuth();
	return <OpenAIAuthControls status={status} busy={busy} error={error} onAction={(action) => void act(action)} onRetry={() => void refresh()} apiKeyEditor={apiKeyEditor} />;
}
