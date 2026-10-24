/** Client-safe OpenAI connection state. No token, authorization URL or client registration leaves the server. */
export type OpenAIAuthMode = "api_key" | "oauth";
export type OpenAIConnectionState = "disconnected" | "pending" | "connected" | "reauth_required" | "error";

export interface OpenAIAuthStatus {
	provider: "openai";
	mode: OpenAIAuthMode;
	state: OpenAIConnectionState;
	authorized: boolean;
	apiKeyPresent: boolean;
	accounts: Array<{ id: string; label: string; connected: boolean }>;
	activeAccountId?: string;
	message?: string;
	loginPending: boolean;
	/** Acknowledged once per saved registration, without storing identity in the browser. */
	planWelcomeRequired?: boolean;
	/** Credentials remain valid; fresh inference pauses until an explicit retry. */
	usageLimit?: "limit_reached" | "unavailable";
}

export type OpenAIAuthAction =
	| { action: "login"; accountId?: string }
	| { action: "select"; accountId: string }
	| { action: "mode"; mode: OpenAIAuthMode }
	| { action: "cancel" }
	| { action: "acknowledge_plan" }
	| { action: "retry_usage" }
	| { action: "logout"; accountId?: string };
