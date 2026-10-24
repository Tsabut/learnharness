import type { ButtonHTMLAttributes } from "react";

/** Unmodified official assets from OpenAI's approved sign-in button formats:
 * https://developers.openai.com/siwc/website */
export function ChatGPTLogo({ white = false }: { white?: boolean }) {
	// Official, locally bundled 21px vector; raster image optimization is unnecessary.
	// eslint-disable-next-line @next/next/no-img-element
	return <img src={`/branding/chatgpt-logo-${white ? "white" : "black"}.svg`} width={21} height={21} alt="" className={white ? "shrink-0" : "shrink-0 dark:invert"} />;
}

export function ContinueWithChatGPTButton(props: ButtonHTMLAttributes<HTMLButtonElement>) {
	return <button {...props} type="button" className="inline-flex min-h-10 items-center justify-center gap-2 rounded-md border border-white/20 bg-black px-4 py-2 font-sans text-sm font-medium text-white transition-opacity hover:opacity-85 disabled:cursor-not-allowed disabled:opacity-40">
		<ChatGPTLogo white />
		Continue with ChatGPT
	</button>;
}

export const CHATGPT_USAGE_URL = "https://chatgpt.com/settings/usage";

export function ManageChatGPTUsage({ primary = false }: { primary?: boolean }) {
	return <a href={CHATGPT_USAGE_URL} target="_blank" rel="noreferrer" data-testid="chatgpt-manage-usage"
		className={primary ? "inline-flex items-center justify-center rounded-sm border border-foreground bg-foreground px-2.5 py-1.5 text-xs font-medium text-background hover:opacity-85" : "text-xs text-foreground underline underline-offset-2 hover:text-muted-foreground"}>
		Manage usage
	</a>;
}
