"use client";

import { useEffect, useRef } from "react";
import { useServerEvent, useServerResync } from "@/components/server-events";
import { useOpenAIAuth } from "@/components/openai-auth";

/** Refresh connection and usage-limit state after server work, including
 * background jobs with no attached chat. The shared SSE channel is reused. */
export function OpenAIAuthServerSync() {
	const { status, refresh } = useOpenAIAuth();
	const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
	const enabled = status?.mode === "oauth";
	const changed = () => {
		if (!enabled) return;
		if (timer.current) clearTimeout(timer.current);
		timer.current = setTimeout(() => { timer.current = null; void refresh(); }, 250);
	};
	useServerEvent("turn-settled", changed);
	useServerEvent("jobs-changed", changed);
	useServerEvent("activity-changed", changed);
	useServerResync(() => { if (enabled) void refresh(); });
	useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);
	return null;
}
