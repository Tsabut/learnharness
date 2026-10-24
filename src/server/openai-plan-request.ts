/** Public Responses HTTP constraints for ChatGPT plan usage.
 * Run after the caller's onPayload transform. API-key requests do not use this seam.
 * https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations
 */
const UNSUPPORTED_FIELDS = [
	"background", "conversation", "max_output_tokens", "max_tool_calls", "metadata", "moderation", "multi_agent",
	"prompt", "prompt_cache_retention", "safety_identifier", "temperature", "top_logprobs", "top_p", "truncation", "user",
	"previous_response_id",
] as const;
const UNSUPPORTED_TOOLS = new Set([
	"image_generation", "file_search", "code_interpreter", "computer", "computer_use", "computer_use_preview",
	"mcp", "tool_search", "programmatic_tool_calling",
]);

function object(value: unknown): value is Record<string, unknown> {
	return !!value && typeof value === "object" && !Array.isArray(value);
}

function validateTools(value: unknown): asserts value is Record<string, unknown>[] {
	if (!Array.isArray(value)) throw new Error("ChatGPT plan tool definitions must be an array.");
	for (const tool of value) {
		if (!object(tool) || typeof tool.type !== "string") throw new Error("ChatGPT plan tool definitions are invalid.");
		if (UNSUPPORTED_TOOLS.has(tool.type)) throw new Error("This hosted Responses tool is unavailable with the ChatGPT plan. Use locally executed function or custom tools.");
		if (tool.type === "namespace") validateTools(tool.tools);
	}
}

/** Use additional_tools declarations rather than introducing a namespace: existing tool names
 * and function_call_output call IDs then remain directly callable by the agent engine.
 */
export function normalizeOpenAIPlanRequest(value: unknown): Record<string, unknown> {
	if (!object(value) || !Array.isArray(value.input)) throw new Error("ChatGPT plan requests require an array of input messages.");
	const result: Record<string, unknown> = { ...value, store: false, stream: true };
	for (const field of UNSUPPORTED_FIELDS) delete result[field];
	const input: unknown[] = value.input.map((item: unknown) => {
		if (!object(item)) return item;
		if (item.type === "tool_search_call" || item.type === "tool_search_output") throw new Error("Responses tool_search history is unavailable with the ChatGPT plan. Use locally executed function tools.");
		if (item.type === "additional_tools") validateTools(item.tools);
		return item.role === "system" ? { ...item, role: "developer" } : item;
	});
	if (value.tools !== undefined) {
		validateTools(value.tools);
		const flat = value.tools.filter((tool) => tool.type === "function" || tool.type === "custom");
		const remaining = value.tools.filter((tool) => tool.type !== "function" && tool.type !== "custom");
		if (flat.length) input.unshift({ type: "additional_tools", role: "developer", tools: flat });
		if (remaining.length) result.tools = remaining;
		else delete result.tools;
	}
	result.input = input;
	return result;
}
