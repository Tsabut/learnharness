import assert from "node:assert/strict";
import { test } from "node:test";
import { createModels, Type, type Api, type AssistantMessage, type Context, type Model, type ToolCall } from "@earendil-works/pi-ai";
import { openaiProvider } from "@earendil-works/pi-ai/providers/openai";
import { normalizeOpenAIPlanRequest } from "../src/server/openai-plan-request.ts";

test("plan request normalization removes unsupported HTTP fields after caller overrides without changing its input", () => {
	const original = {
		model: "legacy-model", store: true, stream: false, background: true, conversation: "c", max_output_tokens: 100,
		max_tool_calls: 4, metadata: { example: "x" }, moderation: {}, multi_agent: {}, prompt: {}, prompt_cache_retention: "24h",
		safety_identifier: "identifier", temperature: 1, top_logprobs: 5, top_p: 0.9, truncation: "auto", user: "u", previous_response_id: "previous",
		input: [{ type: "message", role: "system", content: "Teach carefully" }, { role: "user", content: "Hello" }],
	};
	const normalized = normalizeOpenAIPlanRequest(original);
	assert.deepEqual(normalized, { model: "legacy-model", store: false, stream: true, input: [{ type: "message", role: "developer", content: "Teach carefully" }, { role: "user", content: "Hello" }] });
	assert.equal(original.input[0]!.role, "system");
	assert.equal(original.store, true);
	assert.equal(original.previous_response_id, "previous");
});

test("flat function/custom tools become additional_tools without namespacing names or rewriting call history", () => {
	const tools = [{ type: "function", name: "teach", parameters: { type: "object" } }, { type: "custom", name: "draw", format: { type: "text" } }];
	const history = [{ type: "function_call", call_id: "call_one", name: "teach", arguments: "{}" }, { type: "function_call_output", call_id: "call_one", output: "done" }];
	const normalized = normalizeOpenAIPlanRequest({ input: history, tools, tool_choice: { type: "function", name: "teach" } });
	assert.deepEqual(normalized.input, [{ type: "additional_tools", role: "developer", tools }, ...history]);
	assert.deepEqual(normalized.tool_choice, { type: "function", name: "teach" });
	assert.equal(normalized.tools, undefined);
	assert.equal(tools[0]!.name, "teach");
});

test("existing modern declarations and supported namespaced tools remain intact; unsupported hosted tools fail locally", () => {
	const namespace = { type: "namespace", name: "lesson", tools: [{ type: "function", name: "teach", parameters: {} }] };
	const modern = { input: [{ type: "additional_tools", role: "developer", tools: [{ type: "function", name: "learn", parameters: {} }] }, { role: "developer", content: "Teach" }], tools: [namespace], stream: true, store: false };
	assert.deepEqual(normalizeOpenAIPlanRequest(modern), modern);
	for (const type of ["image_generation", "file_search", "code_interpreter", "computer_use", "mcp", "tool_search", "programmatic_tool_calling"]) {
		assert.throws(() => normalizeOpenAIPlanRequest({ input: [], tools: [{ type }] }), /unavailable with the ChatGPT plan/);
	}
	assert.throws(() => normalizeOpenAIPlanRequest({ input: [{ type: "tool_search_call" }] }), /tool_search history/);
	assert.throws(() => normalizeOpenAIPlanRequest({ input: "string shorthand" }), /array of input/);
});

function toolResponse(): Response {
	const item = { type: "function_call", id: "fc_review_one", call_id: "call_review_one", name: "review_tool", arguments: '{"value":"ok"}', status: "completed" };
	const events = [
		{ type: "response.created", response: { id: "resp_review", status: "in_progress", output: [] } },
		{ type: "response.output_item.added", output_index: 0, item: { ...item, arguments: "", status: "in_progress" } },
		{ type: "response.function_call_arguments.delta", output_index: 0, item_id: item.id, delta: item.arguments },
		{ type: "response.function_call_arguments.done", output_index: 0, item_id: item.id, arguments: item.arguments },
		{ type: "response.output_item.done", output_index: 0, item },
		{ type: "response.completed", response: { id: "resp_review", status: "completed", output: [item], usage: { input_tokens: 5, output_tokens: 4, total_tokens: 9 } } },
	];
	return new Response(events.map((event) => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`).join("") + "data: [DONE]\n\n", { headers: { "content-type": "text/event-stream" } });
}

async function capturedRequest(model: Model<Api>, context: Context) {
	const collection = createModels(); collection.setProvider(openaiProvider());
	let payload: Record<string, unknown> | undefined;
	const result = await collection.streamSimple(model, context, {
		apiKey: "mock-oauth-bearer", maxRetries: 0,
		onPayload: (value) => normalizeOpenAIPlanRequest(value),
		fetch: async (_input, init) => { payload = JSON.parse(String(init?.body)); return toolResponse(); },
	}).result();
	assert.ok(payload, "the actual installed provider reached the mocked HTTP transport");
	return { payload, result };
}

test("actual legacy gpt-4o and modern gpt-6.1-sol adapters produce permitted plan payloads and executable tool calls", async () => {
	const provider = openaiProvider();
	const tool = { name: "review_tool", description: "Review mock only", parameters: Type.Object({ value: Type.String() }) };
	const context: Context = { systemPrompt: "Teach with the local tool.", messages: [{ role: "user", content: "Use the tool", timestamp: Date.now() }], tools: [tool] };
	for (const id of ["gpt-4o", "gpt-6.1-sol"]) {
		const model = provider.getModels().find((item) => item.id === id);
		assert.ok(model, `${id} must be in the locked engine catalog`);
		const { payload, result } = await capturedRequest(model, context);
		assert.equal(payload.store, false);
		assert.equal(payload.stream, true);
		assert.equal(payload.tools, undefined, "function definitions use the route's additional_tools input");
		const input = payload.input as Record<string, unknown>[];
		assert.ok(input.every((item) => item.role !== "system"));
		assert.ok(input.some((item) => item.role === "developer" && item.content === context.systemPrompt));
		const declared = input.find((item) => item.type === "additional_tools")!.tools as Record<string, unknown>[];
		assert.equal(declared[0]!.name, tool.name);
		assert.equal(result.stopReason, "toolUse");
		const call = result.content.find((item): item is ToolCall => item.type === "toolCall");
		assert.ok(call);
		assert.equal(call.name, tool.name, "the local agent can still resolve the exact registered tool name");
		assert.deepEqual(call.arguments, { value: "ok" });
		const executors = { review_tool: (args: Record<string, unknown>) => `executed:${args.value}` };
		assert.equal(executors[call.name as keyof typeof executors](call.arguments), "executed:ok");
		const followup: Context = { ...context, messages: [...context.messages, result as AssistantMessage, { role: "toolResult", toolCallId: call.id, toolName: call.name, content: [{ type: "text", text: "executed:ok" }], isError: false, timestamp: Date.now() }] };
		const next = await capturedRequest(model, followup);
		const output = (next.payload.input as Record<string, unknown>[]).find((item) => item.type === "function_call_output");
		assert.equal(output!.call_id, "call_review_one", "tool-result history keeps the server call ID after normalization");
	}
});
