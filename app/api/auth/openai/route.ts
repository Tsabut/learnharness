import { openAIAuthService, parseOpenAIAuthAction, validOpenAIAuthRequest } from "@/src/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function response(value: unknown, status = 200) {
	return Response.json(value, { status, headers: { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" } });
}

export async function GET(request: Request) {
	const target = new URL(request.url);
	if (!["127.0.0.1", "localhost", "[::1]"].includes(target.hostname)) return response({ error: "OpenAI authentication is available only on the local desktop server." }, 403);
	return response(openAIAuthService().status());
}

export async function POST(request: Request) {
	if (!validOpenAIAuthRequest(request)) return response({ error: "OpenAI connection changes must come from this app." }, 403);
	if (Number(request.headers.get("content-length") ?? "0") > 4096) return response({ error: "Invalid connection request." }, 400);
	let action;
	try { const text = await request.text(); action = text.length <= 4096 ? parseOpenAIAuthAction(JSON.parse(text)) : undefined; } catch { /* rejected below */ }
	if (!action) return response({ error: "Invalid connection action." }, 400);
	try { return response(await openAIAuthService().act(action)); }
	catch {
		return response({ error: "The connection change could not be completed. Cancel any pending sign-in and check secure storage in the desktop app." }, 409);
	}
}
