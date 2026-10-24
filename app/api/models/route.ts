import { modelCatalog, openAIAuthService } from "@/src/server";

/**
 * The model picker's data (model-control wave): pi-ai's configured-provider
 * catalog as client-safe DTOs — id/name/cost/context/modality plus each
 * model's SUPPORTED thinking levels (per its thinkingLevelMap). Static
 * catalog: no network, stable within a pi-ai version.
 */
export async function GET() {
	try { await openAIAuthService().refreshModels(); } catch { /* OAuth status contains a safe recovery message; never substitute a static account list. */ }
	return Response.json(modelCatalog());
}
