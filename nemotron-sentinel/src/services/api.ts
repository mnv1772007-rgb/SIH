import { AnalysisResponse, ApiResult } from "@/types/threat-intel";
import { adaptThreatIntelResponse } from "@/services/adapter";
import { defaultMockThreatResponse } from "@/data/mockThreatData";

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/+$/, "") || "http://localhost:8000";

const REQUEST_TIMEOUT_MS = 60000; // 60s — allows time for OpenAI enrichment

/**
 * Checks if the backend server is reachable.
 */
export async function checkApiHealth(): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(`${API_BASE_URL}/health`, {
      method: "GET",
      signal: controller.signal,
    }).catch(() => null);

    clearTimeout(timeoutId);
    return Boolean(response && response.ok);
  } catch {
    return false;
  }
}

/**
 * Uploads a raw .eml or .msg file to the backend service via FormData.
 * Real analysis NEVER falls back to mock data. If the backend is unreachable,
 * times out, or returns an error, an explicit error is thrown.
 */
export async function analyzeEmailFile(file: File): Promise<ApiResult<AnalysisResponse>> {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("filename", file.name);

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  let response: Response | null = null;
  try {
    // Attempt primary endpoint (/api/analyze)
    response = await fetch(`${API_BASE_URL}/api/analyze`, {
      method: "POST",
      body: formData,
      signal: controller.signal,
    }).catch(async () => {
      // Fallback endpoint path attempt (/analyze)
      return await fetch(`${API_BASE_URL}/analyze`, {
        method: "POST",
        body: formData,
        signal: controller.signal,
      }).catch(() => null);
    });
  } catch (err: any) {
    clearTimeout(timeoutId);
    if (err.name === "AbortError") {
      throw new Error(`Analysis timed out after ${REQUEST_TIMEOUT_MS / 1000}s. The backend may be processing heavy enrichment.`);
    }
    throw new Error(`Network error connecting to backend at ${API_BASE_URL}: ${err.message || err}`);
  } finally {
    clearTimeout(timeoutId);
  }

  if (!response) {
    throw new Error(
      `Backend service unreachable at ${API_BASE_URL}. Ensure the FastAPI server is running on port 8000.`
    );
  }

  if (!response.ok) {
    let errorDetail = `HTTP ${response.status}`;
    try {
      const errJson = await response.json();
      if (errJson?.error?.message) {
        errorDetail = errJson.error.message;
      } else if (errJson?.detail) {
        errorDetail = typeof errJson.detail === "string" ? errJson.detail : JSON.stringify(errJson.detail);
      }
    } catch {
      // Ignore JSON parse failure on error body
    }
    throw new Error(`Analysis failed (${errorDetail}).`);
  }

  const rawJson = await response.json();
  if (!rawJson || typeof rawJson !== "object") {
    throw new Error("Invalid response format received from backend API.");
  }

  const adapted = adaptThreatIntelResponse(rawJson, file.name);
  return {
    data: adapted,
    isDemoFallback: false,
    message: "Live telemetry analyzed via SheildMail API",
  };
}

/**
 * Quick analysis simulator for instant testing with synthetic latency.
 */
export async function analyzeDemoSimulation(
  sampleName = "urgent_account_security_alert.eml"
): Promise<ApiResult<AnalysisResponse>> {
  await new Promise((resolve) => setTimeout(resolve, 1800));

  const demoData: AnalysisResponse = {
    ...defaultMockThreatResponse,
    filename: sampleName,
    timestamp: new Date().toISOString(),
    scan_id: `SHIELD-${Math.random().toString(36).substring(2, 8).toUpperCase()}`,
  };

  return {
    data: demoData,
    isDemoFallback: true,
    message: "Demo Mode active. Displaying simulated threat forensics.",
  };
}
