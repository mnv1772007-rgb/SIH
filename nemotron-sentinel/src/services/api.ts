import { AnalysisResponse, ApiResult } from "@/types/threat-intel";
import { adaptThreatIntelResponse } from "@/services/adapter";
import { defaultMockThreatResponse } from "@/data/mockThreatData";

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL?.replace(/\/+$/, "") || "http://localhost:8000";

const REQUEST_TIMEOUT_MS = 9000;

/**
 * Checks if the backend server is reachable.
 */
export async function checkApiHealth(): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2500);

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
 * Automatically falls back to high-fidelity mock data if the API is unreachable,
 * times out, or returns a 500 error.
 */
export async function analyzeEmailFile(file: File): Promise<ApiResult<AnalysisResponse>> {
  const formData = new FormData();
  formData.append("file", file);
  formData.append("filename", file.name);

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    // Attempt primary endpoint
    let response = await fetch(`${API_BASE_URL}/api/analyze`, {
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

    clearTimeout(timeoutId);

    if (response && response.ok) {
      const rawJson = await response.json();
      const adapted = adaptThreatIntelResponse(rawJson, file.name);
      return {
        data: adapted,
        isDemoFallback: false,
        message: "Live telemetry analyzed via SheildMail API",
      };
    }

    const statusCode = response ? response.status : "CONNECTION_REFUSED";
    console.warn(
      `[SheildMail API] Backend responded with status: ${statusCode}. Engaging Demo Mode Fallback.`
    );

    // Resilient fallback with custom tailored filename and timestamp
    const fallbackData: AnalysisResponse = {
      ...defaultMockThreatResponse,
      filename: file.name,
      timestamp: new Date().toISOString(),
      scan_id: `SHIELD-${Math.random().toString(36).substring(2, 8).toUpperCase()}`,
    };

    return {
      data: fallbackData,
      isDemoFallback: true,
      error: `Backend unreachable at ${API_BASE_URL} (Status: ${statusCode})`,
      message: "API service offline. Displaying simulated threat forensics.",
    };
  } catch (err: any) {
    console.warn("[SheildMail API] Network/Upload error, switching to Demo Fallback:", err);

    const fallbackData: AnalysisResponse = {
      ...defaultMockThreatResponse,
      filename: file.name,
      timestamp: new Date().toISOString(),
      scan_id: `SHIELD-${Math.random().toString(36).substring(2, 8).toUpperCase()}`,
    };

    return {
      data: fallbackData,
      isDemoFallback: true,
      error: err?.message || "Network request failed",
      message: "API service offline. Displaying simulated threat forensics.",
    };
  }
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
