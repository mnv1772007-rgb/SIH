"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { NetworkGraphData, NetworkNode, NetworkLink } from "@/types/network-graph-3d";

interface UseNetworkGraphDataOptions {
  initialData?: NetworkGraphData;
  apiEndpoint?: string;
  websocketUrl?: string;
  pollIntervalMs?: number;
  onDataReceived?: (data: NetworkGraphData) => void;
}

interface UseNetworkGraphDataResult {
  data: NetworkGraphData;
  loading: boolean;
  error: string | null;
  isLive: boolean;
  refresh: () => Promise<void>;
  updateData: (updater: (prev: NetworkGraphData) => NetworkGraphData) => void;
}

/**
 * Standard default enterprise network architecture dataset.
 * Sprawling, multi-tier: Phishing Ingress -> DNS Spoofing -> C2 Hosting Server -> Geolocation
 */
export const defaultEnterpriseGraphData: NetworkGraphData = {
  nodes: [
    {
      id: "node-email-ingress",
      name: "SMTP Ingress Gateway",
      group: "email",
      status: "alert",
      metadata: {
        threatType: "Credential Harvesting Vector",
        riskScore: 94.5,
        protocol: "SMTP/TLSv1.3",
        packetsPerSec: 1420,
        description: "Anomalous inbound spear-phishing payload detected",
      },
    },
    {
      id: "node-spoofed-domain",
      name: "micros0ft.com",
      group: "domain",
      status: "critical",
      metadata: {
        domain: "micros0ft.com",
        threatType: "Typosquatting & Punycode Phish",
        riskScore: 96.0,
        asn: "AS12345 HostNet",
        description: "Zero-day lookalike domain spoofing Microsoft tenant credentials",
      },
    },
    {
      id: "node-c2-payload",
      name: "fake-login-update.com",
      group: "url",
      status: "critical",
      metadata: {
        domain: "fake-login-update.com",
        threatType: "Active C2 Credential Harvester",
        riskScore: 98.2,
        protocol: "HTTPS / Port 443",
        description: "Reverse proxy credential capture endpoint targeting SSO tokens",
      },
    },
    {
      id: "node-hosting-ip",
      name: "198.51.100.14",
      group: "ip",
      status: "alert",
      metadata: {
        ip: "198.51.100.14",
        asn: "AS12345 SuspiciousHost Autonomous",
        threatType: "Bulletproof Hosting Provider",
        riskScore: 89.0,
        packetsPerSec: 3840,
        description: "Known botnet command & control relay node",
      },
    },
    {
      id: "node-threat-geo",
      name: "RU (Novosibirsk / AS12345)",
      group: "geo",
      status: "alert",
      metadata: {
        country: "Russian Federation",
        region: "Siberian Federal District",
        coordinates: "55.0084, 82.9357",
        riskScore: 91.5,
        description: "Threat actor infrastructure origin cluster",
      },
    },
    {
      id: "node-secondary-dns",
      name: "DNS Resolvers (8.8.4.4 / FastFlux)",
      group: "dns",
      status: "cold",
      metadata: {
        protocol: "DoH / Port 853",
        threatType: "FastFlux DNS Rotation",
        riskScore: 68.0,
        description: "Rapidly mutating A-record resolution",
      },
    },
    {
      id: "node-client-endpoint",
      name: "Client Tenant (San Francisco HQ)",
      group: "client",
      status: "normal",
      metadata: {
        country: "United States",
        region: "California",
        riskScore: 12.0,
        description: "Protected enterprise workstation endpoint",
      },
    },
  ],
  links: [
    {
      source: "node-email-ingress",
      target: "node-spoofed-domain",
      label: "SPOOFS_SENDER",
      value: 3,
      activeFlow: true,
    },
    {
      source: "node-email-ingress",
      target: "node-c2-payload",
      label: "EMBEDS_HARVESTER_URL",
      value: 4,
      activeFlow: true,
    },
    {
      source: "node-spoofed-domain",
      target: "node-secondary-dns",
      label: "RESOLVES_VIA",
      value: 2,
      activeFlow: true,
    },
    {
      source: "node-secondary-dns",
      target: "node-hosting-ip",
      label: "ROUTES_TRAFFIC",
      value: 3,
      activeFlow: true,
    },
    {
      source: "node-c2-payload",
      target: "node-hosting-ip",
      label: "HOSTED_ON",
      value: 4,
      activeFlow: true,
    },
    {
      source: "node-hosting-ip",
      target: "node-threat-geo",
      label: "LOCATED_IN",
      value: 5,
      activeFlow: true,
    },
    {
      source: "node-email-ingress",
      target: "node-client-endpoint",
      label: "DELIVERED_TO",
      value: 1,
      activeFlow: false,
    },
  ],
};

/**
 * Enterprise Data-Fetching Hook
 * Manages REST API polling, WebSocket streaming, and graceful mock fallbacks.
 */
export function useNetworkGraphData({
  initialData,
  apiEndpoint,
  websocketUrl,
  pollIntervalMs = 0,
  onDataReceived,
}: UseNetworkGraphDataOptions = {}): UseNetworkGraphDataResult {
  const [data, setData] = useState<NetworkGraphData>(
    initialData || defaultEnterpriseGraphData
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isLive, setIsLive] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  // Sync if initialData changes externally (e.g. from file analysis)
  useEffect(() => {
    if (initialData && initialData.nodes && initialData.nodes.length > 0) {
      setData(initialData);
    }
  }, [initialData]);

  // REST API fetch
  const fetchGraphData = useCallback(async () => {
    if (!apiEndpoint) return;
    try {
      setLoading(true);
      setError(null);
      const res = await fetch(apiEndpoint, {
        headers: { Accept: "application/json" },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to fetch graph telemetry`);
      const json: NetworkGraphData = await res.json();
      if (json && Array.isArray(json.nodes) && Array.isArray(json.links)) {
        setData(json);
        setIsLive(true);
        if (onDataReceived) onDataReceived(json);
      }
    } catch (err: any) {
      console.warn("[NetworkGraph3D] REST fetch error, retaining current telemetry:", err);
      setError(err?.message || "Failed to load backend telemetry");
      setIsLive(false);
    } finally {
      setLoading(false);
    }
  }, [apiEndpoint, onDataReceived]);

  // WebSocket real-time subscription
  useEffect(() => {
    if (!websocketUrl) return;

    let isSubscribed = true;
    try {
      const ws = new WebSocket(websocketUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        if (isSubscribed) setIsLive(true);
      };

      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload && Array.isArray(payload.nodes) && Array.isArray(payload.links)) {
            if (isSubscribed) {
              setData(payload);
              if (onDataReceived) onDataReceived(payload);
            }
          }
        } catch (e) {
          console.error("[NetworkGraph3D] Failed to parse WebSocket packet:", e);
        }
      };

      ws.onerror = () => {
        if (isSubscribed) setIsLive(false);
      };

      ws.onclose = () => {
        if (isSubscribed) setIsLive(false);
      };

      return () => {
        isSubscribed = false;
        ws.close();
      };
    } catch (e) {
      console.warn("[NetworkGraph3D] WebSocket connection failed:", e);
    }
  }, [websocketUrl, onDataReceived]);

  // Polling interval
  useEffect(() => {
    if (pollIntervalMs > 0 && apiEndpoint) {
      fetchGraphData();
      const interval = setInterval(fetchGraphData, pollIntervalMs);
      return () => clearInterval(interval);
    }
  }, [pollIntervalMs, apiEndpoint, fetchGraphData]);

  return {
    data,
    loading,
    error,
    isLive,
    refresh: fetchGraphData,
    updateData: setData,
  };
}
