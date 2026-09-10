"use client";

import { useMemo } from "react";
import { forceSimulation, forceLink, forceManyBody, forceCenter, forceCollide } from "d3-force-3d";
import { NetworkNode, NetworkLink } from "@/types/network-graph-3d";

interface SimulationResult {
  nodes: NetworkNode[];
  links: Array<{
    source: NetworkNode;
    target: NetworkNode;
    value?: number;
    label?: string;
    activeFlow?: boolean;
  }>;
}

/**
 * Computes sprawling, well-spaced 3D positions for nodes and links.
 * Avoids spheres and clumping by utilizing 3D force repulsion, collision boundaries,
 * and multi-layered Z-depth staggering.
 */
export function use3DForceSimulation(
  rawNodes: NetworkNode[],
  rawLinks: NetworkLink[]
): SimulationResult {
  return useMemo(() => {
    if (!rawNodes || rawNodes.length === 0) {
      return { nodes: [], links: [] };
    }

    // Deep clone nodes and assign initial staggered positions to avoid zero-division
    const nodes: NetworkNode[] = rawNodes.map((node, index) => {
      // Deterministic staggered spread
      const angle = (index / Math.max(1, rawNodes.length)) * Math.PI * 2;
      const radius = 60 + (index % 3) * 35;
      const layerZ = ((index % 4) - 1.5) * 50;

      return {
        ...node,
        x: node.x ?? Math.cos(angle) * radius,
        y: node.y ?? Math.sin(angle) * radius,
        z: node.z ?? layerZ,
      };
    });

    const nodeMap = new Map<string, NetworkNode>();
    nodes.forEach((n) => nodeMap.set(n.id, n));

    // Resolve links
    const linkList: any[] = [];
    rawLinks.forEach((l) => {
      const sourceId = typeof l.source === "object" ? l.source.id : l.source;
      const targetId = typeof l.target === "object" ? l.target.id : l.target;

      if (nodeMap.has(sourceId) && nodeMap.has(targetId)) {
        linkList.push({
          ...l,
          source: sourceId,
          target: targetId,
        });
      }
    });

    // Run 3D Force Simulation with strong repulsion and collision buffer
    const sim = forceSimulation(nodes, 3)
      .force(
        "charge",
        forceManyBody().strength(-450).distanceMax(500)
      )
      .force(
        "link",
        forceLink(linkList)
          .id((d: any) => d.id)
          .distance(120)
          .strength(0.5)
      )
      .force("collide", forceCollide().radius(32).iterations(3))
      .force("center", forceCenter(0, 0, 0))
      .stop();

    // Run 140 ticks to reach equilibrium
    for (let i = 0; i < 140; ++i) {
      sim.tick();
    }

    // Map resolved objects back to typed links
    const resolvedLinks = linkList.map((link) => ({
      source: typeof link.source === "object" ? link.source : nodeMap.get(link.source)!,
      target: typeof link.target === "object" ? link.target : nodeMap.get(link.target)!,
      value: link.value ?? 1,
      label: link.label ?? "",
      activeFlow: link.activeFlow ?? true,
    })).filter((l) => l.source && l.target);

    return {
      nodes,
      links: resolvedLinks,
    };
  }, [rawNodes, rawLinks]);
}
