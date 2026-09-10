"use client";

import { useState, useEffect, useRef, RefObject } from "react";

interface Dimensions {
  width: number;
  height: number;
}

export function useResizeObserver<T extends HTMLElement>(
  targetRef: RefObject<T | null>,
  defaultDimensions: Dimensions = { width: 400, height: 400 }
): Dimensions {
  const [dimensions, setDimensions] = useState<Dimensions>(defaultDimensions);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    const element = targetRef.current;
    if (!element) return;

    const handleResize = (entries: ResizeObserverEntry[]) => {
      if (!entries || entries.length === 0) return;
      const entry = entries[0];

      if (rafRef.current) {
        cancelAnimationFrame(rafRef.current);
      }

      rafRef.current = requestAnimationFrame(() => {
        let width = 0;
        let height = 0;

        if (entry.contentBoxSize) {
          const contentBoxSize = Array.isArray(entry.contentBoxSize)
            ? entry.contentBoxSize[0]
            : entry.contentBoxSize;
          width = contentBoxSize.inlineSize;
          height = contentBoxSize.blockSize;
        } else if (entry.contentRect) {
          width = entry.contentRect.width;
          height = entry.contentRect.height;
        }

        if (width === 0 || height === 0) {
          width = element.clientWidth;
          height = element.clientHeight;
        }

        if (width > 50 && height > 50) {
          setDimensions({
            width: Math.floor(width),
            height: Math.floor(height),
          });
        }
      });
    };

    const observer = new ResizeObserver(handleResize);
    observer.observe(element);

    // Initial check
    if (element.clientWidth > 0 && element.clientHeight > 0) {
      setDimensions({
        width: element.clientWidth,
        height: element.clientHeight,
      });
    }

    return () => {
      observer.disconnect();
      if (rafRef.current) {
        cancelAnimationFrame(rafRef.current);
      }
    };
  }, [targetRef]);

  return dimensions;
}
