"""Shared, deterministic dataset integrity helpers.

These operations are offline and work only on already-collected text.  They
avoid a quadratic all-pairs comparison by using four SimHash bands to generate
near-duplicate candidates.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from typing import Iterable


def normalise_for_fingerprint(value: str) -> str:
    value = re.sub(r"<[^>]+>", " ", value or "")
    value = re.sub(r"https?://\S+", " URL ", value, flags=re.IGNORECASE)
    value = re.sub(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", " EMAIL ", value)
    return " ".join(value.lower().split())


def simhash64(value: str) -> int:
    """Return a stable 64-bit SimHash over word unigrams and bigrams."""
    # Corpus messages can contain very long legal notices or quoted threads.
    # A bounded, de-duplicated feature set keeps this quality check linear and
    # reproducible without pretending it is a full semantic similarity model.
    tokens = re.findall(r"[a-z0-9_]{2,}", normalise_for_fingerprint(value))[:160]
    features = list(dict.fromkeys(tokens))[:80]
    features.extend(list(dict.fromkeys(f"{left} {right}" for left, right in zip(tokens, tokens[1:])) )[:80])
    if not features:
        return 0
    weights = [0] * 64
    for feature in features:
        digest = int.from_bytes(hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest(), "big")
        for bit in range(64):
            weights[bit] += 1 if digest & (1 << bit) else -1
    return sum((1 << bit) for bit, weight in enumerate(weights) if weight >= 0)


def hamming_distance(left: int, right: int) -> int:
    return (left ^ right).bit_count()


def near_duplicate_components(texts: Iterable[str], max_distance: int = 3) -> tuple[list[int], list[list[int]], int]:
    """Find connected near-duplicate components with banded SimHash candidates.

    Returns fingerprints, components containing two or more record indexes, and
    the number of candidate pairs compared.  A component is deliberately used
    for split grouping so a chain of close templates cannot leak across splits.
    """

    fingerprints = [simhash64(text) for text in texts]
    buckets: dict[tuple[int, int], list[int]] = defaultdict(list)
    for index, fingerprint in enumerate(fingerprints):
        for band in range(4):
            buckets[(band, (fingerprint >> (band * 16)) & 0xFFFF)].append(index)

    parent = list(range(len(fingerprints)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    checked: set[tuple[int, int]] = set()
    for members in buckets.values():
        for position, left in enumerate(members):
            for right in members[position + 1:]:
                pair = (left, right) if left < right else (right, left)
                if pair in checked:
                    continue
                checked.add(pair)
                if hamming_distance(fingerprints[left], fingerprints[right]) <= max_distance:
                    union(left, right)

    components_by_root: dict[int, list[int]] = defaultdict(list)
    for index in range(len(fingerprints)):
        components_by_root[find(index)].append(index)
    components = [members for members in components_by_root.values() if len(members) > 1]
    return fingerprints, components, len(checked)
