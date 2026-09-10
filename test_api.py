#!/usr/bin/env python3
"""
CLI Test Script for Role 4 API Endpoints
Runs standard assertion checks using FastAPI TestClient.
"""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest

if __name__ == "__main__":
    print("=" * 70)
    print("  RUNNING ROLE 4 AUTOMATED TEST SUITE (PYTEST)")
    print("=" * 70)
    exit_code = pytest.main([
        "-v",
        "--tb=short",
        str(Path(__file__).resolve().parent / "tests"),
    ])
    sys.exit(exit_code)
