#!/usr/bin/env python3
"""Smoke tests for SolGuard — no network required for the pure functions."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server import is_base58, KNOWN_PROGRAMS, KNOWN_SAFE_MINTS

def test_is_base58():
    assert is_base58("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
    assert not is_base58("not valid!")
    assert not is_base58("0OIl")  # ambiguous chars not in base58
    print("ok: is_base58")

def test_registry():
    assert "11111111111111111111111111111111" in KNOWN_PROGRAMS
    assert "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4" in KNOWN_PROGRAMS
    print("ok: program registry")

def test_known_mints():
    assert "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" in KNOWN_SAFE_MINTS
    print("ok: known mints")

if __name__ == "__main__":
    test_is_base58(); test_registry(); test_known_mints()
    print("ALL SMOKE TESTS PASSED")
