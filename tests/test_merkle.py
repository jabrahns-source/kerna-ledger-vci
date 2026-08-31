#!/usr/bin/env python3
"""Deterministic Merkle tree tests for Kerna-Ledger VCI."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from merkle import MerkleTree  # noqa: E402


def test_empty_root() -> None:
    tree = MerkleTree()
    assert tree.get_root() == ""


def test_single_leaf_root_is_leaf_hash() -> None:
    tree = MerkleTree()
    tree.add_leaf("alpha")
    assert len(tree.leaves) == 1
    assert tree.get_root() == tree.leaves[0]


def test_odd_leaf_duplicates_last() -> None:
    a = MerkleTree()
    a.add_leaf("a")
    a.add_leaf("b")
    a.add_leaf("c")
    b = MerkleTree()
    b.add_leaf("a")
    b.add_leaf("b")
    b.add_leaf("c")
    assert a.get_root() == b.get_root()
    assert len(a.get_root()) == 64


def test_proof_roundtrip() -> None:
    tree = MerkleTree()
    leaves = ["pkt-0", "pkt-1", "pkt-2", "pkt-3"]
    for leaf in leaves:
        tree.add_leaf(leaf)
    root = tree.get_root()
    for i, leaf in enumerate(leaves):
        proof = tree.get_proof(i)
        assert tree.verify_proof(leaf, proof, root) is True
        assert tree.verify_proof(leaf + "-tamper", proof, root) is False


def test_invalid_index() -> None:
    tree = MerkleTree()
    tree.add_leaf("only")
    try:
        tree.get_proof(3)
        raise AssertionError("expected IndexError")
    except IndexError:
        pass
