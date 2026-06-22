#!/usr/bin/env python3
"""
Production Merkle Tree with real sibling path proofs.
"""

import hashlib
from typing import List, Tuple

class MerkleTree:
    def __init__(self):
        self.leaves: List[str] = []
        self.tree: List[List[str]] = []

    def _hash(self, data: str) -> str:
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def add_leaf(self, data: str):
        leaf_hash = self._hash(data)
        self.leaves.append(leaf_hash)
        self._rebuild_tree()

    def _rebuild_tree(self):
        if not self.leaves:
            self.tree = []
            return
        level = self.leaves[:]
        self.tree = [level]
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                combined = self._hash(left + right)
                next_level.append(combined)
            level = next_level
            self.tree.append(level)

    def get_root(self) -> str:
        if not self.tree:
            return ""
        return self.tree[-1][0]

    def get_proof(self, index: int) -> List[Tuple[str, str]]:
        if index < 0 or index >= len(self.leaves):
            raise IndexError("Invalid leaf index")
        proof = []
        current_index = index
        for level in self.tree[:-1]:
            sibling_index = current_index ^ 1
            if sibling_index < len(level):
                direction = "left" if current_index % 2 == 1 else "right"
                proof.append((level[sibling_index], direction))
            current_index //= 2
        return proof

    def verify_proof(self, leaf_data: str, proof: List[Tuple[str, str]], root: str) -> bool:
        current = self._hash(leaf_data)
        for sibling, direction in proof:
            if direction == "left":
                current = self._hash(sibling + current)
            else:
                current = self._hash(current + sibling)
        return current == root