"""Tests for OpenMycelium – Logic Skeleton Immune System.

Covers sealing, verification, chain integrity, and tamper detection.
"""

import json
import hashlib
import tempfile
import os
from pathlib import Path

import pytest

from src.seal import Ed25519Keypair, seal_node, canonicalize
from src.verify import (
    Ed25519PublicKey,
    verify_node_signature,
    verify_chain,
    verify_chain_complete,
    verify_timestamp,
)


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def tmp_keys(tmp_path):
    """Generate a temporary keypair and return paths + password."""
    password = "test_password_123"
    keypair = Ed25519Keypair.generate()

    priv_path = str(tmp_path / "private.key")
    pub_path = str(tmp_path / "public.key")

    keypair.save_private(priv_path, password)
    keypair.save_public(pub_path)

    return {
        "private_path": priv_path,
        "public_path": pub_path,
        "password": password,
        "keypair": keypair,
    }


@pytest.fixture
def genesis_node(tmp_keys):
    """Create a genesis node."""
    return seal_node(
        content={"step": "genesis", "data": "initial state"},
        parent_hash="genesis",
        private_key_path=tmp_keys["private_path"],
        private_key_password=tmp_keys["password"],
    )


@pytest.fixture
def three_node_chain(tmp_keys):
    """Create a chain of 3 nodes."""
    nodes = []

    # Genesis
    node = seal_node(
        content={"step": "genesis", "data": "start"},
        parent_hash="genesis",
        private_key_path=tmp_keys["private_path"],
        private_key_password=tmp_keys["password"],
    )
    nodes.append(node)

    # Step 1
    node = seal_node(
        content={"step": "analysis", "data": "findings"},
        parent_hash=nodes[-1]["hash"],
        private_key_path=tmp_keys["private_path"],
        private_key_password=tmp_keys["password"],
    )
    nodes.append(node)

    # Step 2
    node = seal_node(
        content={"step": "conclusion", "data": "result"},
        parent_hash=nodes[-1]["hash"],
        private_key_path=tmp_keys["private_path"],
        private_key_password=tmp_keys["password"],
    )
    nodes.append(node)

    return nodes


# ── Canonicalization ──────────────────────────────────────────────────


class TestCanonicalize:

    def test_deterministic_output(self):
        """Same data, different insertion order → identical canonical form."""
        a = {"z": 1, "a": 2, "m": 3}
        b = {"a": 2, "m": 3, "z": 1}
        assert canonicalize(a) == canonicalize(b)

    def test_no_whitespace(self):
        """Canonical JSON uses compact separators."""
        result = canonicalize({"key": "value"})
        assert b" " not in result

    def test_unicode_preserved(self):
        """Non-ASCII characters are preserved, not escaped."""
        result = canonicalize({"emoji": "🧬", "text": "Ünïcödé"})
        assert "🧬".encode("utf-8") in result

    def test_nested_sorting(self):
        """Nested dicts are also sorted by key."""
        data = {"b": {"z": 1, "a": 2}, "a": 1}
        result = json.loads(canonicalize(data))
        keys = list(result.keys())
        assert keys == ["a", "b"]


# ── Key Management ────────────────────────────────────────────────────


class TestKeypair:

    def test_generate_keypair(self):
        """Can generate a fresh keypair."""
        kp = Ed25519Keypair.generate()
        assert kp.private_key is not None
        assert kp.public_key is not None

    def test_save_and_load_with_password(self, tmp_path):
        """Round-trip: generate → save (encrypted) → load."""
        kp = Ed25519Keypair.generate()
        priv_path = str(tmp_path / "priv.key")
        password = "s3cret"

        kp.save_private(priv_path, password)
        loaded = Ed25519Keypair.load_private(priv_path, password)

        # Verify loaded key can sign and original can verify
        msg = b"test message"
        sig = loaded.private_key.sign(msg)
        kp.public_key.verify(sig, msg)  # no exception = success

    def test_save_and_load_without_password(self, tmp_path):
        """Round-trip without encryption."""
        kp = Ed25519Keypair.generate()
        priv_path = str(tmp_path / "priv.key")

        kp.save_private(priv_path)
        loaded = Ed25519Keypair.load_private(priv_path)

        msg = b"test"
        sig = loaded.private_key.sign(msg)
        kp.public_key.verify(sig, msg)

    def test_load_via_env_variable(self, tmp_path):
        """Password can be read from OPENMYELIUM_KEY_PASSWORD env var."""
        kp = Ed25519Keypair.generate()
        priv_path = str(tmp_path / "priv.key")
        password = "env_password"

        kp.save_private(priv_path, password)

        os.environ["OPENMYELIUM_KEY_PASSWORD"] = password
        try:
            loaded = Ed25519Keypair.load_private(priv_path)  # no password arg
            msg = b"env test"
            sig = loaded.private_key.sign(msg)
            kp.public_key.verify(sig, msg)
        finally:
            del os.environ["OPENMYELIUM_KEY_PASSWORD"]

    def test_public_key_save_load(self, tmp_keys):
        """Public key can be saved and loaded independently."""
        pub_key = Ed25519PublicKey.load(tmp_keys["public_path"])
        assert pub_key.public_key is not None


# ── Sealing ───────────────────────────────────────────────────────────


class TestSealNode:

    def test_genesis_node_structure(self, genesis_node):
        """Genesis node has all required fields."""
        required = {"content", "parent_hash", "timestamp", "hash", "signature"}
        assert required.issubset(genesis_node.keys())

    def test_genesis_parent_hash(self, genesis_node):
        """Genesis node has 'genesis' as parent hash."""
        assert genesis_node["parent_hash"] == "genesis"

    def test_hash_is_valid_sha256(self, genesis_node):
        """Hash field is a valid 64-char hex string (SHA-256)."""
        assert len(genesis_node["hash"]) == 64
        int(genesis_node["hash"], 16)  # should not raise

    def test_hash_matches_content(self, genesis_node):
        """Recalculating the hash from content matches the stored hash."""
        node_data = {k: v for k, v in genesis_node.items() if k not in ("hash", "signature")}
        expected_hash = hashlib.sha256(canonicalize(node_data)).hexdigest()
        assert genesis_node["hash"] == expected_hash

    def test_timestamp_format(self, genesis_node):
        """Timestamp is ISO 8601 UTC format."""
        ts = genesis_node["timestamp"]
        assert ts.endswith("Z")
        assert "T" in ts

    def test_different_content_different_hash(self, tmp_keys):
        """Two nodes with different content produce different hashes."""
        node_a = seal_node(
            content={"data": "alpha"},
            parent_hash="genesis",
            private_key_path=tmp_keys["private_path"],
            private_key_password=tmp_keys["password"],
        )
        node_b = seal_node(
            content={"data": "beta"},
            parent_hash="genesis",
            private_key_path=tmp_keys["private_path"],
            private_key_password=tmp_keys["password"],
        )
        assert node_a["hash"] != node_b["hash"]


# ── Verification ──────────────────────────────────────────────────────


class TestVerifyNode:

    def test_valid_node_passes(self, genesis_node, tmp_keys):
        """A freshly sealed node passes signature verification."""
        pub = Ed25519PublicKey.load(tmp_keys["public_path"])
        is_valid, msg = verify_node_signature(genesis_node, pub.public_key)
        assert is_valid, msg

    def test_tampered_content_fails(self, genesis_node, tmp_keys):
        """Modifying the content breaks verification."""
        tampered = genesis_node.copy()
        tampered["content"] = {"step": "HACKED", "data": "evil"}
        pub = Ed25519PublicKey.load(tmp_keys["public_path"])
        is_valid, msg = verify_node_signature(tampered, pub.public_key)
        assert not is_valid
        assert "tampered" in msg.lower() or "mismatch" in msg.lower()

    def test_tampered_hash_fails(self, genesis_node, tmp_keys):
        """Changing the hash field directly breaks signature verification."""
        tampered = genesis_node.copy()
        tampered["hash"] = "a" * 64
        pub = Ed25519PublicKey.load(tmp_keys["public_path"])
        is_valid, msg = verify_node_signature(tampered, pub.public_key)
        assert not is_valid

    def test_wrong_key_fails(self, genesis_node):
        """Verification with a different keypair's public key fails."""
        wrong_kp = Ed25519Keypair.generate()
        is_valid, msg = verify_node_signature(genesis_node, wrong_kp.public_key)
        assert not is_valid
        assert "invalid" in msg.lower()


# ── Chain Verification ────────────────────────────────────────────────


class TestVerifyChain:

    def test_valid_chain(self, three_node_chain, tmp_keys):
        """A properly constructed chain passes verification."""
        pub = Ed25519PublicKey.load(tmp_keys["public_path"])
        is_valid, msg = verify_chain(three_node_chain, pub)
        assert is_valid, msg

    def test_empty_chain_fails(self, tmp_keys):
        """An empty chain is rejected."""
        pub = Ed25519PublicKey.load(tmp_keys["public_path"])
        is_valid, msg = verify_chain([], pub)
        assert not is_valid

    def test_broken_link_fails(self, three_node_chain, tmp_keys):
        """Swapping nodes breaks chain continuity."""
        broken = [three_node_chain[0], three_node_chain[2], three_node_chain[1]]
        pub = Ed25519PublicKey.load(tmp_keys["public_path"])
        is_valid, msg = verify_chain(broken, pub)
        assert not is_valid
        assert "chain break" in msg.lower() or "parent_hash" in msg.lower()

    def test_removed_node_fails(self, three_node_chain, tmp_keys):
        """Removing a middle node breaks the chain."""
        missing_middle = [three_node_chain[0], three_node_chain[2]]
        pub = Ed25519PublicKey.load(tmp_keys["public_path"])
        is_valid, msg = verify_chain(missing_middle, pub)
        assert not is_valid

    def test_complete_verification(self, three_node_chain, tmp_keys):
        """verify_chain_complete covers both integrity and timestamps."""
        pub = Ed25519PublicKey.load(tmp_keys["public_path"])
        is_valid, messages = verify_chain_complete(three_node_chain, pub)
        assert is_valid
        assert len(messages) == 4  # 1 chain msg + 3 timestamp msgs


# ── Timestamp Verification ────────────────────────────────────────────


class TestVerifyTimestamp:

    def test_valid_timestamp(self, genesis_node):
        """A freshly sealed node has a valid, recent timestamp."""
        is_valid, msg = verify_timestamp(genesis_node)
        assert is_valid

    def test_missing_timestamp(self):
        """A node without timestamp field is rejected."""
        is_valid, msg = verify_timestamp({"content": {}})
        assert not is_valid

    def test_malformed_timestamp(self):
        """An invalid timestamp format is rejected."""
        is_valid, msg = verify_timestamp({"timestamp": "not-a-date"})
        assert not is_valid
