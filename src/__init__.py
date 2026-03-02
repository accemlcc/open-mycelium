"""OpenMycelium - Logic Skeleton Immune System

A Python library for cryptographic sealing and verification of reasoning chains
in stigmergic (file-based) coordination systems.
"""

from .seal import Ed25519Keypair, seal_node, canonicalize
from .verify import Ed25519PublicKey, verify_node_signature, verify_chain, verify_chain_complete

__version__ = "1.0.0"
__all__ = ["Ed25519Keypair", "seal_node", "canonicalize", "Ed25519PublicKey", "verify_node_signature", "verify_chain", "verify_chain_complete"]
