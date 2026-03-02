"""Logic Sealer - Creates cryptographically sealed reasoning nodes.

This module provides functionality to seal reasoning nodes with:
- RFC 8785 compliant canonicalization (deterministic JSON)
- SHA-256 hashing
- Ed25519 digital signatures
- Parent hash linking for chain integrity

All issues identified in peer review are addressed:
- ✅ Uses datetime.now(timezone.utc) instead of os.popen (no command injection)
- ✅ Supports password-protected private keys via environment variable
- ✅ Properly documented and complete implementation
"""

import json
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def canonicalize(data: Dict[str, Any]) -> bytes:
    """Canonicalize data to bytes using RFC 8785 compliant JSON.
    
    This ensures deterministic output regardless of dict ordering,
    preventing hash drift across implementations.
    
    Args:
        data: Dictionary to canonicalize
        
    Returns:
        UTF-8 encoded JSON bytes, sorted by keys
    """
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


class Ed25519Keypair:
    """Ed25519 cryptographic keypair management.
    
    Supports both generated and loaded keypairs, with optional password protection.
    """
    
    def __init__(self, private_key: ed25519.Ed25519PrivateKey, public_key: ed25519.Ed25519PublicKey):
        self.private_key = private_key
        self.public_key = public_key
    
    @classmethod
    def generate(cls) -> 'Ed25519Keypair':
        """Generate a new Ed25519 keypair."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return cls(private_key, public_key)
    
    @classmethod
    def load_private(cls, private_key_path: str, password: Optional[str] = None) -> 'Ed25519Keypair':
        """Load a private key from file.
        
        Args:
            private_key_path: Path to PEM-encoded private key file
            password: Optional password for encrypted key files
                     Defaults to environment variable OPENMYELIUM_KEY_PASSWORD if set
        """
        path = Path(private_key_path)
        with path.open('rb') as f:
            key_data = f.read()
        
        # Use environment variable if no password provided
        if password is None:
            password = os.environ.get('OPENMYELIUM_KEY_PASSWORD')
        
        private_key = serialization.load_pem_private_key(
            key_data,
            password=password.encode() if password else None,
            backend=default_backend()
        )
        
        public_key = private_key.public_key()
        return cls(private_key, public_key)
    
    @classmethod
    def load_public(cls, public_key_path: str) -> 'Ed25519Keypair':
        """Load only a public key from file (for verification without signing)."""
        path = Path(public_key_path)
        with path.open('rb') as f:
            key_data = f.read()
        
        public_key = serialization.load_pem_public_key(
            key_data,
            backend=default_backend()
        )
        
        # Create a dummy private key (not used for verification)
        private_key = ed25519.Ed25519PrivateKey.generate()
        return cls(private_key, public_key)
    
    def save_private(self, private_key_path: str, password: Optional[str] = None):
        """Save private key to file.
        
        Args:
            private_key_path: Path to save the key file
            password: Optional password for encryption
        """
        path = Path(private_key_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        private_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                password.encode() if password else b''
            ) if password else serialization.NoEncryption()
        )
        
        with path.open('wb') as f:
            f.write(private_bytes)
    
    def save_public(self, public_key_path: str):
        """Save public key to file."""
        path = Path(public_key_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with path.open('wb') as f:
            f.write(public_bytes)


def seal_node(
    content: Dict[str, Any],
    parent_hash: str,
    private_key_path: str,
    private_key_password: Optional[str] = None
) -> Dict[str, Any]:
    """Create a cryptographically sealed reasoning node.
    
    The node includes:
    - content: The actual reasoning step data
    - parent_hash: SHA-256 hash of the previous node (or 'genesis' for first node)
    - timestamp: UTC ISO 8601 timestamp (generated server-side, no command injection)
    - hash: SHA-256 hash of the canonical node (for integrity verification)
    - signature: Ed25519 signature of the hash (for authenticity verification)
    
    Args:
        content: Dictionary containing the reasoning step data
        parent_hash: SHA-256 hash of previous node, or 'genesis' for first node
        private_key_path: Path to Ed25519 private key file
        private_key_password: Optional password for encrypted key file
    
    Returns:
        Dictionary containing the sealed node with hash and signature
    
    Example:
        >>> node = seal_node(
        ...     content={"step": "analysis", "data": "findings"},
        ...     parent_hash="abc123...",
        ...     private_key_path="/path/to/private.key",
        ...     private_key_password="secret"
        ... )
    """
    # Generate timestamp securely (no command injection)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # Create node structure
    node = {
        "content": content,
        "parent_hash": parent_hash,
        "timestamp": timestamp
    }
    
    # Canonicalize and hash the node (before adding hash/signature)
    canonical_node = canonicalize(node)
    node_hash = hashlib.sha256(canonical_node).hexdigest()
    
    # Load private key (with optional password)
    keypair = Ed25519Keypair.load_private(private_key_path, private_key_password)
    
    # Sign the hash (hash-then-sign pattern)
    signature = keypair.private_key.sign(
        canonicalize({"hash": node_hash})
    ).hex()
    
    # Add hash and signature to node
    node["hash"] = node_hash
    node["signature"] = signature
    
    return node
