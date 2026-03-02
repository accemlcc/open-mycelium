"""Example: Creating a genesis node.

This demonstrates how to initialize a new reasoning chain with a genesis node.
"""

import json
from pathlib import Path

# Add parent directory to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.seal import seal_node, Ed25519Keypair


def create_genesis_node():
    """Create a genesis node for a new chain."""
    # Generate new keypair
    keypair = Ed25519Keypair.generate()
    
    # Save keys (with password protection)
    private_path = Path(__file__).parent / "keys" / "genesis_private.key"
    public_path = Path(__file__).parent / "keys" / "genesis_public.key"
    
    keypair.save_private(private_path, password="secure_password")
    keypair.save_public(public_path)
    
    # Create genesis node
    genesis = seal_node(
        content={
            "step": "genesis",
            "version": "1.0.0",
            "description": "Genesis node - start of reasoning chain"
        },
        parent_hash="genesis",
        private_key_path=str(private_path),
        private_key_password="secure_password"
    )
    
    print("Genesis Node Created:")
    print(json.dumps(genesis, indent=2))
    
    # Save genesis hash for reference
    genesis_file = Path(__file__).parent / "genesis_hash.txt"
    with genesis_file.open('w') as f:
        f.write(genesis['hash'])
    
    print(f"\nGenesis hash saved to {genesis_file}")
    print(f"Public key available at: {public_path}")
    
    return genesis, keypair


if __name__ == "__main__":
    genesis, keypair = create_genesis_node()
    
    # Next step: Use this genesis node as parent_hash for the first actual step
    print(f"\nTo continue the chain, use parent_hash='{genesis['hash']}' for subsequent nodes.")
