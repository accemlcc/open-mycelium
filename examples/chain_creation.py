"""Example: Building a multi-step reasoning chain.

This demonstrates how to create and append nodes to a reasoning chain.
"""

import json
from pathlib import Path
from datetime import datetime

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.seal import seal_node, Ed25519Keypair


def create_chain_step(
    content: dict,
    parent_hash: str,
    private_key_path: str,
    private_key_password: str,
    chain_file: Path
) -> dict:
    """Create a new chain step and append to JSONL file."""
    node = seal_node(
        content=content,
        parent_hash=parent_hash,
        private_key_path=private_key_path,
        private_key_password=private_key_password
    )
    
    # Append to chain file
    with chain_file.open('a') as f:
        f.write(json.dumps(node) + '\n')
    
    print(f"Step {node['timestamp']}: {content.get('step', 'unknown')}")
    return node


def main():
    """Create a sample multi-step reasoning chain."""
    private_key_path = Path(__file__).parent / "keys" / "genesis_private.key"
    private_key_password = "secure_password"
    chain_file = Path(__file__).parent / "chain.jsonl"
    
    # Clear existing chain
    if chain_file.exists():
        chain_file.unlink()
    
    # Read genesis hash
    genesis_hash_file = Path(__file__).parent / "genesis_hash.txt"
    with genesis_hash_file.open('r') as f:
        parent_hash = f.read().strip()
    
    # Step 1: Research
    print("\n📚 Creating chain step 1: Research phase")
    node1 = create_chain_step(
        content={
            "step": "research",
            "title": "Literature Review",
            "findings": ["Pattern A observed in system X", "Pattern B in system Y"],
            "confidence": 0.85
        },
        parent_hash=parent_hash,
        private_key_path=str(private_key_path),
        private_key_password=private_key_password,
        chain_file=chain_file
    )
    parent_hash = node1['hash']
    
    # Step 2: Analysis
    print("\n🔍 Creating chain step 2: Analysis phase")
    node2 = create_chain_step(
        content={
            "step": "analysis",
            "method": "comparative_study",
            "correlation": "A ↔ B",
            "hypothesis": "Cross-system signal propagation"
        },
        parent_hash=parent_hash,
        private_key_path=str(private_key_path),
        private_key_password=private_key_password,
        chain_file=chain_file
    )
    parent_hash = node2['hash']
    
    # Step 3: Decision
    print("\n🎯 Creating chain step 3: Decision phase")
    node3 = create_chain_step(
        content={
            "step": "decision",
            "action": "deploy_test",
            "rationale": "Signal correlation exceeds threshold",
            "expected_outcome": "Validate propagation pattern"
        },
        parent_hash=parent_hash,
        private_key_path=str(private_key_path),
        private_key_password=private_key_password,
        chain_file=chain_file
    )
    parent_hash = node3['hash']
    
    # Step 4: Result
    print("\n📊 Creating chain step 4: Result phase")
    node4 = create_chain_step(
        content={
            "step": "result",
            "outcome": "success",
            "validation": "Pattern confirmed",
            "metrics": {"propagation_time": "1.2s", "confidence": 0.92}
        },
        parent_hash=parent_hash,
        private_key_path=str(private_key_path),
        private_key_password=private_key_password,
        chain_file=chain_file
    )
    
    print("\n✅ Chain complete!")
    print(f"Total nodes: 5 (genesis + 4 steps)")
    print(f"Chain file: {chain_file}")
    print(f"Final hash: {node4['hash']}")


if __name__ == "__main__":
    main()
