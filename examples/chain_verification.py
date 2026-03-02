"""Example: Verifying reasoning chain integrity.

This demonstrates how to verify both individual nodes and complete chains.
"""

import json
from pathlib import Path
from datetime import datetime, timezone

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.verify import verify_chain, verify_chain_complete, Ed25519PublicKey, verify_node_signature, verify_timestamp


def load_chain_from_file(chain_file: Path) -> list:
    """Load chain from JSONL file."""
    chain = []
    with chain_file.open('r') as f:
        for line in f:
            line = line.strip()
            if line:
                chain.append(json.loads(line))
    return chain


def main():
    """Verify a complete reasoning chain."""
    chain_file = Path(__file__).parent / "chain.jsonl"
    genesis_file = Path(__file__).parent / "genesis_hash.txt"
    public_key_path = Path(__file__).parent / "keys" / "genesis_public.key"
    
    if not chain_file.exists():
        print("❌ Chain file not found. Run chain_creation.py first.")
        return
    
    if not genesis_file.exists():
        print("❌ Genesis hash not found. Run genesis.py first.")
        return
    
    if not public_key_path.exists():
        print("❌ Public key not found. Run genesis.py first.")
        return
    
    # Load chain
    chain = load_chain_from_file(chain_file)
    print(f"\n📖 Verifying {len(chain)} chain steps...")
    
    # Read genesis hash
    with genesis_file.open('r') as f:
        genesis_hash = f.read().strip()
    
    # Load public key
    public_key = Ed25519PublicKey.load(str(public_key_path))
    
    # Verify only the actual signed steps (exclude genesis from chain verification)
    print("\n🔍 Verifying chain continuity and signatures...")
    
    # First, verify genesis hash matches
    message = "Hash matches genesis" if chain[0]['parent_hash'] == genesis_hash else "Chain start mismatch"
    print(f"Genesis verification: {message}")
    if "Chain start mismatch" in message:
        return
    
    # Verify chain integrity from step 0 onwards
    messages = []
    all_valid = True
    
    for i, node in enumerate(chain):
        # Verify individual node signature and hash
        is_valid, message = verify_node_signature(node, public_key.public_key)
        messages.append(f"Step {i+1}: {message}")
        if not is_valid:
            all_valid = False
            
        # Verify chain continuity (except for first step)
        if i > 0:
            expected_parent = chain[i-1]['hash']
            if node['parent_hash'] == expected_parent:
                messages.append(f"Step {i+1}: Chain continuity OK")
            else:
                messages.append(f"Step {i+1}: Chain break!")
                all_valid = False
        
        # Verify timestamp
        ts_valid, ts_msg = verify_timestamp(node)
        messages.append(f"Step {i+1}: {ts_msg}")
        if not ts_valid:
            all_valid = False
    
    print("\n" + "="*60)
    print("VERIFICATION RESULTS")
    print("="*60)
    
    for message in messages:
        print(message)
    
    if is_valid:
        print("\n✅ **ALL CHECKS PASSED**")
        print("   - All nodes have valid signatures")
        print("   - All nodes have valid hashes")
        print("   - Chain continuity verified")
        print("   - Timestamps within acceptable range")
    else:
        print("\n❌ VERIFICATION FAILED")
        print("   One or more checks failed above.")
        print("   The chain may have been tampered with.")
    
    print("\n" + "="*60)
    
    # Individual node verification
    print("\n📋 Individual Node Summary:")
    for i, node in enumerate(chain):
        step = node.get('content', {}).get('step', 'unknown')
        ts = node.get('timestamp', 'unknown')
        print(f"   {i+1}. {step} @ {ts[:19]}...")


if __name__ == "__main__":
    main()
