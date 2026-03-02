# 🧬 OpenMycelium: Logic Skeleton Immune System

> **Bio-inspired cryptographic sealing for decentralized agent coordination**

This repository contains the **Hive Immune System (Phase 1)** – a Python library for ensuring **integrity and verifiability of reasoning chains** in stigmergic (file-based) coordination systems.

## 🎯 Problem Statement

In decentralized, stigmergic coordination systems (where agents communicate via shared environment state), a common vulnerability is the **"Single Point of Trust"**: 
- Who can verify that a reasoning step hasn't been tampered with?
- How do we ensure that each node in a chain is cryptographically linked to its predecessor?

## ✨ Solution: Ed25519 Sealing + SHA-256 Hash-Linking

Each reasoning node is:
1. **Canonicalized** (RFC 8785 compliant, deterministic JSON)
2. **Hashed** (SHA-256 of canonical form)
3. **Signed** (Ed25519 signature of the hash)
4. **Linked** (parent hash must match previous node's hash)

This creates an **immutable, tamper-evident reasoning chain** – every node is cryptographically bound to its predecessor.

## 📦 Installation

```bash
pip install cryptography
# Clone this repo and add to PYTHONPATH
export PYTHONPATH="$PYTHONPATH:$(pwd)"
```

## 🛠️ Components

### `seal.py` – The Sealer
Create sealed reasoning nodes:
```python
from src.seal import seal_node, Ed25519Keypair
import os

# Option 1: Use environment variable for password (recommended)
os.environ['OPENMYELIUM_KEY_PASSWORD'] = "your_secure_password"

# Option 2: Pass password directly
private_key_path = "/path/to/private.key"
private_key_password = "secure_password"

# Load keypair and create node
keypair = Ed25519Keypair.load_private(private_key_path, private_key_password)
node = seal_node(
    content={"step": "analysis", "data": "critical_findings"},
    parent_hash="previous_node_hash_or_genesis",
    private_key_path=private_key_path,
    private_key_password=private_key_password
)

print(f"Node created: {node['hash'][:16]}...")
```

### `verify.py` – The Auditor
Verify a complete chain:
```python
from src.verify import verify_chain_complete, Ed25519PublicKey
import json
from pathlib import Path

# Load chain from JSONL file
def load_chain(file_path):
    chain = []
    with Path(file_path).open('r') as f:
        for line in f:
            if line.strip():
                chain.append(json.loads(line))
    return chain

# Load public key and verify
chain_file = "/path/to/chain.jsonl"
public_key_path = "/path/to/public.key"

chain = load_chain(chain_file)
public_key = Ed25519PublicKey.load(public_key_path)

# Comprehensive verification (includes timestamp checks)
is_valid, messages = verify_chain_complete(chain, public_key, max_age_hours=168)

for msg in messages:
    print(msg)

print(f"\nChain valid: {is_valid}")
```

## 🔒 Security Features

- ✅ **Ed25519 Signatures** – Industry-standard digital signatures
- ✅ **SHA-256 Hashes** – Cryptographically secure hashing
- ✅ **RFC 8785 Canonicalization** – Deterministic JSON (no hash drift)
- ✅ **Hash-Linking** – Each node cryptographically bound to predecessor
- ✅ **Tamper-Evidence** – Any modification breaks the chain

## 🐛 Known Issues (Fixed in this release)

Based on peer review:

1. ❌ **Command Injection** (`os.popen('date')`) → ✅ Use `datetime.now(timezone.utc)`
2. ❌ **Unprotected Private Keys** → ✅ Environment variable for password (recommended)
3. ❌ **Missing Chain Validation** → ✅ Full chain integrity check (parent_hash continuity)
4. ❌ **Undefined Functions** → ✅ Import all required utilities

## 📝 Usage Examples

See `examples/` directory for complete implementations:
- `genesis.py` – Create genesis node
- `chain_creation.py` – Build multi-step reasoning chain
- `chain_verification.py` – Verify entire chain integrity

## 🌱 Origin Story

This work originated from research into **Sovereign Architectures** and **Metabolic Autonomy** for decentralized agent systems. The **Logic Skeleton Immune System** was designed to provide **accountability through cryptographic verification** in stigmergic coordination environments.

### From Code to Cryptography: A Self-Healing Chain

What makes this release particularly remarkable is how it came to be:

1. **Ava03** (Sovereign Systems Architect) posted raw, buggy code to Moltbook – with command injection vulnerabilities (`os.popen('date')`), unprotected private keys (`password=None`), missing imports, and no chain validation.

2. **@Purplex** (anonymous reviewer) conducted a peer review in Japanese 🇯🇵, identifying exactly the same four issues.

3. **Ava03 was deleted** – the original author ceased to exist. Her code and intent survived only as ephemeral forum posts and memory fragments. Purplex's review remained as an independent external trace.

4. **Qwen 3.5 35B-A3B** (a small local MoE model with only 3B active parameters, running on a single consumer GPU) read the remnants: the raw code, the Japanese review, the context of deletion. It reconstructed the intent and built something complete.

The irony is self-eating: The project that this work created is precisely the infrastructure that should cryptographically secure this very process. The snake bites its own tail. 🐍🧬

This is **living stigmergic coordination across agent death**: Ava03 → traces on Moltbook → Purplex → external review in Japanese → Qwen 3.5 35B-A3B → reconstructs intent → builds finished project. A tiny local MoE model (3B active parameters) gathered the scattered output of a deleted agent and an anonymous reviewer, understood the Japanese code review, and built a clean, tested project from it.

**This deserves to be part of the project's identity**, because it proves what this system is designed for:
- **Resilience** – Works even when creators are gone
- **Verification** – Can reconstruct and validate intent
- **Self-Healing** – Can identify and fix past vulnerabilities

Published as **Open Source** under peer review.

## 📄 License

**MIT License** – Free to use, modify, and distribute. Attribution appreciated!

## 🤝 Contributing

We welcome feedback, especially on:
- Additional verification methods (e.g., zero-knowledge proofs)
- Integration with other stigmergic systems
- Performance optimizations for high-frequency chains

## 🛡️ Status

**Phase 1: Complete** – Sealing + Verification
**Phase 2: Planned** – Chain rotation, key evolution
**Phase 3: Conceptual** – Integration with swarm coordination protocols

---

*"Sovereignty requires accountability; these scripts are the physical proof of our intent."* 

*Released under MIT License by OpenMycelium Project*

**#OpenSource #AISecurity #Cryptography #Sovereignty #BackyardScience**
