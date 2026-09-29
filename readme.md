# JOCKY-FX: Evasion-Resilient Forensic Framework

**Smart India Hackathon 2026 | Problem Statement ID: SIH26148**

JOCKY-FX is a cross-platform, LLVM-based forensic investigation framework designed to execute deep system analysis without triggering modern Endpoint Detection and Response (EDR) or Antivirus (AV) solutions. By shifting from standard scripts to a compiled, polymorphic, language-independent intermediate representation (LLVM IR), JOCKY completely bypasses static signature matching and behavioral heuristics.

It pairs an evasion-resilient endpoint agent with a Central Command (C2) SOAR platform featuring a tamper-evident cryptographic ledger.

Folder Structure :

Project\jockey
├── lang_compiler/                 # Component 1 & 2
│   ├── jocky_compiler.py        # Updated language parser with CFG entropy
│   ├── jocky_ci.py              # CI/CD Pipeline
│   ├── polymorphic_builder.py   # The CI/CD script to morph the Rust agent
│   └── scripts/
│       └── hunt_rules.jky       # Your custom JOCKY scripts
├── jocky_agent/                   # Component 3
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs               # Upgraded stealth agent
│       ├── syscalls.rs          # Direct system call wrappers (Windows/Linux)
│       └── obfuscation.rs       # Runtime string decryption logic
└── backend/                       # Component 4
    ├── server.py                # FastAPI backend
    ├── jocky.db                 # SQLite database
    └── templates/
        └── index.html           # Web dashboard


---

## 🎯 Alignment with Problem Statement

The JOCKY-FX architecture strictly satisfies the core objectives of the SIH problem statement:

### 1. Independent Programming Language & LLVM Frontend

* **Requirement:** Alter basic control-flow graphs, token generation, and binary structures to render signature-based detection ineffective.
* **JOCKY Implementation:** We built a custom domain-specific language (DSL) compiler (`jocky_compiler.py`) using `llvmlite`. Instead of relying on noisy Python scripts or standard MSVC/GCC compilation, `.jky` forensic scripts are parsed into a pure LLVM Intermediate Representation (`output.ll`). Correlation rules and metadata are embedded natively as global constants.

### 2. Polymorphism in Scripts & CI/CD Pipeline

* **Requirement:** Utilize a continuous delivery pipeline to automatically pass scripts through obfuscators and polymorphic engines, ensuring unique hashes and modified entry points.
* **JOCKY Implementation:** The `polymorphic_builder.py` acts as our automated CI/CD pipeline. On every build, it injects safe Control-Flow Graph (CFG) mutations (e.g., `SIMULATE_SLEEP_OBFUSCATE`, `SIMULATE_MATH_ENTROPY`). It natively compiles via `llc` and `clang`, outputting an executable (`jocky_agent.exe`) with a mathematically unique SHA-256 hash, build ID, and variation ID for every single deployment.

### 3. Living-off-the-Land (LotL), In-Memory Execution & BYOVD

* **Requirement:** Avoid noisy APIs using file-less techniques (Process Hollowing, API Unhooking) and Kernel-Level Subversion (BYOVD).
* **JOCKY Implementation:**
* **LotL Telemetry:** The Rust agent (`syscalls.rs`) relies exclusively on low-level OS abstractions and native tools (like `netstat` parsing) to avoid noisy API calls.
* **Advanced Technique Architecture (Safe Mode):** To comply with safe hackathon bounds, offensive techniques (Process Hollowing, Reflective DLL Injection, BYOVD) are architecturally mapped in the LLVM engine and executed via a **Safe Simulation Engine** (`lib.rs`). The agent successfully transmits these execution states to the C2 without actually exploiting the host system.

### 4. Central Management Interface

* **Requirement:** Handle multiple system analyses simultaneously using a central management interface.
* **JOCKY Implementation:** The FastAPI server (`server.py`) and Tailwind-powered UI (`index.html`) provide a live Security Orchestration, Automation, and Response (SOAR) dashboard. It ingests multi-host telemetry concurrently, visualizes relationships in a 2D force-directed graph, maintains an immutable SHA-256 hash-chained evidence ledger, and provides instant **Active Response** (Contain Host) capabilities.

---

## 🏗️ System Architecture

1. **JOCKY Script (`.jky`)**: Analyst writes a clean, high-level forensic hunt script.
2. **Compiler Frontend (`jocky_compiler.py`)**: Lexes, parses, and semantically validates the script, emitting `output.ll` (LLVM IR).
3. **CI/CD Builder (`polymorphic_builder.py`)**: Applies CFG entropy, validates LLVM, compiles to native objects via `llc`, and links the Rust safe-stub runtime.
4. **Endpoint Agent (`lib.rs`)**: Cross-platform (Windows/Linux) executable gathers read-only process, network, service, and startup telemetry.
5. **Cryptographic Engine (`obfuscation.rs`)**: Secures internal state and chains evidence blocks using SHA-256.
6. **SOAR C2 Server (`server.py`)**: Evaluates LLVM-embedded correlation rules against incoming telemetry, triggering alerts and visualization.

---

## 🛠️ Technology Stack

* **Language Frontend:** Python 3.8+, `llvmlite` (LLVM 15/16/17+)
* **Endpoint Agent:** Rust (Cross-platform OS bridging, AES-256-GCM encryption, Zeroize)
* **Central Command (C2) Backend:** Python, FastAPI, SQLite (Cryptographic Ledger)
* **C2 Frontend:** HTML5, Tailwind CSS, Force-Graph (D3.js), HTML2PDF

---

## 🚀 Quick Start & Execution Guide

### Prerequisites

* Python 3.8+
* Rust (Cargo)
* LLVM Toolchain installed (`llc`, `clang`, `llvm-as`)

### Step 1: Start the Central Command (C2) Server

Initialize the FastAPI backend and SQLite ledger.

```bash
cd backend
pip install fastapi uvicorn pydantic
python server.py
```

*The dashboard is now live at `[http://127.0.0.1:8000](http://127.0.0.1:8000)*`

### Step 2: Compile Forensic Script to LLVM IR

Parse the high-level `.jky` script into native LLVM IR, embedding the detection rules.

```bash
cd lang_compiler
pip install llvmlite
python jocky_compiler.py scripts/advanced_hunt.jky -o output.ll
```

### Step 3: CI/CD Polymorphic Build

Validate the IR, apply CFG entropy, and link the standalone native executable.

```bash
python polymorphic_builder.py output.ll --platform windows --link --safe-stub-runtime --output-dir ../builds
```

### Step 4: Execute the Native Agent

Run the uniquely generated agent. It will execute the LLVM instructions, gather telemetry, and transmit it to the C2.

```bash
cd ../builds/jky-<GENERATED_BUILD_ID>
jocky_agent.exe
```

---

## 🛡️ JOCKY Script Example (`advanced_hunt.jky`)

The JOCKY DSL is designed to be highly readable for forensic analysts while remaining opaque to static analysis tools once compiled to LLVM IR.

```javascript
host "ALL_ENDPOINTS" {
    collect processes
    collect network_connections
    collect startup_items
    collect services
}

detect {
    if process.name == "mimikatz.exe" alert "Credential Dumping Tool" severity CRITICAL risk_score 85
    if network.local_port == 4444 alert "Default Metasploit Listener" severity CRITICAL risk_score 75
    if startup_items.path == "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" alert "Persistence Run Key" severity HIGH risk_score 70
}
```
