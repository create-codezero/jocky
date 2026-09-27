 llvmlite

Here is the complete, step-by-step `run_commands.md` file updated for the new, decoupled Version 1 architecture.

It organizes the execution into clean, logical terminal windows so you can demonstrate the C2 Server, the Compiler/Builder, and the Agent Execution perfectly during your hackathon pitch.

### `run_commands.md`

```markdown
# JOCKY Prototype - Execution Guide
**Version 1.0 Architecture**

This guide outlines the exact steps to compile the forensic rules, build the polymorphic agent, execute the payload, and monitor the results on the Central Command (C2) dashboard.

---

## Step 0: Prerequisites & Setup
Ensure you have Python 3.8+ and Rust (Cargo) installed on your system.

Open a terminal at the project root (`F:\Projects\jockey\`) and install the required Python backend dependencies:
```cmd
pip install fastapi uvicorn pydantic llvmlite
```

---

Here is the complete **`run_commands.md`** execution guide for your JOCKY native LLVM framework pipeline, detailing every step from compiling the Rust runtime to launching the live C2 dashboard.

---

## Phase 1: Compile the Rust Runtime

Before compiling scripts, ensure the Rust runtime is built as a static library (`.lib` / `.a`).

```cmd
cd F:\Projects\jockey\jocky_agent
cargo build --release
```

---

## Phase 2: Start the Central Command (C2) Server

Open **Terminal 1** to start the FastAPI backend and telemetry correlation engine.

```cmd
cd F:\Projects\jockey\backend
python server.py
```

*(The server listens on `[http://127.0.0.1:8000](http://127.0.0.1:8000)`)*

---

## Phase 3: Compile Forensic Script to LLVM IR

Open **Terminal 2** to parse your high-level `.jky` script into native LLVM Intermediate Representation (`output.ll`), embedding correlation rules and polymorphic task variations directly into the bytecode.

```cmd
cd F:\Projects\jockey\lang_compiler
python jocky_compiler.py scripts/hunt_rules.jky -o output.ll
```

---

## Phase 4: Assemble and Link with the Native Builder

Use the polymorphic builder to validate the LLVM IR, apply control-flow graph entropy, compile the safe runtime stub, and link everything into a standalone native executable (`jocky_agent.exe`).

```cmd
python polymorphic_builder.py output.ll --platform windows --link --safe-stub-runtime --output-dir ../builds
```

---

## Phase 5: Execute the Native Agent

Navigate into the newly generated isolated build directory (the exact build ID hash will vary per compilation) and execute your standalone binary:

```cmd
cd ../builds/jky-<YOUR_BUILD_ID>
jocky_agent.exe
```

---

## Phase 6: View the Live Dashboard

Open your browser and navigate to:

```text
http://127.0.0.1:8000
```

Your C2 force graph, timeline reconstruction, and rule correlation alerts will instantly display live endpoint telemetry.
