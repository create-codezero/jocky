#!/usr/bin/env python3
"""
JOCKY CI/CD Pipeline Simulator
==============================
Automates compiling .jky scripts, applying polymorphic CFG mutation,
building native binaries via polymorphic_builder.py, and tracking
build mutation history.
"""

import subprocess
import json
import time
from pathlib import Path
from datetime import datetime, timezone

HISTORY_FILE = Path("build_pipeline_history.json")

def run_ci_pipeline(script_path="scripts/advanced_hunt.jky"):
    print(f"\n[CI/CD] Triggering automated build pipeline for {script_path}...")
    start_time = time.time()
    
    # 1. Compile script to LLVM IR
    print("[CI/CD] Step 1: Compiling high-level forensic language to LLVM IR...")
    res_comp = subprocess.run(
        ["python", "jocky_compiler.py", script_path, "-o", "output.ll"],
        capture_output=True, text=True
    )
    
    if res_comp.returncode != 0:
        print(f"[CI/CD] ✗ Compilation failed:\n{res_comp.stderr}")
        return False
        
    print("[✓] LLVM IR emission successful.")

    # 2. Run Polymorphic Native Builder & Safe Stub Linker
    print("[CI/CD] Step 2: Running Polymorphic Builder & Safe Runtime Linker...")
    res_build = subprocess.run(
        ["python", "polymorphic_builder.py", "output.ll", "--platform", "windows", "--link", "--safe-stub-runtime", "--output-dir", "../builds"],
        capture_output=True, text=True
    )
    
    if res_build.returncode != 0:
        print(f"[CI/CD] ✗ Native build failed:\n{res_build.stderr}")
        return False
        
    print("[✓] Native executable generated successfully.")
    
    # Read generated manifest to extract build ID and SHA-256
    builds_root = Path("../builds")
    latest_build = max([p for p in builds_root.iterdir() if p.is_dir()], key=os.path.getmtime) if builds_root.exists() else None
    
    build_id = latest_build.name if latest_build else "UNKNOWN"
    manifest_path = latest_build / "manifest.json" if latest_build else None
    
    llvm_sha256 = "N/A"
    if manifest_path and manifest_path.exists():
        try:
            manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
            llvm_sha256 = manifest_data.get("input", {}).get("llvm_sha256", "N/A")
        except:
            pass

    elapsed = round(time.time() - start_time, 2)
    
    # Record history
    history_entry = {
        "build_id": build_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "script": script_path,
        "llvm_sha256": llvm_sha256,
        "build_time_seconds": elapsed,
        "status": "SUCCESS"
    }
    
    history = []
    if HISTORY_FILE.exists():
        try:
            history = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        except:
            history = []
            
    history.insert(0, history_entry)
    HISTORY_FILE.write_text(json.dumps(history, indent=2), encoding="utf-8")
    
    print(f"\n[CI/CD] Pipeline Finished Successfully in {elapsed}s | Build ID: {build_id}")
    print(f"[CI/CD] Build recorded in {HISTORY_FILE.name}\n")
    return True

if __name__ == "__main__":
    import os
    run_ci_pipeline()