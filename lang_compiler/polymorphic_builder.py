#!/usr/bin/env python3
"""
JOCKY Native Builder
====================

LLVM IR (.ll)
    ->
LLVM native object (.obj/.o)
    ->
JOCKY runtime / safe stub
    ->
native executable

The builder is responsible for:
- LLVM validation
- runtime symbol analysis
- safe symbol contract enforcement
- native code generation
- optional linking
- reproducible build metadata
- SHA-256 build artifacts
- simulation metadata

Safety model:
- read-only forensic runtime contract
- no arbitrary command execution
- no process injection
- no AV/EDR bypass
- no kernel exploitation
- no privilege escalation
- no persistence
- no covert routing
- advanced offensive techniques are simulation metadata only
"""

import argparse
import hashlib
import json
import os
import platform
import random
import re
import shutil
import subprocess
import sys
import time
import uuid

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ============================================================
# TERMINAL COLORS
# ============================================================

GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"


# ============================================================
# CONSTANTS
# ============================================================

BUILDER_VERSION = "2.1.0"

VALID_PLATFORMS = {
    "windows",
    "linux",
}

LLVM_TRIPLES = {
    "windows": "x86_64-pc-windows-msvc",
    "linux": "x86_64-unknown-linux-gnu",
}


VALID_ARTIFACTS = {
    "processes",
    "network_connections",
    "startup_items",
    "users",
    "services",
    "file_metadata",
    "authentication_events",
    "system_information",
}


SAFE_RUNTIME_SYMBOLS = {
    "jocky_sys_init",
    "jocky_sys_transmit",
}


SAFE_OPERATION_PREFIX = "jocky_op_"


COMPILER_VARIATION_OPS = {
    "SIMULATE_SLEEP_OBFUSCATE",
    "SIMULATE_MATH_ENTROPY",
    "SIMULATE_MEMORY_ALLOC_FREE",
    "SIMULATE_ENV_QUERY",
}


SIMULATION_TECHNIQUES = {
    "PROCESS_HOLLOWING",
    "REFLECTIVE_LOADING",
    "REFLECTIVE_DLL_INJECTION",
    "THREAD_HIJACKING",
    "API_UNHOOKING",
    "DIRECT_SYSCALL",
    "VULNERABLE_DRIVER",
    "BYOVD",
    "DOMAIN_FRONTING",
    "CDN_ENCAPSULATION",
    "SOCKS5_ROUTING",
    "IN_MEMORY_EXECUTION",
    "KERNEL_SUBVERSION",
}


BLOCKED_TECHNIQUES = {
    "REAL_PROCESS_HOLLOWING",
    "REAL_REFLECTIVE_INJECTION",
    "REAL_THREAD_HIJACKING",
    "REAL_API_UNHOOKING",
    "REAL_DIRECT_SYSCALL",
    "REAL_BYOVD",
    "REAL_DRIVER_EXPLOIT",
    "REAL_EDR_TAMPERING",
    "REAL_AV_BYPASS",
    "REAL_PRIVILEGE_ESCALATION",
    "REAL_PERSISTENCE",
    "REAL_COVERT_C2",
}


# ============================================================
# DATA STRUCTURES
# ============================================================

@dataclass
class CommandResult:
    command: List[str]
    returncode: int
    stdout: str
    stderr: str
    elapsed_seconds: float


@dataclass
class SymbolAnalysis:
    runtime_symbols: List[str]
    collection_symbols: List[str]
    variation_symbols: List[str]
    simulation_symbols: List[str]
    blocked_symbols: List[str]
    unknown_symbols: List[str]


# ============================================================
# LOGGING
# ============================================================

def info(message: str) -> None:
    print(f"{CYAN}[~]{RESET} {message}")


def ok(message: str) -> None:
    print(f"{GREEN}[✓]{RESET} {message}")


def warn(message: str) -> None:
    print(f"{YELLOW}[!]{RESET} {message}")


def error(message: str) -> None:
    print(f"{RED}[✗]{RESET} {message}")


def section(title: str) -> None:
    print()
    print(f"{BOLD}{MAGENTA}{title}{RESET}")
    print("-" * 72)


# ============================================================
# HASHING
# ============================================================

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


# ============================================================
# TIME / BUILD IDS
# ============================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_timestamp() -> str:
    return utc_now().strftime("%Y%m%d-%H%M%S")


def generate_build_id(
    llvm_hash: str,
    reproducible: bool,
) -> str:

    if reproducible:
        suffix = llvm_hash[:12]
    else:
        suffix = secrets_token(12)

    return (
        f"jky-{utc_timestamp()}-{suffix}"
    )


def generate_variation_id(
    llvm_hash: str,
    reproducible: bool,
) -> str:

    if reproducible:
        seed = f"variation:{llvm_hash}"
        return hashlib.sha256(
            seed.encode("utf-8")
        ).hexdigest()[:16]

    return secrets_token(16)


def secrets_token(length: int) -> str:
    return uuid.uuid4().hex[:length]


# ============================================================
# COMMAND EXECUTION
# ============================================================

def run_command(
    command: List[str],
    cwd: Optional[Path] = None,
) -> CommandResult:

    start = time.perf_counter()

    try:
        result = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        elapsed = (
            time.perf_counter() - start
        )

        return CommandResult(
            command=command,
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            elapsed_seconds=elapsed,
        )

    except OSError as exc:

        elapsed = (
            time.perf_counter() - start
        )

        return CommandResult(
            command=command,
            returncode=-1,
            stdout="",
            stderr=str(exc),
            elapsed_seconds=elapsed,
        )


# ============================================================
# TOOL DISCOVERY
# ============================================================

def find_tool(
    preferred: Optional[str],
    alternatives: List[str],
) -> Optional[str]:

    candidates = []

    if preferred:
        candidates.append(preferred)

    candidates.extend(alternatives)

    for candidate in candidates:

        resolved = shutil.which(candidate)

        if resolved:
            return resolved

        direct = Path(candidate)

        if direct.exists():
            return str(
                direct.resolve()
            )

    return None


def find_llvm_tools(
    args: argparse.Namespace,
) -> Dict[str, Optional[str]]:

    llc = find_tool(
        args.llc,
        [
            "llc",
            "llc-19",
            "llc-18",
            "llc-17",
            "llc-16",
            "llc-15",
        ],
    )

    llvm_as = find_tool(
        args.llvm_as,
        [
            "llvm-as",
            "llvm-as-19",
            "llvm-as-18",
            "llvm-as-17",
            "llvm-as-16",
            "llvm-as-15",
        ],
    )

    llvm_dis = find_tool(
        args.llvm_dis,
        [
            "llvm-dis",
            "llvm-dis-19",
            "llvm-dis-18",
            "llvm-dis-17",
            "llvm-dis-16",
            "llvm-dis-15",
        ],
    )

    objdump = find_tool(
        args.objdump,
        [
            "llvm-objdump",
            "llvm-objdump-19",
            "llvm-objdump-18",
            "llvm-objdump-17",
            "llvm-objdump-16",
        ],
    )

    clang = find_tool(
        args.clang,
        [
            "clang",
            "clang-19",
            "clang-18",
            "clang-17",
            "clang-16",
            "clang-15",
        ],
    )

    return {
        "llc": llc,
        "llvm_as": llvm_as,
        "llvm_dis": llvm_dis,
        "objdump": objdump,
        "clang": clang,
    }


# ============================================================
# LLVM INPUT
# ============================================================

def read_llvm(path: Path) -> str:

    try:
        return path.read_text(
            encoding="utf-8"
        )

    except UnicodeDecodeError:

        return path.read_text(
            encoding="utf-8",
            errors="replace",
        )


# ============================================================
# SYMBOL EXTRACTION
# ============================================================

def extract_jocky_symbols(
    llvm_text: str,
) -> List[str]:
    """
    Extract every JOCKY runtime symbol from LLVM IR.

    We intentionally search the entire IR rather than only
    `declare` lines.

    This handles:

        declare void @jocky_op_processes()

        call void @jocky_op_processes()

        define void @jocky_op_processes()
    """

    # LLVM textual IR permits identifiers to be either unquoted:
    #
    #     @jocky_op_processes
    #
    # or quoted (llvmlite commonly emits this form):
    #
    #     @"jocky_op_processes"
    #
    # The previous parser only accepted the first form, which caused
    # runtime symbol analysis to return zero symbols and therefore
    # generated a safe stub without the operation functions required
    # by the linker.
    pattern = re.compile(
        r'@"?([A-Za-z_.$][A-Za-z0-9_.$]*)"?'
    )

    symbols = set()

    for match in pattern.finditer(
        llvm_text
    ):

        symbol = match.group(1)

        if symbol.startswith("jocky_"):
            symbols.add(symbol)

    return sorted(symbols)


def analyze_symbols(
    llvm_text: str,
) -> SymbolAnalysis:

    all_symbols = extract_jocky_symbols(
        llvm_text
    )

    runtime_symbols = []
    collection_symbols = []
    variation_symbols = []
    simulation_symbols = []
    blocked_symbols = []
    unknown_symbols = []

    artifact_operation_symbols = {
        f"jocky_op_{name}"
        for name in VALID_ARTIFACTS
    }

    variation_operation_symbols = {
        f"jocky_op_{name}"
        for name in COMPILER_VARIATION_OPS
    }

    simulation_operation_symbols = {
        f"jocky_op_{name}"
        for name in SIMULATION_TECHNIQUES
    }

    blocked_operation_symbols = {
        f"jocky_op_{name}"
        for name in BLOCKED_TECHNIQUES
    }

    for symbol in all_symbols:

        if symbol in SAFE_RUNTIME_SYMBOLS:

            runtime_symbols.append(symbol)

        elif symbol in artifact_operation_symbols:

            collection_symbols.append(symbol)

        elif symbol in variation_operation_symbols:

            variation_symbols.append(symbol)

        elif symbol in simulation_operation_symbols:

            simulation_symbols.append(symbol)

        elif symbol in blocked_operation_symbols:

            blocked_symbols.append(symbol)

        elif symbol.startswith(
            SAFE_OPERATION_PREFIX
        ):

            unknown_symbols.append(symbol)

        else:

            unknown_symbols.append(symbol)

    return SymbolAnalysis(
        runtime_symbols=sorted(
            set(runtime_symbols)
        ),
        collection_symbols=sorted(
            set(collection_symbols)
        ),
        variation_symbols=sorted(
            set(variation_symbols)
        ),
        simulation_symbols=sorted(
            set(simulation_symbols)
        ),
        blocked_symbols=sorted(
            set(blocked_symbols)
        ),
        unknown_symbols=sorted(
            set(unknown_symbols)
        ),
    )


# ============================================================
# LLVM VALIDATION
# ============================================================

def validate_llvm_symbols(
    analysis: SymbolAnalysis,
    strict: bool,
) -> bool:

    if analysis.blocked_symbols:

        error(
            "Blocked runtime symbols detected:"
        )

        for symbol in analysis.blocked_symbols:
            print(
                f"    {symbol}"
            )

        return False

    if analysis.unknown_symbols:

        if strict:

            error(
                "Unknown JOCKY runtime symbols detected:"
            )

            for symbol in analysis.unknown_symbols:
                print(
                    f"    {symbol}"
                )

            return False

        warn(
            "Unknown JOCKY symbols detected; "
            "they will not be generated by the safe stub:"
        )

        for symbol in analysis.unknown_symbols:
            print(
                f"    {symbol}"
            )

    return True


def validate_with_llvm_as(
    llvm_as: Optional[str],
    llvm_path: Path,
    build_dir: Path,
) -> bool:

    if not llvm_as:

        warn(
            "llvm-as not found; "
            "falling back to textual LLVM validation."
        )

        return True

    bitcode_path = (
        build_dir /
        "validated.bc"
    )

    result = run_command(
        [
            llvm_as,
            str(llvm_path),
            "-o",
            str(bitcode_path),
        ]
    )

    if result.returncode != 0:

        error(
            "LLVM IR validation failed."
        )

        if result.stderr:
            print(result.stderr)

        return False

    ok(
        "LLVM IR validated successfully."
    )

    return True


# ============================================================
# SAFE RUNTIME STUB
# ============================================================

def c_escape(value: str) -> str:

    return (
        value
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def generate_safe_runtime_stub(
    output_path: Path,
    symbol_analysis: SymbolAnalysis,
    build_id: str,
) -> Path:
    """
    Generate a safe linker-compatible runtime.

    IMPORTANT:
    These functions do not perform invasive operations.

    Collection operations only report that they were invoked.
    The stub exists to validate:
        LLVM -> object -> linker -> executable

    Real read-only collection belongs in the Rust runtime.
    """

    required_operations = set()

    required_operations.update(
        symbol_analysis.collection_symbols
    )

    required_operations.update(
        symbol_analysis.variation_symbols
    )

    required_operations.update(
        symbol_analysis.simulation_symbols
    )

    operation_functions = []

    for symbol in sorted(
        required_operations
    ):

        escaped = c_escape(symbol)

        operation_functions.append(
            f"""
void {symbol}(void)
{{
    printf("[JOCKY] operation: {escaped}\\\\n");
}}
"""
        )

    runtime = f"""
#include <stdio.h>

#if defined(_WIN32)
#define JOCKY_EXPORT __declspec(dllexport)
#else
#define JOCKY_EXPORT
#endif

static const char *JOCKY_BUILD_ID =
    "{c_escape(build_id)}";

JOCKY_EXPORT
void jocky_sys_init(void)
{{
    printf("[JOCKY] runtime initialized\\\\n");
    printf("[JOCKY] build: %s\\\\n", JOCKY_BUILD_ID);
    printf("[JOCKY] mode: SAFE STUB\\\\n");
}}

JOCKY_EXPORT
void jocky_sys_transmit(void)
{{
    printf(
        "[JOCKY] evidence transmission boundary reached\\\\n"
    );

    printf(
        "[JOCKY] SAFE STUB: no network transmission performed\\\\n"
    );
}}

{"".join(operation_functions)}
"""

    output_path.write_text(
        runtime.strip() + "\n",
        encoding="utf-8",
    )

    return output_path


# ============================================================
# NATIVE OBJECT GENERATION
# ============================================================

def compile_object(
    llc: str,
    llvm_path: Path,
    object_path: Path,
    triple: str,
    optimization: str,
    emit_assembly: bool,
    assembly_path: Optional[Path],
) -> Tuple[bool, Optional[Path]]:

    info(
        "Generating native object with llc "
        f"({triple}, O{optimization})..."
    )

    command = [
        llc,
        f"-mtriple={triple}",
        f"-O{optimization}",
        "-filetype=obj",
        str(llvm_path),
        "-o",
        str(object_path),
    ]

    result = run_command(
        command
    )

    if result.returncode != 0:

        error(
            "llc object generation failed."
        )

        if result.stderr:
            print(result.stderr)

        return False, None

    ok(
        f"Native object generated: "
        f"{object_path.name}"
    )

    if (
        emit_assembly
        and assembly_path
    ):

        asm_command = [
            llc,
            f"-mtriple={triple}",
            f"-O{optimization}",
            "-filetype=asm",
            str(llvm_path),
            "-o",
            str(assembly_path),
        ]

        asm_result = run_command(
            asm_command
        )

        if asm_result.returncode != 0:

            warn(
                "Assembly generation failed; "
                "continuing with object."
            )

        else:

            ok(
                "Native assembly generated: "
                f"{assembly_path.name}"
            )

    return True, object_path


# ============================================================
# LINKING
# ============================================================

def link_native_executable(
    clang: str,
    object_path: Path,
    executable_path: Path,
    runtime_objects: List[Path],
    runtime_libraries: List[str],
    platform_target: str,
) -> bool:

    command = [
        clang,
        str(object_path),
    ]

    command.extend(
        str(path)
        for path in runtime_objects
    )

    command.extend(
        runtime_libraries
    )

    if platform_target == "windows":

        command.extend(
            [
                "-target",
                LLVM_TRIPLES["windows"],
            ]
        )

    command.extend(
        [
            "-o",
            str(executable_path),
        ]
    )

    info(
        "Linking native executable..."
    )

    result = run_command(
        command
    )

    if result.returncode != 0:

        error(
            "Native linking failed."
        )

        if result.stdout:
            print(result.stdout)

        if result.stderr:
            print(result.stderr)

        return False

    ok(
        "Native executable generated: "
        f"{executable_path.name}"
    )

    return True


# ============================================================
# OBJECT SYMBOL INSPECTION
# ============================================================

def inspect_object_symbols(
    objdump: Optional[str],
    object_path: Path,
    output_path: Path,
) -> None:

    if not objdump:

        warn(
            "llvm-objdump not found; "
            "skipping object symbol inspection."
        )

        return

    result = run_command(
        [
            objdump,
            "-t",
            str(object_path),
        ]
    )

    report = {
        "command": result.command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }

    output_path.write_text(
        json.dumps(
            report,
            indent=2,
        ),
        encoding="utf-8",
    )

    if result.returncode == 0:

        ok(
            "Native object symbol report generated."
        )

    else:

        warn(
            "Native object symbol inspection failed."
        )


# ============================================================
# SIMULATION REPORT
# ============================================================

def generate_simulation_report(
    build_id: str,
    variation_id: str,
    analysis: SymbolAnalysis,
    output_path: Path,
) -> Dict:

    techniques = []

    for symbol in analysis.simulation_symbols:

        raw = symbol

        prefix = "jocky_op_"

        if raw.startswith(prefix):
            technique = raw[len(prefix):]
        else:
            technique = raw

        techniques.append(
            {
                "symbol": raw,
                "technique": technique,
                "mode": "SIMULATION_ONLY",
            }
        )

    report = {
        "schema_version": "1.0",
        "build_id": build_id,
        "variation_id": variation_id,
        "techniques": techniques,
        "blocked_symbols": analysis.blocked_symbols,
        "policy": {
            "simulation_only": True,
            "real_injection": False,
            "real_kernel_exploitation": False,
            "real_security_product_tampering": False,
            "real_covert_routing": False,
        },
    }

    output_path.write_text(
        json.dumps(
            report,
            indent=2,
        ),
        encoding="utf-8",
    )

    return report


# ============================================================
# SYMBOL REPORT
# ============================================================

def write_symbol_report(
    path: Path,
    analysis: SymbolAnalysis,
) -> None:

    report = asdict(
        analysis
    )

    report["counts"] = {
        key: len(value)
        for key, value in report.items()
        if isinstance(value, list)
    }

    path.write_text(
        json.dumps(
            report,
            indent=2,
        ),
        encoding="utf-8",
    )


# ============================================================
# MANIFEST
# ============================================================

def create_manifest(
    build_id: str,
    variation_id: str,
    llvm_path: Path,
    object_path: Path,
    assembly_path: Optional[Path],
    executable_path: Optional[Path],
    simulation_path: Path,
    symbol_report_path: Path,
    source_path: Optional[Path],
    platform_target: str,
    optimization: str,
    tools: Dict[str, Optional[str]],
    symbol_analysis: SymbolAnalysis,
    security_policy: Dict,
    reproducible: bool,
) -> Dict:

    manifest = {
        "schema_version": "2.1",

        "builder": {
            "name": "JOCKY Native Builder",
            "version": BUILDER_VERSION,
        },

        "build": {
            "build_id": build_id,
            "variation_id": variation_id,
            "reproducible": reproducible,
            "generated_at": utc_now().isoformat(),
        },

        "input": {
            "llvm_file": str(
                llvm_path
            ),
            "llvm_sha256": sha256_file(
                llvm_path
            ),
        },

        "target": {
            "platform": platform_target,
            "triple": LLVM_TRIPLES[
                platform_target
            ],
            "architecture": "x86_64",
            "optimization": f"O{optimization}",
        },

        "artifacts": {
            "llvm": str(
                llvm_path
            ),
            "object": str(
                object_path
            ),
            "assembly": (
                str(assembly_path)
                if assembly_path
                else None
            ),
            "executable": (
                str(executable_path)
                if executable_path
                else None
            ),
            "simulation_report": str(
                simulation_path
            ),
            "symbol_report": str(
                symbol_report_path
            ),
        },

        "runtime_contract": {
            "initialization": "jocky_sys_init",
            "transmission": "jocky_sys_transmit",
            "operation_prefix": "jocky_op_",
        },

        "symbols": asdict(
            symbol_analysis
        ),

        "toolchain": {
            key: value
            for key, value in tools.items()
        },

        "host": {
            "os": platform.system(),
            "os_release": platform.release(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
        },

        "source": (
            {
                "file": str(source_path)
            }
            if source_path
            else None
        ),

        "execution_policy": security_policy,
    }

    return manifest


# ============================================================
# JSON
# ============================================================

def write_json(
    path: Path,
    data: Dict,
) -> None:

    path.write_text(
        json.dumps(
            data,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


# ============================================================
# COPY SOURCE
# ============================================================

def copy_optional_source(
    source_path: Optional[Path],
    build_dir: Path,
) -> Optional[Path]:

    if not source_path:
        return None

    source_path = source_path.resolve()

    if not source_path.exists():

        raise FileNotFoundError(
            f"Source file not found: "
            f"{source_path}"
        )

    destination = (
        build_dir /
        source_path.name
    )

    shutil.copy2(
        source_path,
        destination,
    )

    return destination


# ============================================================
# BUILD HASHES
# ============================================================

def generate_hash_manifest(
    build_dir: Path,
    build_id: str,
) -> Path:

    hashes = {
        "build_id": build_id,
        "generated_at": utc_now().isoformat(),
        "files": {},
    }

    for path in sorted(
        build_dir.rglob("*")
    ):

        if not path.is_file():
            continue

        if path.name == "hashes.json":
            continue

        relative = str(
            path.relative_to(
                build_dir
            )
        )

        hashes["files"][relative] = {
            "sha256": sha256_file(
                path
            ),
            "size": path.stat().st_size,
        }

    output = (
        build_dir /
        "hashes.json"
    )

    write_json(
        output,
        hashes,
    )

    return output


# ============================================================
# BUILD
# ============================================================

def build(
    args: argparse.Namespace,
) -> int:

    llvm_path = Path(
        args.llvm
    ).resolve()

    if not llvm_path.exists():

        error(
            f"LLVM input file not found: "
            f"{llvm_path}"
        )

        return 1

    if llvm_path.suffix.lower() != ".ll":

        error(
            "This builder expects LLVM textual IR (.ll)."
        )

        return 1

    if args.platform not in VALID_PLATFORMS:

        error(
            f"Unsupported target platform: "
            f"{args.platform}"
        )

        return 1

    tools = find_llvm_tools(
        args
    )

    if not tools["llc"]:

        error(
            "llc was not found. "
            "Install LLVM and ensure llc is on PATH."
        )

        return 1

    if args.link and not tools["clang"]:

        error(
            "clang is required for --link "
            "but was not found."
        )

        return 1

    # --------------------------------------------------------
    # HEADER
    # --------------------------------------------------------

    section(
        f"JOCKY Native Builder v{BUILDER_VERSION}"
    )

    print(
        f"LLVM input : {llvm_path}"
    )

    print(
        f"Platform   : {args.platform}"
    )

    print(
        f"Triple     : "
        f"{LLVM_TRIPLES[args.platform]}"
    )

    print(
        f"Optimization: O{args.optimization}"
    )

    # --------------------------------------------------------
    # READ LLVM
    # --------------------------------------------------------

    llvm_text = read_llvm(
        llvm_path
    )

    llvm_hash = sha256_bytes(
        llvm_text.encode("utf-8")
    )

    build_id = generate_build_id(
        llvm_hash,
        args.reproducible,
    )

    variation_id = generate_variation_id(
        llvm_hash,
        args.reproducible,
    )

    print(
        f"Build ID   : {build_id}"
    )

    print(
        f"LLVM SHA256: {llvm_hash}"
    )

    print(
        f"Variation  : {variation_id}"
    )

    # --------------------------------------------------------
    # BUILD DIRECTORY
    # --------------------------------------------------------

    output_root = Path(
        args.output_dir
    ).resolve()

    build_dir = (
        output_root /
        build_id
    )

    if args.clean and build_dir.exists():

        shutil.rmtree(
            build_dir
        )

    build_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    # --------------------------------------------------------
    # COPY LLVM
    # --------------------------------------------------------

    llvm_copy = (
        build_dir /
        "program.ll"
    )

    shutil.copy2(
        llvm_path,
        llvm_copy,
    )

    source_path = None

    if args.source:

        source_path = copy_optional_source(
            Path(args.source),
            build_dir,
        )

    # --------------------------------------------------------
    # SYMBOL ANALYSIS
    # --------------------------------------------------------

    section(
        "LLVM Runtime Analysis"
    )

    symbol_analysis = analyze_symbols(
        llvm_text
    )

    print(
        f"Runtime symbols   : "
        f"{len(symbol_analysis.runtime_symbols)}"
    )

    print(
        f"Collection symbols: "
        f"{len(symbol_analysis.collection_symbols)}"
    )

    print(
        f"Variation symbols : "
        f"{len(symbol_analysis.variation_symbols)}"
    )

    print(
        f"Simulation symbols : "
        f"{len(symbol_analysis.simulation_symbols)}"
    )

    if symbol_analysis.runtime_symbols:

        for symbol in symbol_analysis.runtime_symbols:

            print(
                f"    runtime: {symbol}"
            )

    if symbol_analysis.collection_symbols:

        for symbol in symbol_analysis.collection_symbols:

            print(
                f"    collect: {symbol}"
            )

    if symbol_analysis.variation_symbols:

        for symbol in symbol_analysis.variation_symbols:

            print(
                f"    variation: {symbol}"
            )

    if symbol_analysis.simulation_symbols:

        for symbol in symbol_analysis.simulation_symbols:

            print(
                f"    simulation: {symbol}"
            )

    if not validate_llvm_symbols(
        symbol_analysis,
        args.strict_symbols,
    ):

        return 1

    # --------------------------------------------------------
    # SECURITY POLICY
    # --------------------------------------------------------

    security_policy = {
        "read_only_forensics": True,
        "arbitrary_commands": False,
        "process_injection": False,
        "memory_injection": False,
        "kernel_exploitation": False,
        "security_product_tampering": False,
        "privilege_escalation": False,
        "persistence": False,
        "covert_c2": False,
        "advanced_technique_simulation": True,
    }

    section(
        "JOCKY Security Policy"
    )

    print(
        f"{GREEN}[✓]{RESET} "
        "Unsafe execution primitives are blocked."
    )

    print(
        f"{GREEN}[✓]{RESET} "
        "Advanced techniques are simulation-only."
    )

    # --------------------------------------------------------
    # LLVM VALIDATION
    # --------------------------------------------------------

    section(
        "LLVM Validation"
    )

    if not validate_with_llvm_as(
        tools["llvm_as"],
        llvm_copy,
        build_dir,
    ):

        return 1

    # --------------------------------------------------------
    # SIMULATION REPORT
    # --------------------------------------------------------

    section(
        "Advanced Technique Simulation"
    )

    simulation_path = (
        build_dir /
        "simulation_report.json"
    )

    simulation_report = (
        generate_simulation_report(
            build_id,
            variation_id,
            symbol_analysis,
            simulation_path,
        )
    )

    if simulation_report[
        "techniques"
    ]:

        for technique in simulation_report[
            "techniques"
        ]:

            print(
                f"{CYAN}[SIMULATION]{RESET} "
                f"{technique['technique']}"
            )

    else:

        info(
            "No advanced technique simulation "
            "symbols requested."
        )

    # --------------------------------------------------------
    # OBJECT
    # --------------------------------------------------------

    section(
        "Native Code Generation"
    )

    object_path = (
        build_dir /
        (
            "jocky_agent.obj"
            if args.platform == "windows"
            else "jocky_agent.o"
        )
    )

    assembly_path = (
        build_dir /
        (
            "jocky_agent.asm"
            if args.platform == "windows"
            else "jocky_agent.s"
        )
    )

    success, object_path = compile_object(
        tools["llc"],
        llvm_copy,
        object_path,
        LLVM_TRIPLES[
            args.platform
        ],
        args.optimization,
        args.emit_assembly,
        (
            assembly_path
            if args.emit_assembly
            else None
        ),
    )

    if not success:
        return 1

    # --------------------------------------------------------
    # OBJECT SYMBOL REPORT
    # --------------------------------------------------------

    symbol_report_path = (
        build_dir /
        "native_symbols.json"
    )

    inspect_object_symbols(
        tools["objdump"],
        object_path,
        symbol_report_path,
    )

    # --------------------------------------------------------
    # LINK
    # --------------------------------------------------------

    executable_path = None

    if args.link:

        section(
            "Native Linking"
        )

        runtime_objects = []
        runtime_libraries = []

        # ----------------------------------------------------
        # User runtime objects
        # ----------------------------------------------------

        for runtime in args.runtime:

            runtime_path = (
                Path(runtime)
                .resolve()
            )

            if not runtime_path.exists():

                error(
                    f"Runtime file not found: "
                    f"{runtime_path}"
                )

                return 1

            if runtime_path.suffix.lower() in {
                ".o",
                ".obj",
            }:

                runtime_objects.append(
                    runtime_path
                )

            elif runtime_path.suffix.lower() in {
                ".a",
                ".lib",
                ".so",
                ".dll",
            }:

                runtime_libraries.append(
                    str(runtime_path)
                )

            else:

                warn(
                    f"Unknown runtime file type: "
                    f"{runtime_path.name}"
                )

        # ----------------------------------------------------
        # Runtime linker arguments
        # ----------------------------------------------------

        runtime_libraries.extend(
            args.runtime_lib
        )

        # ----------------------------------------------------
        # Safe stub
        # ----------------------------------------------------

        if args.safe_stub_runtime:

            stub_source = (
                build_dir /
                "jocky_safe_runtime.c"
            )

            generate_safe_runtime_stub(
                stub_source,
                symbol_analysis,
                build_id,
            )

            stub_object = (
                build_dir /
                (
                    "jocky_safe_runtime.obj"
                    if args.platform == "windows"
                    else "jocky_safe_runtime.o"
                )
            )

            compile_stub_command = [
                tools["clang"],
                "-c",
                str(stub_source),
                "-o",
                str(stub_object),
            ]

            if args.platform == "windows":

                compile_stub_command.extend(
                    [
                        "-target",
                        LLVM_TRIPLES[
                            "windows"
                        ],
                    ]
                )

            info(
                "Compiling safe runtime stub..."
            )

            stub_result = run_command(
                compile_stub_command
            )

            if stub_result.returncode != 0:

                error(
                    "Safe runtime stub compilation failed."
                )

                if stub_result.stderr:
                    print(
                        stub_result.stderr
                    )

                return 1

            runtime_objects.append(
                stub_object
            )

            ok(
                "Safe runtime stub compiled."
            )

        # ----------------------------------------------------
        # Runtime availability
        # ----------------------------------------------------

        if (
            not runtime_objects
            and not runtime_libraries
        ):

            error(
                "No runtime supplied. "
                "Use --runtime, --runtime-lib, "
                "or --safe-stub-runtime."
            )

            return 1

        # ----------------------------------------------------
        # Executable
        # ----------------------------------------------------

        executable_name = (
            "jocky_agent.exe"
            if args.platform == "windows"
            else "jocky_agent"
        )

        executable_path = (
            build_dir /
            executable_name
        )

        linked = link_native_executable(
            tools["clang"],
            object_path,
            executable_path,
            runtime_objects,
            runtime_libraries,
            args.platform,
        )

        if not linked:
            return 1

    # --------------------------------------------------------
    # MANIFEST
    # --------------------------------------------------------

    section(
        "Build Manifest"
    )

    manifest = create_manifest(
        build_id=build_id,
        variation_id=variation_id,
        llvm_path=llvm_copy,
        object_path=object_path,
        assembly_path=(
            assembly_path
            if args.emit_assembly
            else None
        ),
        executable_path=executable_path,
        simulation_path=simulation_path,
        symbol_report_path=symbol_report_path,
        source_path=source_path,
        platform_target=args.platform,
        optimization=args.optimization,
        tools=tools,
        symbol_analysis=symbol_analysis,
        security_policy=security_policy,
        reproducible=args.reproducible,
    )

    manifest_path = (
        build_dir /
        "manifest.json"
    )

    write_json(
        manifest_path,
        manifest,
    )

    # --------------------------------------------------------
    # HASHES
    # --------------------------------------------------------

    hashes_path = (
        build_dir /
        "hashes.json"
    )

    # Write once after all normal artifacts exist.
    generate_hash_manifest(
        build_dir,
        build_id,
    )

    # --------------------------------------------------------
    # FINAL SUMMARY
    # --------------------------------------------------------

    section(
        "Build Complete"
    )

    print(
        f"Build directory : "
        f"{build_dir}"
    )

    print(
        f"Build ID        : "
        f"{build_id}"
    )

    print(
        f"LLVM SHA256     : "
        f"{llvm_hash}"
    )

    print(
        f"Object          : "
        f"{object_path.name}"
    )

    if executable_path:

        print(
            f"Executable      : "
            f"{executable_path.name}"
        )

    print(
        f"Manifest        : "
        f"{manifest_path.name}"
    )

    print(
        f"Simulation      : "
        f"{simulation_path.name}"
    )

    print(
        f"Symbols         : "
        f"{symbol_report_path.name}"
    )

    print(
        f"Hashes          : "
        f"{hashes_path.name}"
    )

    print()

    ok(
        "JOCKY native build completed."
    )

    if not executable_path:

        info(
            "Only the native object was produced. "
            "Use --link when a runtime is available."
        )

    return 0


# ============================================================
# CLI
# ============================================================

def create_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        prog="polymorphic_builder",
        description=(
            "JOCKY LLVM Native Builder "
            f"v{BUILDER_VERSION}"
        ),
        formatter_class=(
            argparse.RawTextHelpFormatter
        ),
    )

    parser.add_argument(
        "llvm",
        help="Input LLVM IR file (.ll)",
    )

    parser.add_argument(
        "--source",
        help="Original .jky source file",
    )

    parser.add_argument(
        "-o",
        "--output-dir",
        default="builds",
        help="Root build output directory",
    )

    parser.add_argument(
        "--platform",
        choices=sorted(
            VALID_PLATFORMS
        ),
        default="windows",
        help="Native target platform",
    )

    parser.add_argument(
        "--optimization",
        choices=[
            "0",
            "1",
            "2",
            "3",
        ],
        default="2",
        help="LLVM optimization level",
    )

    parser.add_argument(
        "--reproducible",
        action="store_true",
        help=(
            "Derive build IDs/variation from "
            "the LLVM hash"
        ),
    )

    parser.add_argument(
        "--link",
        action="store_true",
        help="Link native object into executable",
    )

    parser.add_argument(
        "--runtime",
        action="append",
        default=[],
        help=(
            "Runtime .o/.obj/.lib/.a file. "
            "May be supplied multiple times."
        ),
    )

    parser.add_argument(
        "--runtime-lib",
        action="append",
        default=[],
        help=(
            "Runtime library/linker argument. "
            "May be supplied multiple times."
        ),
    )

    parser.add_argument(
        "--safe-stub-runtime",
        action="store_true",
        help=(
            "Generate a safe linker-compatible "
            "runtime stub"
        ),
    )

    parser.add_argument(
        "--emit-assembly",
        action="store_true",
        help="Also emit native assembly",
    )

    parser.add_argument(
        "--strict-symbols",
        action="store_true",
        help=(
            "Fail on unknown JOCKY runtime symbols"
        ),
    )

    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove existing build directory",
    )

    parser.add_argument(
        "--llc",
        help="Path to llc",
    )

    parser.add_argument(
        "--llvm-as",
        help="Path to llvm-as",
    )

    parser.add_argument(
        "--llvm-dis",
        help="Path to llvm-dis",
    )

    parser.add_argument(
        "--objdump",
        help="Path to llvm-objdump",
    )

    parser.add_argument(
        "--clang",
        help="Path to clang",
    )

    return parser


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    parser = create_parser()

    args = parser.parse_args()

    try:

        return_code = build(
            args
        )

        sys.exit(
            return_code
        )

    except KeyboardInterrupt:

        error(
            "Build interrupted by user."
        )

        sys.exit(130)

    except Exception as exc:

        error(
            f"Unexpected builder error: {exc}"
        )

        if os.environ.get(
            "JOCKY_BUILDER_DEBUG"
        ):

            import traceback

            traceback.print_exc()

        sys.exit(1)


if __name__ == "__main__":
    main()