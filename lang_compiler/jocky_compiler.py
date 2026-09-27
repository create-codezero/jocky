#!/usr/bin/env python3
"""
JOCKY Compiler - True LLVM Frontend
===================================

High-level JOCKY (.jky) forensic language
        ->
AST / semantic validation
        ->
LLVM IR (.ll)
        ->
Rust JOCKY runtime static library
        ->
native executable

Design goals:
- Read-only forensic operations
- Explicit runtime symbol contract
- Host/task metadata preservation
- Correlation-rule embedding
- Reproducible build metadata
- Safe polymorphic execution-sequence variation
"""

import sys
import json
import argparse
import re
import random
import hashlib
import secrets
from pathlib import Path
from difflib import get_close_matches

try:
    from llvmlite import ir
except ImportError:
    print(
        "\n\033[91m\033[1merror\033[0m: llvmlite is not installed. "
        "Run: pip install llvmlite"
    )
    sys.exit(1)


# ============================================================
# VERSION / COLORS
# ============================================================

COMPILER_VERSION = "2.1.0"

GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"


# ============================================================
# FORENSIC ARTIFACTS
# ============================================================

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


# These are intentionally simulation-only operations.
SIMULATION_OPERATIONS = [
    "SIMULATE_SLEEP_OBFUSCATE",
    "SIMULATE_MATH_ENTROPY",
    "SIMULATE_MEMORY_ALLOC_FREE",
    "SIMULATE_ENV_QUERY",
]


ALL_RUNTIME_OPERATIONS = VALID_ARTIFACTS | set(SIMULATION_OPERATIONS)


# ============================================================
# LEXER
# ============================================================

TOKEN_SPECIFICATION = [
    ("COMMENT", r"//.*"),
    (
        "KEYWORD",
        r"\b(host|collect|detect|if|alert|severity|risk_score)\b",
    ),
    ("OPERATOR", r"(==|!=|>=|<=|>|<)"),
    ("ASSIGN", r"="),
    ("NUMBER", r"\b\d+\b"),
    ("STRING", r'"[^"]*"'),
    ("IDENTIFIER", r"[a-zA-Z_][a-zA-Z0-9_\.]*"),
    ("LBRACE", r"\{"),
    ("RBRACE", r"\}"),
    ("WHITESPACE", r"[ \t]+"),
    ("NEWLINE", r"\r?\n"),
    ("MISMATCH", r"."),
]


class Token:
    def __init__(self, kind, value, line, col):
        self.kind = kind
        self.value = value
        self.line = line
        self.col = col


def lex(code, filename="<stdin>"):
    tok_regex = "|".join(
        f"(?P<{pair[0]}>{pair[1]})"
        for pair in TOKEN_SPECIFICATION
    )

    tokens = []
    line_num = 1
    line_start = 0

    for match in re.finditer(tok_regex, code):
        kind = match.lastgroup
        value = match.group()

        col = match.start() - line_start + 1

        if kind == "NEWLINE":
            line_num += 1
            line_start = match.end()
            continue

        if kind in ("WHITESPACE", "COMMENT"):
            continue

        if kind == "MISMATCH":
            show_compiler_error(
                filename,
                code,
                line_num,
                col,
                f"Unrecognized character '{value}'",
            )
            sys.exit(1)

        if kind == "STRING":
            value = value[1:-1]

        elif kind == "NUMBER":
            value = int(value)

        tokens.append(
            Token(
                kind=kind,
                value=value,
                line=line_num,
                col=col,
            )
        )

    return tokens


# ============================================================
# ERROR REPORTING
# ============================================================

def show_compiler_error(
    filename,
    source,
    line,
    col,
    message,
    suggestion=None,
):
    lines = source.splitlines()

    error_line = (
        lines[line - 1]
        if 0 < line <= len(lines)
        else ""
    )

    print(
        f"\n{RED}{BOLD}jocky error{RESET}: {message}"
    )

    print(
        f"  --> {filename}:{line}:{col}"
    )

    print("   |")
    print(f"{line:3d}| {error_line}")
    print(
        f"   | {' ' * max(0, col - 1)}{RED}^{RESET}"
    )

    if suggestion:
        print(
            f"{CYAN}   = help{RESET}: {suggestion}"
        )

    print()


# ============================================================
# PARSER
# ============================================================

class Parser:

    def __init__(self, tokens, source, filename):
        self.tokens = tokens
        self.source = source
        self.filename = filename
        self.pos = 0

    def current_token(self):
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]

        return None

    def consume(
        self,
        expected_kind=None,
        expected_value=None,
    ):
        token = self.current_token()

        if token is None:
            line = (
                self.tokens[-1].line
                if self.tokens
                else 1
            )

            show_compiler_error(
                self.filename,
                self.source,
                line,
                1,
                (
                    "Unexpected end of file, "
                    f"expected {expected_kind or expected_value}"
                ),
            )

            sys.exit(1)

        if expected_kind and token.kind != expected_kind:
            show_compiler_error(
                self.filename,
                self.source,
                token.line,
                token.col,
                (
                    f"Expected token type '{expected_kind}', "
                    f"found '{token.kind}' ('{token.value}')"
                ),
            )

            sys.exit(1)

        if expected_value and token.value != expected_value:
            show_compiler_error(
                self.filename,
                self.source,
                token.line,
                token.col,
                (
                    f"Expected keyword '{expected_value}', "
                    f"found '{token.value}'"
                ),
            )

            sys.exit(1)

        self.pos += 1

        return token

    def parse(self):
        ast = {
            "hosts": [],
            "detections": [],
        }

        while self.current_token():

            token = self.current_token()

            if (
                token.kind == "KEYWORD"
                and token.value == "host"
            ):
                ast["hosts"].append(
                    self.parse_host_block()
                )

            elif (
                token.kind == "KEYWORD"
                and token.value == "detect"
            ):
                ast["detections"].extend(
                    self.parse_detect_block()
                )

            else:
                show_compiler_error(
                    self.filename,
                    self.source,
                    token.line,
                    token.col,
                    (
                        "Statements must start with "
                        "'host' or 'detect'. "
                        f"Found '{token.value}'"
                    ),
                )

                sys.exit(1)

        return ast

    def parse_host_block(self):

        self.consume(
            "KEYWORD",
            "host",
        )

        target_host = self.consume(
            "STRING"
        ).value

        self.consume("LBRACE")

        commands = []

        while (
            self.current_token()
            and self.current_token().kind != "RBRACE"
        ):

            self.consume(
                "KEYWORD",
                "collect",
            )

            artifact_token = self.consume(
                "IDENTIFIER"
            )

            artifact_name = artifact_token.value

            if artifact_name not in VALID_ARTIFACTS:

                matches = get_close_matches(
                    artifact_name,
                    VALID_ARTIFACTS,
                    n=1,
                    cutoff=0.6,
                )

                suggestion = (
                    f"Did you mean '{matches[0]}'?"
                    if matches
                    else
                    "Check supported collectors reference."
                )

                show_compiler_error(
                    self.filename,
                    self.source,
                    artifact_token.line,
                    artifact_token.col,
                    (
                        "Unknown forensic artifact: "
                        f"\"{artifact_name}\""
                    ),
                    suggestion,
                )

                sys.exit(1)

            commands.append(
                {
                    "op": artifact_name,
                }
            )

        self.consume("RBRACE")

        return {
            "target": target_host,
            "collections": commands,
        }

    def parse_detect_block(self):

        self.consume(
            "KEYWORD",
            "detect",
        )

        self.consume("LBRACE")

        rules = []

        while (
            self.current_token()
            and self.current_token().kind != "RBRACE"
        ):

            self.consume(
                "KEYWORD",
                "if",
            )

            field = self.consume(
                "IDENTIFIER"
            ).value

            operator = self.consume(
                "OPERATOR"
            ).value

            value_token = self.consume()

            rule = {
                "condition": {
                    "field": field,
                    "operator": operator,
                    "value": value_token.value,
                },
                "alert": None,
                "severity": "MEDIUM",
                "risk_score": 10,
            }

            while (
                self.current_token()
                and self.current_token().value
                in (
                    "alert",
                    "severity",
                    "risk_score",
                )
            ):

                action_type = self.consume(
                    "KEYWORD"
                ).value

                if action_type == "alert":

                    rule["alert"] = self.consume(
                        "STRING"
                    ).value

                elif action_type == "severity":

                    severity = self.consume(
                        "IDENTIFIER"
                    ).value.upper()

                    if severity not in {
                        "LOW",
                        "MEDIUM",
                        "HIGH",
                        "CRITICAL",
                    }:
                        show_compiler_error(
                            self.filename,
                            self.source,
                            self.tokens[self.pos - 1].line,
                            self.tokens[self.pos - 1].col,
                            (
                                f"Unknown severity '{severity}'. "
                                "Use LOW, MEDIUM, HIGH or CRITICAL."
                            ),
                        )

                        sys.exit(1)

                    rule["severity"] = severity

                elif action_type == "risk_score":

                    score = self.consume(
                        "NUMBER"
                    ).value

                    if not 0 <= score <= 100:
                        show_compiler_error(
                            self.filename,
                            self.source,
                            self.tokens[self.pos - 1].line,
                            self.tokens[self.pos - 1].col,
                            "risk_score must be between 0 and 100.",
                        )

                        sys.exit(1)

                    rule["risk_score"] = score

            rules.append(rule)

        self.consume("RBRACE")

        return rules


# ============================================================
# SEMANTIC VALIDATION
# ============================================================

def validate_ast(ast):

    if not ast["hosts"]:
        print(
            f"{YELLOW}[warning]{RESET}: "
            "No host blocks were defined."
        )

    for host in ast["hosts"]:

        target = host.get("target")

        if not target:
            raise ValueError(
                "Host target cannot be empty."
            )

        if not host["collections"]:
            print(
                f"{YELLOW}[warning]{RESET}: "
                f"Host '{target}' has no collectors."
            )

    for rule in ast["detections"]:

        condition = rule["condition"]

        if not condition["field"]:
            raise ValueError(
                "Detection rule field cannot be empty."
            )

        if condition["operator"] not in {
            "==",
            "!=",
            ">",
            "<",
            ">=",
            "<=",
        }:
            raise ValueError(
                f"Unsupported operator: "
                f"{condition['operator']}"
            )


# ============================================================
# POLYMORPHIC EXECUTION-SEQUENCE VARIATION
# ============================================================

def inject_execution_variation(
    base_tasks,
    intensity=0.4,
):
    """
    Adds safe simulation-only operations around
    forensic collection operations.

    This intentionally does NOT implement evasion,
    injection, bypass, persistence, or stealth behavior.
    """

    result = []

    for task in base_tasks:

        if random.random() < intensity:
            result.append(
                {
                    "op": random.choice(
                        SIMULATION_OPERATIONS
                    ),
                    "simulation": True,
                }
            )

        result.append(task)

        if random.random() < intensity:
            result.append(
                {
                    "op": random.choice(
                        SIMULATION_OPERATIONS
                    ),
                    "simulation": True,
                }
            )

    return result


# ============================================================
# LLVM STRING CONSTANT HELPER
# ============================================================

def make_llvm_string_constant(module, name, value):
    """
    Creates a null-terminated LLVM global string.
    """

    data = value.encode("utf-8") + b"\x00"

    array_type = ir.ArrayType(
        ir.IntType(8),
        len(data),
    )

    global_value = ir.GlobalVariable(
        module,
        array_type,
        name=name,
    )

    global_value.global_constant = True

    # Keep externally visible so the generated program can
    # expose metadata to the linked runtime if required.
    global_value.linkage = "external"

    global_value.initializer = ir.Constant(
        array_type,
        bytearray(data),
    )

    return global_value


# ============================================================
# TASK EXTRACTION
# ============================================================

def build_tasks(ast):

    tasks = []

    for host in ast["hosts"]:

        target = host["target"]

        for collection in host["collections"]:

            tasks.append(
                {
                    "target": target,
                    "op": collection["op"],
                    "simulation": False,
                }
            )

    return tasks


# ============================================================
# LLVM IR GENERATOR
# ============================================================

def generate_llvm_ir(
    ast,
    platform_target,
    polymorphic=True,
):

    build_seed = secrets.token_hex(8)

    base_tasks = build_tasks(ast)

    if polymorphic:

        random.seed(build_seed)

        final_tasks = inject_execution_variation(
            base_tasks,
            intensity=0.40,
        )

    else:

        final_tasks = base_tasks

    # --------------------------------------------------------
    # LLVM MODULE
    # --------------------------------------------------------

    module = ir.Module(
        name="jocky_payload"
    )

    if platform_target == "windows":

        module.triple = (
            "x86_64-pc-windows-msvc"
        )

    else:

        module.triple = (
            "x86_64-unknown-linux-gnu"
        )

    # --------------------------------------------------------
    # RUNTIME FUNCTION DECLARATIONS
    # --------------------------------------------------------

    void_type = ir.VoidType()

    void_fn_type = ir.FunctionType(
        void_type,
        [],
    )

    declared_functions = {}

    for task in final_tasks:

        operation = task["op"]

        if operation not in declared_functions:

            runtime_name = (
                f"jocky_op_{operation}"
            )

            declared_functions[operation] = (
                ir.Function(
                    module,
                    void_fn_type,
                    name=runtime_name,
                )
            )

    init_function = ir.Function(
        module,
        void_fn_type,
        name="jocky_sys_init",
    )

    transmit_function = ir.Function(
        module,
        void_fn_type,
        name="jocky_sys_transmit",
    )

    # --------------------------------------------------------
    # NATIVE MAIN
    # --------------------------------------------------------

    main_type = ir.FunctionType(
        ir.IntType(32),
        [],
    )

    main_function = ir.Function(
        module,
        main_type,
        name="main",
    )

    entry = main_function.append_basic_block(
        name="entry"
    )

    builder = ir.IRBuilder(entry)

    # Runtime initialization
    builder.call(
        init_function,
        [],
    )

    # --------------------------------------------------------
    # TASK EXECUTION
    # --------------------------------------------------------

    for task in final_tasks:

        operation = task["op"]

        function = declared_functions[
            operation
        ]

        builder.call(
            function,
            [],
        )

    # --------------------------------------------------------
    # TRANSMISSION
    # --------------------------------------------------------

    builder.call(
        transmit_function,
        [],
    )

    builder.ret(
        ir.Constant(
            ir.IntType(32),
            0,
        )
    )

    # ========================================================
    # CORRELATION RULES
    # ========================================================

    correlation_rules = []

    for rule in ast["detections"]:

        correlation_rules.append(
            {
                "field": rule["condition"]["field"],
                "operator": rule["condition"]["operator"],
                "value": rule["condition"]["value"],
                "alert": rule["alert"],
                "severity": rule["severity"],
                "score_impact": rule["risk_score"],
            }
        )

    rules_json = json.dumps(
        correlation_rules,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    rules_bytes = (
        rules_json.encode("utf-8")
        + b"\x00"
    )

    rules_type = ir.ArrayType(
        ir.IntType(8),
        len(rules_bytes),
    )

    correlation_global = ir.GlobalVariable(
        module,
        rules_type,
        name="JOCKY_CORRELATION_RULES",
    )

    correlation_global.global_constant = True

    # FIXED: Commented out linkage = "external" to prevent llvm-as initializer conflict
    # correlation_global.linkage = "external"

    correlation_global.initializer = ir.Constant(
        rules_type,
        bytearray(rules_bytes),
    )

    # ========================================================
    # BUILD METADATA
    # ========================================================

    metadata = {
        "compiler": "JOCKY LLVM Frontend",
        "compiler_version": COMPILER_VERSION,
        "llvm_module": "jocky_payload",
        "platform": platform_target,
        "build_seed": build_seed,
        "polymorphic_execution_variation": polymorphic,
        "base_task_count": len(base_tasks),
        "final_task_count": len(final_tasks),
        "correlation_rule_count": len(
            correlation_rules
        ),
        "security_mode": "READ_ONLY_FORENSICS",
        "arbitrary_command_execution": False,
        "process_injection": False,
        "security_product_tampering": False,
        "privilege_escalation": False,
        "persistence": False,
        "covert_network_routing": False,
    }

    metadata_json = json.dumps(
        metadata,
        separators=(",", ":"),
    )

    metadata_bytes = (
        metadata_json.encode("utf-8")
        + b"\x00"
    )

    metadata_type = ir.ArrayType(
        ir.IntType(8),
        len(metadata_bytes),
    )

    metadata_global = ir.GlobalVariable(
        module,
        metadata_type,
        name="JOCKY_BUILD_METADATA",
    )

    metadata_global.global_constant = True
    # metadata_global.linkage = "external"

    metadata_global.initializer = ir.Constant(
        metadata_type,
        bytearray(metadata_bytes),
    )

    # ========================================================
    # TASK METADATA
    # ========================================================

    task_metadata = []

    for index, task in enumerate(final_tasks):

        task_metadata.append(
            {
                "index": index,
                "operation": task["op"],
                "target": task.get("target"),
                "simulation": bool(
                    task.get("simulation", False)
                ),
            }
        )

    task_metadata_json = json.dumps(
        task_metadata,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    task_metadata_bytes = (
        task_metadata_json.encode("utf-8")
        + b"\x00"
    )

    task_metadata_type = ir.ArrayType(
        ir.IntType(8),
        len(task_metadata_bytes),
    )

    task_metadata_global = ir.GlobalVariable(
        module,
        task_metadata_type,
        name="JOCKY_TASK_METADATA",
    )

    task_metadata_global.global_constant = True
    # task_metadata_global.linkage = "external"

    task_metadata_global.initializer = ir.Constant(
        task_metadata_type,
        bytearray(task_metadata_bytes),
    )

    return (
        str(module),
        len(base_tasks),
        len(final_tasks),
        len(correlation_rules),
        build_seed,
    )


# ============================================================
# FILE HASHING
# ============================================================

def sha256_text(value):
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


# ============================================================
# WRITE BUILD MANIFEST
# ============================================================

def write_manifest(
    path,
    source_path,
    llvm_path,
    llvm_text,
    ast,
    platform,
    build_seed,
    base_task_count,
    final_task_count,
    rule_count,
):

    source_text = Path(
        source_path
    ).read_text(
        encoding="utf-8"
    )

    manifest = {
        "schema_version": "2.1",
        "compiler": {
            "name": "JOCKY LLVM Frontend",
            "version": COMPILER_VERSION,
        },
        "source": {
            "file": str(
                Path(source_path).resolve()
            ),
            "sha256": sha256_text(
                source_text
            ),
        },
        "llvm": {
            "file": str(
                Path(llvm_path).resolve()
            ),
            "sha256": sha256_text(
                llvm_text
            ),
        },
        "target": {
            "platform": platform,
            "architecture": "x86_64",
        },
        "build": {
            "seed": build_seed,
            "polymorphic_execution_variation": True,
        },
        "statistics": {
            "hosts": len(ast["hosts"]),
            "base_tasks": base_task_count,
            "final_tasks": final_task_count,
            "correlation_rules": rule_count,
        },
        "runtime_contract": {
            "init": "jocky_sys_init",
            "transmit": "jocky_sys_transmit",
            "operation_prefix": "jocky_op_",
        },
        "security_policy": {
            "read_only_forensics": True,
            "arbitrary_command_execution": False,
            "process_injection": False,
            "security_product_tampering": False,
            "privilege_escalation": False,
            "persistence": False,
            "covert_network_routing": False,
        },
    }

    Path(path).write_text(
        json.dumps(
            manifest,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )


# ============================================================
# CLI
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        prog="jocky_compiler",
        description=(
            "JOCKY Native LLVM Frontend "
            f"v{COMPILER_VERSION}"
        ),
    )

    parser.add_argument(
        "file",
        help="Path to .jky forensic script",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="output.ll",
        help="Output LLVM IR file",
    )

    parser.add_argument(
        "--platform",
        choices=[
            "windows",
            "linux",
        ],
        default="windows",
        help="Target operating system",
    )

    parser.add_argument(
        "--no-obfuscation",
        action="store_true",
        help=(
            "Disable safe polymorphic "
            "execution-sequence variation"
        ),
    )

    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Validate syntax and semantics "
            "without generating LLVM"
        ),
    )

    parser.add_argument(
        "--manifest",
        help=(
            "Optional compiler manifest output path"
        ),
    )

    args = parser.parse_args()

    source_path = Path(args.file)

    if not source_path.exists():

        print(
            f"{RED}{BOLD}error{RESET}: "
            f"File not found: {args.file}"
        )

        sys.exit(1)

    print(
        f"\n{BOLD}"
        "JOCKY Compiler Frontend "
        "(True LLVM Engine)"
        f"{RESET}"
    )

    print("=" * 55)

    source = source_path.read_text(
        encoding="utf-8"
    )

    # --------------------------------------------------------
    # LEX
    # --------------------------------------------------------

    tokens = lex(
        source,
        str(source_path),
    )

    print(
        f"{GREEN}[✓]{RESET} "
        f"Lexed {len(tokens)} tokens"
    )

    # --------------------------------------------------------
    # PARSE
    # --------------------------------------------------------

    ast = Parser(
        tokens,
        source,
        str(source_path),
    ).parse()

    # --------------------------------------------------------
    # SEMANTIC VALIDATION
    # --------------------------------------------------------

    try:
        validate_ast(ast)

    except ValueError as exc:

        print(
            f"\n{RED}{BOLD}semantic error{RESET}: "
            f"{exc}\n"
        )

        sys.exit(1)

    print(
        f"{GREEN}[✓]{RESET} "
        "AST and semantic validation passed"
    )

    # --------------------------------------------------------
    # CHECK MODE
    # --------------------------------------------------------

    if args.check:

        print(
            f"{GREEN}[✓]{RESET} "
            f"Validation successful: {args.file}"
        )

        return

    # --------------------------------------------------------
    # LLVM GENERATION
    # --------------------------------------------------------

    (
        llvm_ir,
        base_count,
        final_count,
        rule_count,
        build_seed,
    ) = generate_llvm_ir(
        ast,
        platform_target=args.platform,
        polymorphic=(
            not args.no_obfuscation
        ),
    )

    output_path = Path(
        args.output
    )

    output_path.write_text(
        llvm_ir,
        encoding="utf-8",
    )

    # --------------------------------------------------------
    # HASH
    # --------------------------------------------------------

    llvm_hash = sha256_text(
        llvm_ir
    )

    # --------------------------------------------------------
    # MANIFEST
    # --------------------------------------------------------

    manifest_path = (
        Path(args.manifest)
        if args.manifest
        else output_path.with_suffix(
            ".manifest.json"
        )
    )

    write_manifest(
        manifest_path,
        source_path,
        output_path,
        llvm_ir,
        ast,
        args.platform,
        build_seed,
        base_count,
        final_count,
        rule_count,
    )

    # --------------------------------------------------------
    # OUTPUT
    # --------------------------------------------------------

    print(
        f"{GREEN}[✓]{RESET} "
        f"Generated LLVM IR: "
        f"{output_path}"
    )

    print(
        f"{GREEN}[✓]{RESET} "
        f"LLVM SHA-256: {llvm_hash}"
    )

    print(
        f"{CYAN}[~]{RESET} "
        f"Hosts: {len(ast['hosts'])}"
    )

    print(
        f"{CYAN}[~]{RESET} "
        f"Base forensic tasks: {base_count}"
    )

    print(
        f"{CYAN}[~]{RESET} "
        f"Final runtime operations: {final_count}"
    )

    print(
        f"{CYAN}[~]{RESET} "
        f"Correlation rules: {rule_count}"
    )

    if not args.no_obfuscation:

        print(
            f"{CYAN}[~]{RESET} "
            "Safe polymorphic execution variation enabled"
        )

    else:

        print(
            f"{YELLOW}[~]{RESET} "
            "Polymorphic execution variation disabled"
        )

    print(
        f"{CYAN}[~]{RESET} "
        f"Build seed: {build_seed}"
    )

    print(
        f"{CYAN}[~]{RESET} "
        f"Manifest: {manifest_path}"
    )

    print(
        f"\n{CYAN}"
        "Next stage:"
        f"{RESET} "
        "polymorphic_builder.py"
    )

    print("=" * 55)
    print()


if __name__ == "__main__":
    main()