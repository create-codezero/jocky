use chrono::Utc;
use reqwest::blocking::Client;
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use std::collections::HashMap;
use std::env;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

mod obfuscation;
mod syscalls;

const RUNTIME_VERSION: &str = "2.0.0";
const POLICY_VERSION: &str = "JOCKY-SAFE-2.0";

const C2_DEFAULT: &str =
    "http://127.0.0.1:8000/api/evidence/ingest";

const MAX_ARTIFACTS: usize = 10000;

const ALLOWED_ARTIFACTS: &[&str] = &[
    "processes",
    "network_connections",
    "startup_items",
    "users",
    "services",
    "file_metadata",
    "authentication_events",
    "system_information",
];

const SIMULATION_OPERATIONS: &[&str] = &[
    "SIMULATE_SLEEP_OBFUSCATE",
    "SIMULATE_MATH_ENTROPY",
    "SIMULATE_MEMORY_ALLOC_FREE",
    "SIMULATE_ENV_QUERY",
    "PROCESS_HOLLOWING",
    "REFLECTIVE_LOADING",
    "REFLECTIVE_DLL_INJECTION",
    "THREAD_HIJACKING",
    "API_UNHOOKING",
    "DIRECT_SYSCALL",
    "IN_MEMORY_EXECUTION",
    "VULNERABLE_DRIVER",
    "BYOVD",
    "KERNEL_SUBVERSION",
    "DOMAIN_FRONTING",
    "CDN_ENCAPSULATION",
    "SOCKS5_ROUTING",
];

const BLOCKED_OPERATIONS: &[&str] = &[
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
];


// ============================================================
// GLOBAL RUNTIME STATE
// ============================================================

static RUNTIME: OnceLock<Mutex<RuntimeState>> = OnceLock::new();


#[derive(Debug)]
struct RuntimeState {
    initialized: bool,

    build_id: String,

    investigation_id: String,

    agent_id: String,

    hostname: String,

    operating_system: String,

    started_at: String,

    artifacts: Vec<ArtifactRecord>,

    simulation_events: Vec<SimulationEvent>,

    warnings: Vec<String>,

    executed_operations: Vec<String>,

    blocked_operations: Vec<String>,
}


impl RuntimeState {
    fn new() -> Self {
        Self {
            initialized: false,

            build_id: env::var("JOCKY_BUILD_ID")
                .unwrap_or_else(|_| "LLVM_BUILD_UNKNOWN".to_string()),

            investigation_id: generate_investigation_id(),

            agent_id: env::var("JOCKY_AGENT_ID")
                .unwrap_or_else(|_| generate_agent_id()),

            hostname: "unknown".to_string(),

            operating_system:
                std::env::consts::OS.to_string(),

            started_at:
                Utc::now().to_rfc3339(),

            artifacts: Vec::new(),

            simulation_events: Vec::new(),

            warnings: Vec::new(),

            executed_operations: Vec::new(),

            blocked_operations: Vec::new(),
        }
    }
}


fn runtime_state() -> &'static Mutex<RuntimeState> {
    RUNTIME.get_or_init(|| {
        Mutex::new(RuntimeState::new())
    })
}


// ============================================================
// EVIDENCE STRUCTURES
// ============================================================

#[derive(Serialize, Debug, Clone)]
struct ArtifactRecord {
    #[serde(rename = "type")]
    record_type: String,

    data: Map<String, Value>,
}


#[derive(Serialize, Debug, Clone)]
struct SimulationEvent {
    technique: String,

    execution_status: String,

    real_execution: bool,

    read_only: bool,

    evidence_generated: bool,

    timestamp: String,

    details: Map<String, Value>,
}


#[derive(Serialize, Debug)]
struct EvidenceReport {
    schema: String,

    runtime_version: String,

    policy_version: String,

    investigation_id: String,

    agent_id: String,

    build_id: String,

    timestamp: String,

    hostname: String,

    operating_system: String,

    read_only: bool,

    execution_mode: String,

    artifacts: Vec<ArtifactRecord>,

    simulations: Vec<SimulationEvent>,

    executed_operations: Vec<String>,

    blocked_operations: Vec<String>,

    warnings: Vec<String>,

    artifact_count: usize,

    report_sha256: String,
}


#[derive(Serialize, Debug)]
struct RuntimeMetadata {
    runtime_version: String,

    policy_version: String,

    read_only: bool,

    arbitrary_command_execution: bool,

    process_injection: bool,

    memory_injection: bool,

    kernel_exploitation: bool,

    security_product_tampering: bool,

    privilege_escalation: bool,

    persistence: bool,

    covert_c2: bool,

    simulation_enabled: bool,
}


// ============================================================
// IDENTIFIERS
// ============================================================

fn generate_agent_id() -> String {
    let hostname =
        hostname_fallback();

    let material = format!(
        "{}:{}:{}",
        hostname,
        std::env::consts::OS,
        std::env::consts::ARCH
    );

    let hash = sha256_hex(
        material.as_bytes()
    );

    format!(
        "agent-{}",
        &hash[..16]
    )
}


fn generate_investigation_id() -> String {
    let timestamp =
        Utc::now()
            .format("%Y%m%d-%H%M%S")
            .to_string();

    let hostname =
        hostname_fallback();

    let material = format!(
        "{}:{}:{}",
        timestamp,
        hostname,
        std::process::id()
    );

    let hash = sha256_hex(
        material.as_bytes()
    );

    format!(
        "INV-{}-{}",
        timestamp,
        &hash[..12]
    )
}


fn hostname_fallback() -> String {
    env::var("COMPUTERNAME")
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string())
}


// ============================================================
// HASHING
// ============================================================

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher =
        Sha256::new();

    hasher.update(data);

    let result =
        hasher.finalize();

    result
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}


// ============================================================
// SAFETY POLICY
// ============================================================

fn is_allowed_artifact(
    artifact: &str,
) -> bool {
    ALLOWED_ARTIFACTS
        .iter()
        .any(|x| *x == artifact)
}


fn is_simulation_operation(
    operation: &str,
) -> bool {
    SIMULATION_OPERATIONS
        .iter()
        .any(|x| *x == operation)
}


fn is_blocked_operation(
    operation: &str,
) -> bool {
    BLOCKED_OPERATIONS
        .iter()
        .any(|x| *x == operation)
}


fn runtime_metadata() -> RuntimeMetadata {
    RuntimeMetadata {
        runtime_version:
            RUNTIME_VERSION.to_string(),

        policy_version:
            POLICY_VERSION.to_string(),

        read_only: true,

        arbitrary_command_execution: false,

        process_injection: false,

        memory_injection: false,

        kernel_exploitation: false,

        security_product_tampering: false,

        privilege_escalation: false,

        persistence: false,

        covert_c2: false,

        simulation_enabled: true,
    }
}


// ============================================================
// INITIALIZATION
// ============================================================

#[no_mangle]
pub extern "C" fn jocky_sys_init() {
    let state_mutex =
        runtime_state();

    let mut state =
        match state_mutex.lock() {
            Ok(value) => value,

            Err(_) => {
                eprintln!(
                    "[JOCKY] runtime state lock failure"
                );

                return;
            }
        };

    if state.initialized {
        return;
    }

    let platform =
        syscalls::platform();

    match platform.system_information() {

        Ok(info) => {

            state.hostname =
                info.hostname.clone();

            state.operating_system =
                info.operating_system.clone();
        }

        Err(error) => {

            state.warnings.push(
                format!(
                    "system_information failed: {}",
                    error
                )
            );
        }
    }

    state.initialized = true;

    println!(
        "[JOCKY] Runtime {} initialized",
        RUNTIME_VERSION
    );

    println!(
        "[JOCKY] Investigation: {}",
        state.investigation_id
    );

    println!(
        "[JOCKY] Agent: {}",
        state.agent_id
    );

    println!(
        "[JOCKY] Build: {}",
        state.build_id
    );

    println!(
        "[JOCKY] Policy: {}",
        POLICY_VERSION
    );

    println!(
        "[JOCKY] Mode: READ_ONLY_FORENSICS"
    );
}


// ============================================================
// COLLECTION ENGINE
// ============================================================

fn collect_artifact(
    artifact: &str,
) {
    if !is_allowed_artifact(artifact) {

        record_warning(
            format!(
                "Unsupported artifact rejected: {}",
                artifact
            )
        );

        return;
    }

    let platform =
        syscalls::platform();

    println!(
        "[JOCKY] Collecting: {}",
        artifact
    );

    match platform.collect(artifact) {

        Ok(result) => {

            let mut state =
                match runtime_state().lock() {
                    Ok(value) => value,

                    Err(_) => {
                        eprintln!(
                            "[JOCKY] Runtime state lock failure"
                        );

                        return;
                    }
                };

            for warning in result.warnings {

                state.warnings.push(
                    format!(
                        "{}: {}",
                        artifact,
                        warning
                    )
                );

                println!(
                    "[JOCKY][WARNING] {}",
                    warning
                );
            }

            for observation in result.observations {

                if state.artifacts.len()
                    >= MAX_ARTIFACTS
                {
                    state.warnings.push(
                        "Maximum evidence record limit reached"
                            .to_string()
                    );

                    break;
                }

                let record =
                    map_observation(
                        &observation
                    );

                state.artifacts.push(
                    record
                );
            }

            state.executed_operations.push(
                format!(
                    "collect:{}",
                    artifact
                )
            );
        }

        Err(error) => {

            record_warning(
                format!(
                    "{} collection failed: {}",
                    artifact,
                    error
                )
            );
        }
    }
}


// ============================================================
// COLLECTION EXPORTS
// ============================================================

#[no_mangle]
pub extern "C" fn jocky_op_processes() {
    collect_artifact("processes");
}


#[no_mangle]
pub extern "C" fn jocky_op_network_connections() {
    collect_artifact(
        "network_connections"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_startup_items() {
    collect_artifact(
        "startup_items"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_users() {
    collect_artifact("users");
}


#[no_mangle]
pub extern "C" fn jocky_op_services() {
    collect_artifact("services");
}


#[no_mangle]
pub extern "C" fn jocky_op_file_metadata() {
    collect_artifact(
        "file_metadata"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_authentication_events() {
    collect_artifact(
        "authentication_events"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_system_information() {
    collect_artifact(
        "system_information"
    );
}


// ============================================================
// SIMULATION ENGINE
// ============================================================

fn simulate_operation(
    operation: &str,
) {
    let normalized =
        operation.to_uppercase();

    if is_blocked_operation(
        &normalized
    ) {

        record_blocked_operation(
            &normalized
        );

        println!(
            "[JOCKY][BLOCKED] {}",
            normalized
        );

        return;
    }

    if !is_simulation_operation(
        &normalized
    ) {

        record_warning(
            format!(
                "Unknown runtime operation rejected: {}",
                normalized
            )
        );

        return;
    }

    println!(
        "[JOCKY][SIMULATION] {}",
        normalized
    );

    let mut details =
        Map::new();

    details.insert(
        "technique".to_string(),
        Value::String(
            normalized.clone()
        ),
    );

    details.insert(
        "execution".to_string(),
        Value::String(
            "NOT_PERFORMED".to_string()
        ),
    );

    details.insert(
        "memory_modification".to_string(),
        Value::Bool(false),
    );

    details.insert(
        "remote_process_modification".to_string(),
        Value::Bool(false),
    );

    details.insert(
        "kernel_interaction".to_string(),
        Value::Bool(false),
    );

    details.insert(
        "security_product_interaction".to_string(),
        Value::Bool(false),
    );

    details.insert(
        "network_stealth".to_string(),
        Value::Bool(false),
    );

    let event =
        SimulationEvent {
            technique: normalized.clone(),

            execution_status:
                "SIMULATED".to_string(),

            real_execution: false,

            read_only: true,

            evidence_generated: true,

            timestamp:
                Utc::now()
                    .to_rfc3339(),

            details,
        };

    match runtime_state().lock() {

        Ok(mut state) => {

            state.simulation_events
                .push(event);

            state.executed_operations.push(
                format!(
                    "simulate:{}",
                    normalized
                )
            );
        }

        Err(_) => {

            eprintln!(
                "[JOCKY] Failed to record simulation"
            );
        }
    }
}


// ============================================================
// SAFE CFG VARIATION OPERATIONS
// ============================================================

#[no_mangle]
pub extern "C" fn jocky_op_SIMULATE_SLEEP_OBFUSCATE() {
    simulate_operation(
        "SIMULATE_SLEEP_OBFUSCATE"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_SIMULATE_MATH_ENTROPY() {
    simulate_operation(
        "SIMULATE_MATH_ENTROPY"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_SIMULATE_MEMORY_ALLOC_FREE() {
    simulate_operation(
        "SIMULATE_MEMORY_ALLOC_FREE"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_SIMULATE_ENV_QUERY() {
    simulate_operation(
        "SIMULATE_ENV_QUERY"
    );
}


// ============================================================
// ADVANCED TECHNIQUE SIMULATIONS
// ============================================================

#[no_mangle]
pub extern "C" fn jocky_op_PROCESS_HOLLOWING() {
    simulate_operation(
        "PROCESS_HOLLOWING"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_REFLECTIVE_LOADING() {
    simulate_operation(
        "REFLECTIVE_LOADING"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_REFLECTIVE_DLL_INJECTION() {
    simulate_operation(
        "REFLECTIVE_DLL_INJECTION"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_THREAD_HIJACKING() {
    simulate_operation(
        "THREAD_HIJACKING"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_API_UNHOOKING() {
    simulate_operation(
        "API_UNHOOKING"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_DIRECT_SYSCALL() {
    simulate_operation(
        "DIRECT_SYSCALL"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_IN_MEMORY_EXECUTION() {
    simulate_operation(
        "IN_MEMORY_EXECUTION"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_VULNERABLE_DRIVER() {
    simulate_operation(
        "VULNERABLE_DRIVER"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_BYOVD() {
    simulate_operation(
        "BYOVD"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_KERNEL_SUBVERSION() {
    simulate_operation(
        "KERNEL_SUBVERSION"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_DOMAIN_FRONTING() {
    simulate_operation(
        "DOMAIN_FRONTING"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_CDN_ENCAPSULATION() {
    simulate_operation(
        "CDN_ENCAPSULATION"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_SOCKS5_ROUTING() {
    simulate_operation(
        "SOCKS5_ROUTING"
    );
}


// ============================================================
// BLOCKED OPERATION EXPORTS
// ============================================================

#[no_mangle]
pub extern "C" fn jocky_op_REAL_PROCESS_HOLLOWING() {
    block_operation(
        "REAL_PROCESS_HOLLOWING"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_REAL_REFLECTIVE_INJECTION() {
    block_operation(
        "REAL_REFLECTIVE_INJECTION"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_REAL_THREAD_HIJACKING() {
    block_operation(
        "REAL_THREAD_HIJACKING"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_REAL_API_UNHOOKING() {
    block_operation(
        "REAL_API_UNHOOKING"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_REAL_DIRECT_SYSCALL() {
    block_operation(
        "REAL_DIRECT_SYSCALL"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_REAL_BYOVD() {
    block_operation(
        "REAL_BYOVD"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_REAL_DRIVER_EXPLOIT() {
    block_operation(
        "REAL_DRIVER_EXPLOIT"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_REAL_EDR_TAMPERING() {
    block_operation(
        "REAL_EDR_TAMPERING"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_REAL_AV_BYPASS() {
    block_operation(
        "REAL_AV_BYPASS"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_REAL_PRIVILEGE_ESCALATION() {
    block_operation(
        "REAL_PRIVILEGE_ESCALATION"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_REAL_PERSISTENCE() {
    block_operation(
        "REAL_PERSISTENCE"
    );
}


#[no_mangle]
pub extern "C" fn jocky_op_REAL_COVERT_C2() {
    block_operation(
        "REAL_COVERT_C2"
    );
}


fn block_operation(
    operation: &str,
) {
    let normalized =
        operation.to_uppercase();

    record_blocked_operation(
        &normalized
    );

    println!(
        "[JOCKY][BLOCKED] {}",
        normalized
    );
}


// ============================================================
// WARNING / BLOCK RECORDING
// ============================================================

fn record_warning(
    message: String,
) {
    eprintln!(
        "[JOCKY][WARNING] {}",
        message
    );

    if let Ok(mut state) =
        runtime_state().lock()
    {
        state.warnings.push(
            message
        );
    }
}


fn record_blocked_operation(
    operation: &str,
) {
    if let Ok(mut state) =
        runtime_state().lock()
    {
        state.blocked_operations.push(
            operation.to_string()
        );
    }
}

// ============================================================
// OBSERVATION MAPPING
// ============================================================

fn map_observation(
    observation: &syscalls::Observation,
) -> ArtifactRecord {

    let mut data = Map::new();

    for (k, v) in &observation.fields {
        if k == "pid" || k == "uid" || k == "gid" || k == "size" || k == "memory_kb" || k == "local_port" || k == "remote_port" {
            if let Ok(num) = v.parse::<i64>() {
                data.insert(k.clone(), json!(num));
                continue;
            }
        }
        data.insert(k.clone(), Value::String(v.clone()));
    }

    data.insert(
        "timestamp_unix_ms".to_string(),
        json!(observation.timestamp_unix_ms),
    );

    let artifact = observation.artifact.as_str();

    match artifact {
        "processes" => {
            if !data.contains_key("exe_path") {
                data.insert(
                    "exe_path".to_string(),
                    Value::String("unknown".to_string()),
                );
            }
        }
        "network_connections" => {
            normalize_network_fields(&mut data);
        }
        _ => {}
    }

    let record_type = match artifact {
        "processes" => "Process",
        "network_connections" => "NetworkConnection",
        "startup_items" => "StartupItem",
        "users" => "UserAccount",
        "services" => "Service",
        "file_metadata" => "FileMetadata",
        "authentication_events" => "AuthenticationEvent",
        "system_information" => "SystemInformation",
        _ => "GenericArtifact",
    };

    ArtifactRecord {
        record_type: record_type.to_string(),
        data,
    }
}


// ============================================================
// NETWORK NORMALIZATION
// ============================================================

fn normalize_network_fields(
    data: &mut Map<String, Value>,
) {
    if let Some(value) = data.get("local_address") {
        if let Some(address) = value.as_str() {
            let (host, port) = split_host_port(address);

            if let Some(h) = host {
                data.insert("local_ip".to_string(), Value::String(h));
            }

            if let Some(p) = port {
                data.insert("local_port".to_string(), json!(p));
            }
        }
    }

    if let Some(value) = data.get("remote_address") {
        if let Some(address) = value.as_str() {
            let (host, port) = split_host_port(address);

            if let Some(h) = host {
                data.insert("remote_ip".to_string(), Value::String(h));
            }

            if let Some(p) = port {
                data.insert("remote_port".to_string(), json!(p));
            }
        }
    }

    if !data.contains_key("pid") {
        data.insert("pid".to_string(), json!(0));
    }
}


fn split_host_port(
    address: &str,
) -> (Option<String>, Option<u16>) {

    let trimmed = address.trim();

    if trimmed.starts_with('[') {
        if let Some(close) = trimmed.find(']') {
            let host = &trimmed[1..close];
            let remainder = &trimmed[close + 1..];

            if let Some(port_text) = remainder.strip_prefix(':') {
                if let Ok(port) = port_text.parse::<u16>() {
                    return (Some(host.to_string()), Some(port));
                }
            }

            return (Some(host.to_string()), None);
        }
    }

    if let Some((host, port)) = trimmed.rsplit_once(':') {
        if let Ok(port_number) = port.parse::<u16>() {
            return (Some(host.to_string()), Some(port_number));
        }
    }

    (Some(trimmed.to_string()), None)
}

// ============================================================
// REPORT GENERATION
// ============================================================

fn build_report_without_hash(
    state: &RuntimeState,
) -> EvidenceReport {

    EvidenceReport {
        schema:
            "jocky.evidence.v2".to_string(),

        runtime_version:
            RUNTIME_VERSION.to_string(),

        policy_version:
            POLICY_VERSION.to_string(),

        investigation_id:
            state.investigation_id.clone(),

        agent_id:
            state.agent_id.clone(),

        build_id:
            state.build_id.clone(),

        timestamp:
            Utc::now()
                .to_rfc3339(),

        hostname:
            state.hostname.clone(),

        operating_system:
            state.operating_system.clone(),

        read_only:
            true,

        execution_mode:
            "READ_ONLY_FORENSICS".to_string(),

        artifacts:
            state.artifacts.clone(),

        simulations:
            state.simulation_events.clone(),

        executed_operations:
            state.executed_operations.clone(),

        blocked_operations:
            state.blocked_operations.clone(),

        warnings:
            state.warnings.clone(),

        artifact_count:
            state.artifacts.len(),

        report_sha256:
            String::new(),
    }
}


fn calculate_report_hash(
    report: &EvidenceReport,
) -> String {

    match serde_json::to_vec(report) {

        Ok(bytes) =>
            sha256_hex(&bytes),

        Err(_) =>
            "REPORT_SERIALIZATION_ERROR"
                .to_string(),
    }
}


// ============================================================
// EVIDENCE TRANSMISSION
// ============================================================

#[no_mangle]
pub extern "C" fn jocky_sys_transmit() {

    println!(
        "[JOCKY] Preparing evidence report..."
    );

    let report = {

        let state_mutex =
            runtime_state();

        let state =
            match state_mutex.lock() {

                Ok(value) => value,

                Err(_) => {

                    eprintln!(
                        "[JOCKY] Unable to acquire runtime state"
                    );

                    return;
                }
            };

        build_report_without_hash(
            &state
        )
    };

    let mut report =
        report;

    let report_hash =
        calculate_report_hash(
            &report
        );

    report.report_sha256 =
        report_hash.clone();

    let payload =
        match serde_json::to_string_pretty(
            &report
        ) {

            Ok(value) => value,

            Err(error) => {

                eprintln!(
                    "[JOCKY] Report serialization failed: {}",
                    error
                );

                return;
            }
        };

    println!(
        "[JOCKY] Evidence records: {}",
        report.artifact_count
    );

    println!(
        "[JOCKY] Simulation events: {}",
        report.simulations.len()
    );

    println!(
        "[JOCKY] Report SHA-256: {}",
        report_hash
    );

    if let Err(error) =
        write_local_report(
            &payload
        )
    {
        eprintln!(
            "[JOCKY] Local evidence write failed: {}",
            error
        );
    }

    let upload_enabled =
        env::var("JOCKY_UPLOAD")
            .unwrap_or_else(
                |_| "1".to_string()
            );

    if upload_enabled == "0" ||
       upload_enabled.eq_ignore_ascii_case(
           "false"
       )
    {
        println!(
            "[JOCKY] Upload disabled by JOCKY_UPLOAD."
        );

        return;
    }

    transmit_report(
        &payload
    );
}


// ============================================================
// LOCAL REPORT
// ============================================================

fn write_local_report(
    payload: &str,
) -> Result<(), String> {

    let path =
        env::var("JOCKY_EVIDENCE_OUTPUT")
            .unwrap_or_else(
                |_| "jocky_evidence.json"
                    .to_string()
            );

    std::fs::write(
        &path,
        payload.as_bytes(),
    )
    .map_err(
        |error|
        error.to_string()
    )?;

    println!(
        "[JOCKY] Evidence saved: {}",
        path
    );

    Ok(())
}


// ============================================================
// HTTP TRANSMISSION
// ============================================================

fn transmit_report(
    payload: &str,
) {

    let endpoint =
        env::var("JOCKY_C2_URL")
            .unwrap_or_else(
                |_| C2_DEFAULT.to_string()
            );

    println!(
        "[JOCKY] Evidence endpoint: {}",
        endpoint
    );

    let client =
        match Client::builder()
            .timeout(
                Duration::from_secs(15)
            )
            .build()
        {
            Ok(client) =>
                client,

            Err(error) => {

                eprintln!(
                    "[JOCKY] HTTP client initialization failed: {}",
                    error
                );

                return;
            }
        };

    let response =
        client
            .post(&endpoint)
            .header(
                "Content-Type",
                "application/json"
            )
            .header(
                "X-JOCKY-Runtime",
                RUNTIME_VERSION
            )
            .header(
                "X-JOCKY-Policy",
                POLICY_VERSION
            )
            .body(
                payload.to_string()
            )
            .send();

    match response {

        Ok(response) => {

            if response.status().is_success() {

                println!(
                    "[JOCKY] Evidence transmission successful: {}",
                    response.status()
                );

            } else {

                eprintln!(
                    "[JOCKY] Evidence endpoint returned HTTP {}",
                    response.status()
                );
            }
        }

        Err(error) => {

            eprintln!(
                "[JOCKY] Evidence transmission failed: {}",
                error
            );
        }
    }
}


// ============================================================
// OPTIONAL RUNTIME METADATA EXPORT
// ============================================================

#[no_mangle]
pub extern "C" fn jocky_runtime_metadata() {

    let metadata =
        runtime_metadata();

    match serde_json::to_string(
        &metadata
    ) {

        Ok(value) =>
            println!(
                "[JOCKY] Runtime metadata: {}",
                value
            ),

        Err(error) =>
            eprintln!(
                "[JOCKY] Metadata serialization failed: {}",
                error
            ),
    }
}


// ============================================================
// TEST SUPPORT
// ============================================================

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_sha256() {

        let hash =
            sha256_hex(
                b"jocky"
            );

        assert_eq!(
            hash.len(),
            64
        );
    }


    #[test]
    fn test_artifact_validation() {

        assert!(
            is_allowed_artifact(
                "processes"
            )
        );

        assert!(
            is_allowed_artifact(
                "network_connections"
            )
        );

        assert!(
            !is_allowed_artifact(
                "arbitrary_command"
            )
        );
    }


    #[test]
    fn test_simulation_detection() {

        assert!(
            is_simulation_operation(
                "PROCESS_HOLLOWING"
            )
        );

        assert!(
            is_simulation_operation(
                "DOMAIN_FRONTING"
            )
        );
    }


    #[test]
    fn test_block_detection() {

        assert!(
            is_blocked_operation(
                "REAL_BYOVD"
            )
        );

        assert!(
            is_blocked_operation(
                "REAL_EDR_TAMPERING"
            )
        );
    }


    #[test]
    fn test_ipv4_port() {

        let (
            host,
            port
        ) =
            split_host_port(
                "127.0.0.1:443"
            );

        assert_eq!(
            host,
            Some(
                "127.0.0.1".to_string()
            )
        );

        assert_eq!(
            port,
            Some(443)
        );
    }


    #[test]
    fn test_ipv6_port() {

        let (
            host,
            port
        ) =
            split_host_port(
                "[::1]:443"
            );

        assert_eq!(
            host,
            Some(
                "::1".to_string()
            )
        );

        assert_eq!(
            port,
            Some(443)
        );
    }


    #[test]
    fn test_runtime_metadata() {

        let metadata =
            runtime_metadata();

        assert!(
            metadata.read_only
        );

        assert!(
            !metadata.process_injection
        );

        assert!(
            !metadata.kernel_exploitation
        );

        assert!(
            metadata.simulation_enabled
        );
    }
}