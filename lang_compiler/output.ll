; ModuleID = "jocky_payload"
target triple = "x86_64-pc-windows-msvc"
target datalayout = ""

declare void @"jocky_op_SIMULATE_ENV_QUERY"()

declare void @"jocky_op_processes"()

declare void @"jocky_op_network_connections"()

declare void @"jocky_op_SIMULATE_MEMORY_ALLOC_FREE"()

declare void @"jocky_op_startup_items"()

declare void @"jocky_op_services"()

declare void @"jocky_op_system_information"()

declare void @"jocky_sys_init"()

declare void @"jocky_sys_transmit"()

define i32 @"main"()
{
entry:
  call void @"jocky_sys_init"()
  call void @"jocky_op_SIMULATE_ENV_QUERY"()
  call void @"jocky_op_processes"()
  call void @"jocky_op_network_connections"()
  call void @"jocky_op_SIMULATE_MEMORY_ALLOC_FREE"()
  call void @"jocky_op_startup_items"()
  call void @"jocky_op_SIMULATE_MEMORY_ALLOC_FREE"()
  call void @"jocky_op_services"()
  call void @"jocky_op_SIMULATE_ENV_QUERY"()
  call void @"jocky_op_system_information"()
  call void @"jocky_op_SIMULATE_MEMORY_ALLOC_FREE"()
  call void @"jocky_sys_transmit"()
  ret i32 0
}

@"JOCKY_CORRELATION_RULES" = constant [1107 x i8] c"[{\22field\22:\22process.name\22,\22operator\22:\22==\22,\22value\22:\22mimikatz.exe\22,\22alert\22:\22Credential Dumping Tool Detected (Mimikatz)\22,\22severity\22:\22CRITICAL\22,\22score_impact\22:85},{\22field\22:\22network.local_port\22,\22operator\22:\22==\22,\22value\22:4444,\22alert\22:\22Suspicious Default Metasploit Listener (Port 4444)\22,\22severity\22:\22CRITICAL\22,\22score_impact\22:75},{\22field\22:\22process.name\22,\22operator\22:\22==\22,\22value\22:\22nc.exe\22,\22alert\22:\22Netcat Reverse Shell Utility Observed\22,\22severity\22:\22HIGH\22,\22score_impact\22:60},{\22field\22:\22network.local_port\22,\22operator\22:\22==\22,\22value\22:4433,\22alert\22:\22Suspicious Encrypted C2 Tunnel Port (4433)\22,\22severity\22:\22HIGH\22,\22score_impact\22:50},{\22field\22:\22process.name\22,\22operator\22:\22==\22,\22value\22:\22powershell.exe\22,\22alert\22:\22PowerShell Execution (Verify if Authorized)\22,\22severity\22:\22MEDIUM\22,\22score_impact\22:20},{\22field\22:\22network.local_port\22,\22operator\22:\22==\22,\22value\22:3389,\22alert\22:\22RDP Port Open / Exposed\22,\22severity\22:\22LOW\22,\22score_impact\22:10},{\22field\22:\22startup_items.path\22,\22operator\22:\22==\22,\22value\22:\22HKLM\5c\5c\5c\5cSoftware\5c\5c\5c\5cMicrosoft\5c\5c\5c\5cWindows\5c\5c\5c\5cCurrentVersion\5c\5c\5c\5cRun\22,\22alert\22:\22Persistence Registry Run Key Populated\22,\22severity\22:\22HIGH\22,\22score_impact\22:70}]\00"
@"JOCKY_BUILD_METADATA" = constant [468 x i8] c"{\22compiler\22:\22JOCKY LLVM Frontend\22,\22compiler_version\22:\222.1.0\22,\22llvm_module\22:\22jocky_payload\22,\22platform\22:\22windows\22,\22build_seed\22:\222036b3d457e061b6\22,\22polymorphic_execution_variation\22:true,\22base_task_count\22:5,\22final_task_count\22:10,\22correlation_rule_count\22:7,\22security_mode\22:\22READ_ONLY_FORENSICS\22,\22arbitrary_command_execution\22:false,\22process_injection\22:false,\22security_product_tampering\22:false,\22privilege_escalation\22:false,\22persistence\22:false,\22covert_network_routing\22:false}\00"
@"JOCKY_TASK_METADATA" = constant [833 x i8] c"[{\22index\22:0,\22operation\22:\22SIMULATE_ENV_QUERY\22,\22target\22:null,\22simulation\22:true},{\22index\22:1,\22operation\22:\22processes\22,\22target\22:\22ALL_ENDPOINTS\22,\22simulation\22:false},{\22index\22:2,\22operation\22:\22network_connections\22,\22target\22:\22ALL_ENDPOINTS\22,\22simulation\22:false},{\22index\22:3,\22operation\22:\22SIMULATE_MEMORY_ALLOC_FREE\22,\22target\22:null,\22simulation\22:true},{\22index\22:4,\22operation\22:\22startup_items\22,\22target\22:\22ALL_ENDPOINTS\22,\22simulation\22:false},{\22index\22:5,\22operation\22:\22SIMULATE_MEMORY_ALLOC_FREE\22,\22target\22:null,\22simulation\22:true},{\22index\22:6,\22operation\22:\22services\22,\22target\22:\22ALL_ENDPOINTS\22,\22simulation\22:false},{\22index\22:7,\22operation\22:\22SIMULATE_ENV_QUERY\22,\22target\22:null,\22simulation\22:true},{\22index\22:8,\22operation\22:\22system_information\22,\22target\22:\22ALL_ENDPOINTS\22,\22simulation\22:false},{\22index\22:9,\22operation\22:\22SIMULATE_MEMORY_ALLOC_FREE\22,\22target\22:null,\22simulation\22:true}]\00"