//! Built-in hunting query library.
//!
//! Provides a curated set of threat hunting queries organized by MITRE ATT&CK
//! tactic categories, with templates for both Splunk SPL and Elasticsearch KQL.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::hunt::QueryType;

/// MITRE ATT&CK tactic-aligned hunting categories.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HuntingCategory {
    /// Credential theft and abuse.
    CredentialAccess,
    /// Moving through the network.
    LateralMovement,
    /// Maintaining access.
    Persistence,
    /// Data theft.
    Exfiltration,
    /// Communication with attacker infrastructure.
    CommandAndControl,
    /// Gaining higher privileges.
    PrivilegeEscalation,
    /// Reconnaissance and mapping.
    Discovery,
    /// Initial compromise vectors.
    InitialAccess,
}

impl std::fmt::Display for HuntingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HuntingCategory::CredentialAccess => write!(f, "Credential Access"),
            HuntingCategory::LateralMovement => write!(f, "Lateral Movement"),
            HuntingCategory::Persistence => write!(f, "Persistence"),
            HuntingCategory::Exfiltration => write!(f, "Exfiltration"),
            HuntingCategory::CommandAndControl => write!(f, "Command & Control"),
            HuntingCategory::PrivilegeEscalation => write!(f, "Privilege Escalation"),
            HuntingCategory::Discovery => write!(f, "Discovery"),
            HuntingCategory::InitialAccess => write!(f, "Initial Access"),
        }
    }
}

/// A built-in hunting query with templates for multiple platforms.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuiltInQuery {
    /// Unique identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Description of what this query hunts for.
    pub description: String,
    /// MITRE ATT&CK tactic category.
    pub category: HuntingCategory,
    /// MITRE ATT&CK technique IDs.
    pub mitre_techniques: Vec<String>,
    /// Query templates keyed by platform.
    pub query_templates: HashMap<QueryType, String>,
    /// Default expected baseline count for anomaly detection.
    pub default_baseline: Option<u64>,
    /// Required data sources.
    pub data_sources: Vec<String>,
    /// Configurable parameters.
    pub parameters: Vec<QueryParameter>,
}

/// A configurable parameter for a built-in query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryParameter {
    /// Parameter name used in query template substitution.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Data type of the parameter.
    pub param_type: ParameterType,
    /// Default value if not provided.
    pub default_value: Option<String>,
    /// Whether this parameter is required.
    pub required: bool,
}

/// Data types for query parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ParameterType {
    /// Free-form text.
    String,
    /// Whole number.
    Integer,
    /// Time duration (e.g., "24h", "7d").
    Duration,
    /// IPv4 or IPv6 address.
    IpAddress,
    /// Hostname or FQDN.
    Hostname,
}

/// Returns all built-in hunting queries.
#[allow(clippy::vec_init_then_push)]
pub fn get_built_in_queries() -> Vec<BuiltInQuery> {
    let mut queries = Vec::new();

    // =========================================================================
    // Credential Access
    // =========================================================================

    queries.push(BuiltInQuery {
        id: "hunt-cred-kerberoasting".to_string(),
        name: "Kerberoasting Detection".to_string(),
        description: "Detects potential Kerberoasting attacks by looking for unusual TGS ticket requests for service accounts.".to_string(),
        category: HuntingCategory::CredentialAccess,
        mitre_techniques: vec!["T1558.003".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 | where Service_Name!="krbtgt" | stats count by Account_Name, Service_Name, Client_Address | where count > 5"#.to_string()),
            (QueryType::Elasticsearch, r#"event.code: "4769" AND winlog.event_data.TicketEncryptionType: "0x17" AND NOT winlog.event_data.ServiceName: "krbtgt""#.to_string()),
        ]),
        default_baseline: Some(5),
        data_sources: vec!["windows_security_events".to_string()],
        parameters: vec![
            QueryParameter {
                name: "threshold".to_string(),
                description: "Minimum number of TGS requests to flag".to_string(),
                param_type: ParameterType::Integer,
                default_value: Some("5".to_string()),
                required: false,
            },
        ],
    });

    queries.push(BuiltInQuery {
        id: "hunt-cred-dcsync".to_string(),
        name: "DCSync Attack Detection".to_string(),
        description: "Detects DCSync attacks where non-DC machines request directory replication.".to_string(),
        category: HuntingCategory::CredentialAccess,
        mitre_techniques: vec!["T1003.006".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=wineventlog EventCode=4662 Access_Mask=0x100 | search Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" | where NOT match(Account_Name, ".*\\$$")"#.to_string()),
            (QueryType::Elasticsearch, r#"event.code: "4662" AND winlog.event_data.AccessMask: "0x100" AND winlog.event_data.Properties: (*1131f6ad* OR *1131f6aa*)"#.to_string()),
        ]),
        default_baseline: Some(0),
        data_sources: vec!["windows_security_events".to_string()],
        parameters: vec![],
    });

    queries.push(BuiltInQuery {
        id: "hunt-cred-bruteforce".to_string(),
        name: "Brute Force Detection".to_string(),
        description: "Identifies accounts with excessive failed login attempts followed by success.".to_string(),
        category: HuntingCategory::CredentialAccess,
        mitre_techniques: vec!["T1110.001".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=wineventlog (EventCode=4625 OR EventCode=4624) | transaction Account_Name maxspan=10m | where eventcount > {{threshold}} AND mvindex(EventCode, -1)=4624"#.to_string()),
            (QueryType::Elasticsearch, r#"(event.code: "4625" OR event.code: "4624") | Aggregate by user.name with threshold"#.to_string()),
        ]),
        default_baseline: Some(10),
        data_sources: vec!["windows_security_events".to_string(), "authentication_logs".to_string()],
        parameters: vec![
            QueryParameter {
                name: "threshold".to_string(),
                description: "Minimum failed attempts before success".to_string(),
                param_type: ParameterType::Integer,
                default_value: Some("10".to_string()),
                required: false,
            },
            QueryParameter {
                name: "timewindow".to_string(),
                description: "Time window to correlate failures".to_string(),
                param_type: ParameterType::Duration,
                default_value: Some("10m".to_string()),
                required: false,
            },
        ],
    });

    queries.push(BuiltInQuery {
        id: "hunt-cred-dumping".to_string(),
        name: "Credential Dumping via LSASS".to_string(),
        description: "Detects processes accessing LSASS memory, a common credential dumping technique.".to_string(),
        category: HuntingCategory::CredentialAccess,
        mitre_techniques: vec!["T1003.001".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=sysmon EventCode=10 TargetImage="*lsass.exe" | where NOT match(SourceImage, ".*(csrss|services|svchost|wininit|winlogon|mrt|taskmgr)\.exe$")"#.to_string()),
            (QueryType::Elasticsearch, r#"event.code: "10" AND process.target.executable: *lsass.exe AND NOT process.executable: (*csrss.exe OR *services.exe OR *svchost.exe)"#.to_string()),
        ]),
        default_baseline: Some(2),
        data_sources: vec!["sysmon".to_string(), "edr_process_events".to_string()],
        parameters: vec![],
    });

    // =========================================================================
    // Lateral Movement
    // =========================================================================

    queries.push(BuiltInQuery {
        id: "hunt-lat-psexec".to_string(),
        name: "PsExec Remote Execution".to_string(),
        description: "Detects PsExec-like remote service creation indicative of lateral movement.".to_string(),
        category: HuntingCategory::LateralMovement,
        mitre_techniques: vec!["T1570".to_string(), "T1021.002".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=wineventlog EventCode=7045 Service_Name="PSEXESVC" OR (EventCode=7045 Service_File_Name="*\\PSEXESVC*")"#.to_string()),
            (QueryType::Elasticsearch, r#"event.code: "7045" AND (winlog.event_data.ServiceName: "PSEXESVC" OR winlog.event_data.ImagePath: *PSEXESVC*)"#.to_string()),
        ]),
        default_baseline: Some(0),
        data_sources: vec!["windows_system_events".to_string()],
        parameters: vec![],
    });

    queries.push(BuiltInQuery {
        id: "hunt-lat-wmi-remote".to_string(),
        name: "WMI Remote Execution".to_string(),
        description: "Detects remote process creation via WMI, commonly used for lateral movement.".to_string(),
        category: HuntingCategory::LateralMovement,
        mitre_techniques: vec!["T1047".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=sysmon EventCode=1 ParentImage="*WmiPrvSE.exe" | where NOT match(Image, ".*(svchost|mofcomp|wmiprvse)\.exe$")"#.to_string()),
            (QueryType::Elasticsearch, r#"event.code: "1" AND process.parent.executable: *WmiPrvSE.exe AND NOT process.executable: (*svchost.exe OR *mofcomp.exe)"#.to_string()),
        ]),
        default_baseline: Some(3),
        data_sources: vec!["sysmon".to_string(), "edr_process_events".to_string()],
        parameters: vec![],
    });

    queries.push(BuiltInQuery {
        id: "hunt-lat-rdp".to_string(),
        name: "Unusual RDP Lateral Movement".to_string(),
        description: "Identifies RDP connections from non-standard sources or to unusual destinations.".to_string(),
        category: HuntingCategory::LateralMovement,
        mitre_techniques: vec!["T1021.001".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=wineventlog EventCode=4624 Logon_Type=10 | stats count dc(Workstation_Name) as unique_sources by Account_Name | where unique_sources > {{threshold}}"#.to_string()),
            (QueryType::Elasticsearch, r#"event.code: "4624" AND winlog.event_data.LogonType: "10" | Aggregate by user.name and source.ip"#.to_string()),
        ]),
        default_baseline: Some(3),
        data_sources: vec!["windows_security_events".to_string()],
        parameters: vec![
            QueryParameter {
                name: "threshold".to_string(),
                description: "Maximum unique source machines for normal RDP".to_string(),
                param_type: ParameterType::Integer,
                default_value: Some("3".to_string()),
                required: false,
            },
        ],
    });

    queries.push(BuiltInQuery {
        id: "hunt-lat-pth".to_string(),
        name: "Pass-the-Hash Detection".to_string(),
        description: "Detects NTLM authentication with unusual patterns suggesting pass-the-hash attacks.".to_string(),
        category: HuntingCategory::LateralMovement,
        mitre_techniques: vec!["T1550.002".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=wineventlog EventCode=4624 Logon_Type=9 Authentication_Package=NTLM | stats count by Account_Name, Workstation_Name | where count > 1"#.to_string()),
            (QueryType::Elasticsearch, r#"event.code: "4624" AND winlog.event_data.LogonType: "9" AND winlog.event_data.AuthenticationPackageName: "NTLM""#.to_string()),
        ]),
        default_baseline: Some(1),
        data_sources: vec!["windows_security_events".to_string()],
        parameters: vec![],
    });

    // =========================================================================
    // Persistence
    // =========================================================================

    queries.push(BuiltInQuery {
        id: "hunt-persist-schtask".to_string(),
        name: "New Scheduled Tasks".to_string(),
        description: "Detects creation of new scheduled tasks, a common persistence mechanism.".to_string(),
        category: HuntingCategory::Persistence,
        mitre_techniques: vec!["T1053.005".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=wineventlog (EventCode=4698 OR EventCode=106) | where NOT match(Task_Name, "^\\Microsoft\\.*") | table _time, Task_Name, Task_Content, Account_Name"#.to_string()),
            (QueryType::Elasticsearch, r#"(event.code: "4698" OR event.code: "106") AND NOT winlog.event_data.TaskName: \\Microsoft\\*"#.to_string()),
        ]),
        default_baseline: Some(5),
        data_sources: vec!["windows_security_events".to_string(), "windows_task_scheduler".to_string()],
        parameters: vec![],
    });

    queries.push(BuiltInQuery {
        id: "hunt-persist-runkeys".to_string(),
        name: "Registry Run Key Modifications".to_string(),
        description: "Detects modifications to common auto-start registry keys used for persistence.".to_string(),
        category: HuntingCategory::Persistence,
        mitre_techniques: vec!["T1547.001".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=sysmon EventCode=13 TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\CurrentVersion\\RunOnce*" | where NOT match(Image, ".*(explorer|msiexec|setup)\.exe$")"#.to_string()),
            (QueryType::Elasticsearch, r#"event.code: "13" AND registry.path: (*CurrentVersion\\Run* OR *CurrentVersion\\RunOnce*)"#.to_string()),
        ]),
        default_baseline: Some(3),
        data_sources: vec!["sysmon".to_string(), "edr_registry_events".to_string()],
        parameters: vec![],
    });

    queries.push(BuiltInQuery {
        id: "hunt-persist-service".to_string(),
        name: "Suspicious New Services".to_string(),
        description: "Detects new Windows services created by non-standard executables.".to_string(),
        category: HuntingCategory::Persistence,
        mitre_techniques: vec!["T1543.003".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=wineventlog EventCode=7045 | where NOT match(Service_File_Name, "^(C:\\Windows|C:\\Program Files).*") | table _time, Service_Name, Service_File_Name, Service_Account"#.to_string()),
            (QueryType::Elasticsearch, r#"event.code: "7045" AND NOT winlog.event_data.ImagePath: (C\\:\\Windows* OR C\\:\\Program\\ Files*)"#.to_string()),
        ]),
        default_baseline: Some(2),
        data_sources: vec!["windows_system_events".to_string()],
        parameters: vec![],
    });

    queries.push(BuiltInQuery {
        id: "hunt-persist-startup".to_string(),
        name: "Startup Folder Modifications".to_string(),
        description: "Detects files dropped into user or system startup folders.".to_string(),
        category: HuntingCategory::Persistence,
        mitre_techniques: vec!["T1547.001".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=sysmon EventCode=11 TargetFilename="*\\Start Menu\\Programs\\Startup\\*" | table _time, Image, TargetFilename, User"#.to_string()),
            (QueryType::Elasticsearch, r#"event.code: "11" AND file.path: *Start\\ Menu\\Programs\\Startup*"#.to_string()),
        ]),
        default_baseline: Some(1),
        data_sources: vec!["sysmon".to_string(), "edr_file_events".to_string()],
        parameters: vec![],
    });

    // =========================================================================
    // Exfiltration
    // =========================================================================

    queries.push(BuiltInQuery {
        id: "hunt-exfil-large-transfer".to_string(),
        name: "Large Outbound Data Transfers".to_string(),
        description: "Detects unusually large outbound data transfers that may indicate exfiltration.".to_string(),
        category: HuntingCategory::Exfiltration,
        mitre_techniques: vec!["T1048".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=network direction=outbound | stats sum(bytes_out) as total_bytes by src_ip, dest_ip | where total_bytes > {{bytes_threshold}} | sort -total_bytes"#.to_string()),
            (QueryType::Elasticsearch, r#"network.direction: "outbound" | Aggregate sum(destination.bytes) by source.ip where total > threshold"#.to_string()),
        ]),
        default_baseline: Some(100_000_000),
        data_sources: vec!["network_traffic".to_string(), "firewall_logs".to_string()],
        parameters: vec![
            QueryParameter {
                name: "bytes_threshold".to_string(),
                description: "Bytes threshold for large transfers".to_string(),
                param_type: ParameterType::Integer,
                default_value: Some("100000000".to_string()),
                required: false,
            },
        ],
    });

    queries.push(BuiltInQuery {
        id: "hunt-exfil-dns-tunnel".to_string(),
        name: "DNS Tunneling Detection".to_string(),
        description: "Detects potential DNS tunneling by analyzing query patterns and subdomain lengths.".to_string(),
        category: HuntingCategory::Exfiltration,
        mitre_techniques: vec!["T1048.003".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=dns | eval subdomain_len=len(mvindex(split(query, "."), 0)) | where subdomain_len > 50 | stats count by query, src_ip | where count > {{threshold}}"#.to_string()),
            (QueryType::Elasticsearch, r#"dns.question.name: * AND dns.question.name.length > 50 | Aggregate by source.ip and dns.question.registered_domain"#.to_string()),
        ]),
        default_baseline: Some(10),
        data_sources: vec!["dns_logs".to_string()],
        parameters: vec![
            QueryParameter {
                name: "threshold".to_string(),
                description: "Minimum suspicious DNS queries".to_string(),
                param_type: ParameterType::Integer,
                default_value: Some("10".to_string()),
                required: false,
            },
        ],
    });

    queries.push(BuiltInQuery {
        id: "hunt-exfil-upload".to_string(),
        name: "Unusual Upload Patterns".to_string(),
        description: "Detects large file uploads to cloud storage or uncommon external services.".to_string(),
        category: HuntingCategory::Exfiltration,
        mitre_techniques: vec!["T1567.002".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=proxy method=POST OR method=PUT | where bytes_out > 10000000 | stats sum(bytes_out) as total by src_ip, dest_host | where total > {{bytes_threshold}}"#.to_string()),
            (QueryType::Elasticsearch, r#"http.request.method: (POST OR PUT) AND http.request.body.bytes > 10000000 | Aggregate by source.ip and url.domain"#.to_string()),
        ]),
        default_baseline: Some(50_000_000),
        data_sources: vec!["proxy_logs".to_string(), "web_traffic".to_string()],
        parameters: vec![
            QueryParameter {
                name: "bytes_threshold".to_string(),
                description: "Upload bytes threshold".to_string(),
                param_type: ParameterType::Integer,
                default_value: Some("50000000".to_string()),
                required: false,
            },
        ],
    });

    // =========================================================================
    // Command and Control
    // =========================================================================

    queries.push(BuiltInQuery {
        id: "hunt-c2-beacon".to_string(),
        name: "Beaconing Pattern Detection".to_string(),
        description: "Identifies regular-interval outbound connections that may indicate C2 beaconing.".to_string(),
        category: HuntingCategory::CommandAndControl,
        mitre_techniques: vec!["T1071.001".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=network direction=outbound | bucket _time span=60s | stats count by _time, src_ip, dest_ip | eventstats stdev(count) as stdev, avg(count) as avg by src_ip, dest_ip | where stdev < 2 AND avg > 0 | stats dc(_time) as intervals by src_ip, dest_ip | where intervals > {{min_intervals}}"#.to_string()),
            (QueryType::Elasticsearch, r#"network.direction: "outbound" | Date histogram interval=60s | Filter by low standard deviation of connection count"#.to_string()),
        ]),
        default_baseline: Some(0),
        data_sources: vec!["network_traffic".to_string(), "firewall_logs".to_string()],
        parameters: vec![
            QueryParameter {
                name: "min_intervals".to_string(),
                description: "Minimum beacon intervals to detect".to_string(),
                param_type: ParameterType::Integer,
                default_value: Some("20".to_string()),
                required: false,
            },
        ],
    });

    queries.push(BuiltInQuery {
        id: "hunt-c2-doh".to_string(),
        name: "DNS-over-HTTPS Detection".to_string(),
        description: "Detects use of DNS-over-HTTPS (DoH) to known DoH providers, which may bypass DNS monitoring.".to_string(),
        category: HuntingCategory::CommandAndControl,
        mitre_techniques: vec!["T1071.004".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=proxy dest_host IN ("dns.google", "cloudflare-dns.com", "dns.quad9.net", "doh.opendns.com") url="*/dns-query*" | stats count by src_ip, dest_host"#.to_string()),
            (QueryType::Elasticsearch, r#"url.domain: ("dns.google" OR "cloudflare-dns.com" OR "dns.quad9.net") AND url.path: *dns-query*"#.to_string()),
        ]),
        default_baseline: Some(5),
        data_sources: vec!["proxy_logs".to_string(), "network_traffic".to_string()],
        parameters: vec![],
    });

    queries.push(BuiltInQuery {
        id: "hunt-c2-encoded".to_string(),
        name: "Encoded Traffic Detection".to_string(),
        description: "Identifies HTTP requests with unusually high entropy in URLs or headers, suggesting encoded C2 traffic.".to_string(),
        category: HuntingCategory::CommandAndControl,
        mitre_techniques: vec!["T1132.001".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=proxy | eval url_len=len(url) | where url_len > 200 | regex url="(?:[A-Za-z0-9+/]{4}){10,}" | stats count by src_ip, dest_host | where count > {{threshold}}"#.to_string()),
            (QueryType::Elasticsearch, r#"url.full.length > 200 AND url.full: /[A-Za-z0-9+\\/]{40,}/"#.to_string()),
        ]),
        default_baseline: Some(5),
        data_sources: vec!["proxy_logs".to_string()],
        parameters: vec![
            QueryParameter {
                name: "threshold".to_string(),
                description: "Minimum encoded requests".to_string(),
                param_type: ParameterType::Integer,
                default_value: Some("5".to_string()),
                required: false,
            },
        ],
    });

    // =========================================================================
    // Privilege Escalation
    // =========================================================================

    queries.push(BuiltInQuery {
        id: "hunt-privesc-powershell".to_string(),
        name: "Suspicious PowerShell Execution".to_string(),
        description: "Detects PowerShell with encoded commands, download cradles, or suspicious invocations.".to_string(),
        category: HuntingCategory::PrivilegeEscalation,
        mitre_techniques: vec!["T1059.001".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=sysmon EventCode=1 Image="*powershell.exe" (CommandLine="*-enc*" OR CommandLine="*-encodedcommand*" OR CommandLine="*IEX*" OR CommandLine="*Invoke-Expression*" OR CommandLine="*downloadstring*" OR CommandLine="*bypass*")"#.to_string()),
            (QueryType::Elasticsearch, r#"event.code: "1" AND process.executable: *powershell.exe AND process.command_line: (*-enc* OR *IEX* OR *Invoke-Expression* OR *downloadstring* OR *bypass*)"#.to_string()),
        ]),
        default_baseline: Some(5),
        data_sources: vec!["sysmon".to_string(), "powershell_logs".to_string()],
        parameters: vec![],
    });

    queries.push(BuiltInQuery {
        id: "hunt-privesc-token".to_string(),
        name: "Token Manipulation".to_string(),
        description: "Detects token impersonation and privilege escalation via token manipulation.".to_string(),
        category: HuntingCategory::PrivilegeEscalation,
        mitre_techniques: vec!["T1134.001".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=wineventlog EventCode=4672 | where NOT match(Account_Name, "^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$") | stats count by Account_Name | where count > {{threshold}}"#.to_string()),
            (QueryType::Elasticsearch, r#"event.code: "4672" AND NOT user.name: (SYSTEM OR "LOCAL SERVICE" OR "NETWORK SERVICE")"#.to_string()),
        ]),
        default_baseline: Some(10),
        data_sources: vec!["windows_security_events".to_string()],
        parameters: vec![
            QueryParameter {
                name: "threshold".to_string(),
                description: "Maximum normal special privilege assignments".to_string(),
                param_type: ParameterType::Integer,
                default_value: Some("10".to_string()),
                required: false,
            },
        ],
    });

    queries.push(BuiltInQuery {
        id: "hunt-privesc-uac-bypass".to_string(),
        name: "UAC Bypass Attempts".to_string(),
        description: "Detects common UAC bypass techniques using auto-elevating binaries.".to_string(),
        category: HuntingCategory::PrivilegeEscalation,
        mitre_techniques: vec!["T1548.002".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=sysmon EventCode=1 (Image="*fodhelper.exe" OR Image="*computerdefaults.exe" OR Image="*sdclt.exe") IntegrityLevel=High | where NOT ParentImage="*explorer.exe""#.to_string()),
            (QueryType::Elasticsearch, r#"event.code: "1" AND process.executable: (*fodhelper.exe OR *computerdefaults.exe OR *sdclt.exe) AND NOT process.parent.executable: *explorer.exe"#.to_string()),
        ]),
        default_baseline: Some(0),
        data_sources: vec!["sysmon".to_string(), "edr_process_events".to_string()],
        parameters: vec![],
    });

    // =========================================================================
    // Discovery
    // =========================================================================

    queries.push(BuiltInQuery {
        id: "hunt-disc-portscan".to_string(),
        name: "Internal Port Scanning".to_string(),
        description: "Detects hosts making connections to many ports on internal targets, indicating scanning.".to_string(),
        category: HuntingCategory::Discovery,
        mitre_techniques: vec!["T1046".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=network src_ip=10.0.0.0/8 OR src_ip=172.16.0.0/12 OR src_ip=192.168.0.0/16 | stats dc(dest_port) as unique_ports by src_ip, dest_ip | where unique_ports > {{port_threshold}}"#.to_string()),
            (QueryType::Elasticsearch, r#"source.ip: (10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16) | Cardinality of destination.port by source.ip, destination.ip > threshold"#.to_string()),
        ]),
        default_baseline: Some(20),
        data_sources: vec!["network_traffic".to_string(), "firewall_logs".to_string()],
        parameters: vec![
            QueryParameter {
                name: "port_threshold".to_string(),
                description: "Unique ports threshold for scan detection".to_string(),
                param_type: ParameterType::Integer,
                default_value: Some("20".to_string()),
                required: false,
            },
        ],
    });

    queries.push(BuiltInQuery {
        id: "hunt-disc-ad-recon".to_string(),
        name: "Active Directory Reconnaissance".to_string(),
        description: "Detects excessive LDAP queries indicative of AD enumeration tools like BloodHound.".to_string(),
        category: HuntingCategory::Discovery,
        mitre_techniques: vec!["T1087.002".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=wineventlog EventCode=4662 | stats count by Account_Name, Workstation_Name | where count > {{threshold}} | sort -count"#.to_string()),
            (QueryType::Elasticsearch, r#"event.code: "4662" | Aggregate by user.name | Filter count > threshold"#.to_string()),
        ]),
        default_baseline: Some(100),
        data_sources: vec!["windows_security_events".to_string(), "ldap_logs".to_string()],
        parameters: vec![
            QueryParameter {
                name: "threshold".to_string(),
                description: "LDAP query count threshold".to_string(),
                param_type: ParameterType::Integer,
                default_value: Some("100".to_string()),
                required: false,
            },
        ],
    });

    queries.push(BuiltInQuery {
        id: "hunt-disc-enum".to_string(),
        name: "Network Enumeration Commands".to_string(),
        description: "Detects execution of common network enumeration commands (net, nltest, dsquery).".to_string(),
        category: HuntingCategory::Discovery,
        mitre_techniques: vec!["T1018".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=sysmon EventCode=1 (Image="*net.exe" OR Image="*nltest.exe" OR Image="*dsquery.exe" OR Image="*nslookup.exe" OR Image="*systeminfo.exe") | stats count by User, Image, CommandLine | where count > 3"#.to_string()),
            (QueryType::Elasticsearch, r#"event.code: "1" AND process.executable: (*net.exe OR *nltest.exe OR *dsquery.exe OR *nslookup.exe OR *systeminfo.exe)"#.to_string()),
        ]),
        default_baseline: Some(5),
        data_sources: vec!["sysmon".to_string(), "edr_process_events".to_string()],
        parameters: vec![],
    });

    // =========================================================================
    // Initial Access
    // =========================================================================

    queries.push(BuiltInQuery {
        id: "hunt-init-susplogin".to_string(),
        name: "Suspicious Login Patterns".to_string(),
        description: "Detects logins from unusual locations, impossible travel, or anomalous times.".to_string(),
        category: HuntingCategory::InitialAccess,
        mitre_techniques: vec!["T1078".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=auth action=success | iplocation src_ip | stats dc(Country) as countries, values(Country) as country_list by user | where countries > {{country_threshold}}"#.to_string()),
            (QueryType::Elasticsearch, r#"event.outcome: "success" AND event.category: "authentication" | Aggregate by user.name and geo.country_name | Filter distinct countries > threshold"#.to_string()),
        ]),
        default_baseline: Some(2),
        data_sources: vec!["authentication_logs".to_string(), "identity_provider".to_string()],
        parameters: vec![
            QueryParameter {
                name: "country_threshold".to_string(),
                description: "Maximum countries for normal access".to_string(),
                param_type: ParameterType::Integer,
                default_value: Some("2".to_string()),
                required: false,
            },
        ],
    });

    queries.push(BuiltInQuery {
        id: "hunt-init-mfa-bypass".to_string(),
        name: "MFA Bypass Attempts".to_string(),
        description: "Detects successful authentications that bypassed MFA or had MFA failures followed by success.".to_string(),
        category: HuntingCategory::InitialAccess,
        mitre_techniques: vec!["T1556.006".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=auth (mfa_status=failed OR mfa_status=bypassed) | transaction user maxspan=5m | where mvfind(mfa_status, "bypassed") >= 0 OR (mvfind(mfa_status, "failed") >= 0 AND mvfind(action, "success") >= 0)"#.to_string()),
            (QueryType::Elasticsearch, r#"(authentication.mfa_status: "failed" OR authentication.mfa_status: "bypassed") AND event.outcome: "success""#.to_string()),
        ]),
        default_baseline: Some(0),
        data_sources: vec!["authentication_logs".to_string(), "identity_provider".to_string()],
        parameters: vec![],
    });

    queries.push(BuiltInQuery {
        id: "hunt-init-phishing-click".to_string(),
        name: "Phishing Click-Through Detection".to_string(),
        description: "Correlates email delivery with subsequent suspicious URL visits from the same user.".to_string(),
        category: HuntingCategory::InitialAccess,
        mitre_techniques: vec!["T1566.002".to_string()],
        query_templates: HashMap::from([
            (QueryType::Splunk, r#"index=email action=delivered | join user [search index=proxy category=suspicious_url | rename src_user as user] | where _time_proxy - _time_email < 3600 | table user, subject, url, _time_email, _time_proxy"#.to_string()),
            (QueryType::Elasticsearch, r#"event.category: "email" AND event.action: "delivered" | Correlate with proxy suspicious_url visits within 1 hour"#.to_string()),
        ]),
        default_baseline: Some(0),
        data_sources: vec!["email_logs".to_string(), "proxy_logs".to_string()],
        parameters: vec![],
    });

    queries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_built_in_queries_count() {
        let queries = get_built_in_queries();
        assert!(
            queries.len() >= 20,
            "Expected at least 20 built-in queries, got {}",
            queries.len()
        );
    }

    #[test]
    fn test_all_categories_covered() {
        let queries = get_built_in_queries();
        let categories: std::collections::HashSet<_> =
            queries.iter().map(|q| q.category.clone()).collect();

        assert!(categories.contains(&HuntingCategory::CredentialAccess));
        assert!(categories.contains(&HuntingCategory::LateralMovement));
        assert!(categories.contains(&HuntingCategory::Persistence));
        assert!(categories.contains(&HuntingCategory::Exfiltration));
        assert!(categories.contains(&HuntingCategory::CommandAndControl));
        assert!(categories.contains(&HuntingCategory::PrivilegeEscalation));
        assert!(categories.contains(&HuntingCategory::Discovery));
        assert!(categories.contains(&HuntingCategory::InitialAccess));
    }

    #[test]
    fn test_queries_have_splunk_templates() {
        let queries = get_built_in_queries();
        for q in &queries {
            assert!(
                q.query_templates.contains_key(&QueryType::Splunk),
                "Query '{}' missing Splunk template",
                q.id
            );
        }
    }

    #[test]
    fn test_queries_have_elasticsearch_templates() {
        let queries = get_built_in_queries();
        for q in &queries {
            assert!(
                q.query_templates.contains_key(&QueryType::Elasticsearch),
                "Query '{}' missing Elasticsearch template",
                q.id
            );
        }
    }

    #[test]
    fn test_queries_have_unique_ids() {
        let queries = get_built_in_queries();
        let ids: std::collections::HashSet<_> = queries.iter().map(|q| q.id.clone()).collect();
        assert_eq!(ids.len(), queries.len(), "Duplicate query IDs found");
    }

    #[test]
    fn test_queries_have_mitre_techniques() {
        let queries = get_built_in_queries();
        for q in &queries {
            assert!(
                !q.mitre_techniques.is_empty(),
                "Query '{}' has no MITRE techniques",
                q.id
            );
            for tech in &q.mitre_techniques {
                assert!(
                    tech.starts_with('T'),
                    "Query '{}' has invalid MITRE technique: {}",
                    q.id,
                    tech
                );
            }
        }
    }

    #[test]
    fn test_queries_have_data_sources() {
        let queries = get_built_in_queries();
        for q in &queries {
            assert!(
                !q.data_sources.is_empty(),
                "Query '{}' has no data sources",
                q.id
            );
        }
    }

    #[test]
    fn test_queries_have_descriptions() {
        let queries = get_built_in_queries();
        for q in &queries {
            assert!(!q.name.is_empty(), "Query '{}' has empty name", q.id);
            assert!(
                !q.description.is_empty(),
                "Query '{}' has empty description",
                q.id
            );
        }
    }

    #[test]
    fn test_parameter_validation() {
        let queries = get_built_in_queries();
        for q in &queries {
            for param in &q.parameters {
                assert!(
                    !param.name.is_empty(),
                    "Query '{}' has param with empty name",
                    q.id
                );
                assert!(
                    !param.description.is_empty(),
                    "Query '{}' param '{}' has empty description",
                    q.id,
                    param.name
                );
            }
        }
    }

    #[test]
    fn test_hunting_category_display() {
        assert_eq!(
            format!("{}", HuntingCategory::CredentialAccess),
            "Credential Access"
        );
        assert_eq!(
            format!("{}", HuntingCategory::LateralMovement),
            "Lateral Movement"
        );
        assert_eq!(format!("{}", HuntingCategory::Persistence), "Persistence");
        assert_eq!(format!("{}", HuntingCategory::Exfiltration), "Exfiltration");
        assert_eq!(
            format!("{}", HuntingCategory::CommandAndControl),
            "Command & Control"
        );
        assert_eq!(
            format!("{}", HuntingCategory::PrivilegeEscalation),
            "Privilege Escalation"
        );
        assert_eq!(format!("{}", HuntingCategory::Discovery), "Discovery");
        assert_eq!(
            format!("{}", HuntingCategory::InitialAccess),
            "Initial Access"
        );
    }

    #[test]
    fn test_hunting_category_serialization() {
        let categories = vec![
            HuntingCategory::CredentialAccess,
            HuntingCategory::LateralMovement,
            HuntingCategory::Persistence,
            HuntingCategory::Exfiltration,
            HuntingCategory::CommandAndControl,
            HuntingCategory::PrivilegeEscalation,
            HuntingCategory::Discovery,
            HuntingCategory::InitialAccess,
        ];

        for cat in categories {
            let json = serde_json::to_string(&cat).unwrap();
            let back: HuntingCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(cat, back);
        }
    }

    #[test]
    fn test_parameter_type_serialization() {
        let types = vec![
            ParameterType::String,
            ParameterType::Integer,
            ParameterType::Duration,
            ParameterType::IpAddress,
            ParameterType::Hostname,
        ];

        for pt in types {
            let json = serde_json::to_string(&pt).unwrap();
            let back: ParameterType = serde_json::from_str(&json).unwrap();
            assert_eq!(pt, back);
        }
    }

    #[test]
    fn test_built_in_query_serialization() {
        let queries = get_built_in_queries();
        let first = &queries[0];

        let json = serde_json::to_string(first).unwrap();
        assert!(!json.is_empty());
        // Verify it can be deserialized
        let _back: BuiltInQuery = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn test_credential_access_queries() {
        let queries = get_built_in_queries();
        let cred_queries: Vec<_> = queries
            .iter()
            .filter(|q| q.category == HuntingCategory::CredentialAccess)
            .collect();
        assert!(
            cred_queries.len() >= 3,
            "Expected at least 3 credential access queries, got {}",
            cred_queries.len()
        );
    }

    #[test]
    fn test_lateral_movement_queries() {
        let queries = get_built_in_queries();
        let lat_queries: Vec<_> = queries
            .iter()
            .filter(|q| q.category == HuntingCategory::LateralMovement)
            .collect();
        assert!(
            lat_queries.len() >= 3,
            "Expected at least 3 lateral movement queries, got {}",
            lat_queries.len()
        );
    }
}
