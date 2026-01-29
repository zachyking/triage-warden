"""MITRE ATT&CK technique mapping for security analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from tw_ai.agents.models import MITRETechnique


# ============================================================================
# MITRE ATT&CK Mappings
# ============================================================================

@dataclass
class TechniqueInfo:
    """Information about a MITRE ATT&CK technique."""

    id: str
    name: str
    tactic: str
    keywords: list[str]


# Comprehensive mappings for common techniques
MITRE_MAPPINGS: dict[str, TechniqueInfo] = {
    # Initial Access
    "T1566": TechniqueInfo(
        id="T1566",
        name="Phishing",
        tactic="Initial Access",
        keywords=["phishing", "phish", "social engineering", "email attack"],
    ),
    "T1566.001": TechniqueInfo(
        id="T1566.001",
        name="Spearphishing Attachment",
        tactic="Initial Access",
        keywords=[
            "spearphishing", "malicious attachment", "email attachment",
            "weaponized document", "macro", "office document", "pdf attachment",
        ],
    ),
    "T1566.002": TechniqueInfo(
        id="T1566.002",
        name="Spearphishing Link",
        tactic="Initial Access",
        keywords=[
            "spearphishing link", "malicious link", "phishing url",
            "credential harvesting", "fake login", "phishing page",
        ],
    ),
    "T1566.003": TechniqueInfo(
        id="T1566.003",
        name="Spearphishing via Service",
        tactic="Initial Access",
        keywords=[
            "social media phishing", "messaging phishing", "teams phishing",
            "slack phishing", "discord phishing",
        ],
    ),
    "T1190": TechniqueInfo(
        id="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        keywords=[
            "web exploit", "application exploit", "rce", "remote code execution",
            "sql injection", "sqli", "xss", "web shell", "vulnerability exploit",
        ],
    ),
    "T1133": TechniqueInfo(
        id="T1133",
        name="External Remote Services",
        tactic="Initial Access",
        keywords=[
            "vpn compromise", "rdp brute force", "ssh brute force",
            "remote access", "citrix", "pulse secure",
        ],
    ),

    # Execution
    "T1059": TechniqueInfo(
        id="T1059",
        name="Command and Scripting Interpreter",
        tactic="Execution",
        keywords=["script", "interpreter", "command execution", "shell"],
    ),
    "T1059.001": TechniqueInfo(
        id="T1059.001",
        name="PowerShell",
        tactic="Execution",
        keywords=[
            "powershell", "pwsh", "encoded command", "base64 powershell",
            "bypass execution policy", "iex", "invoke-expression",
            "downloadstring", "encoded powershell", "obfuscated powershell",
        ],
    ),
    "T1059.003": TechniqueInfo(
        id="T1059.003",
        name="Windows Command Shell",
        tactic="Execution",
        keywords=[
            "cmd", "cmd.exe", "command prompt", "batch file", "bat file",
            "windows shell", "cmd execution",
        ],
    ),
    "T1059.005": TechniqueInfo(
        id="T1059.005",
        name="Visual Basic",
        tactic="Execution",
        keywords=[
            "vbscript", "vbs", "visual basic", "wscript", "cscript",
            "macro execution", "office macro",
        ],
    ),
    "T1059.006": TechniqueInfo(
        id="T1059.006",
        name="Python",
        tactic="Execution",
        keywords=["python", "python script", "py execution"],
    ),
    "T1059.007": TechniqueInfo(
        id="T1059.007",
        name="JavaScript",
        tactic="Execution",
        keywords=["javascript", "jscript", "js execution", "node.js"],
    ),
    "T1204": TechniqueInfo(
        id="T1204",
        name="User Execution",
        tactic="Execution",
        keywords=[
            "user execution", "user opened", "user clicked", "user ran",
            "clicked link", "opened attachment",
        ],
    ),
    "T1204.001": TechniqueInfo(
        id="T1204.001",
        name="Malicious Link",
        tactic="Execution",
        keywords=["clicked malicious link", "user clicked link"],
    ),
    "T1204.002": TechniqueInfo(
        id="T1204.002",
        name="Malicious File",
        tactic="Execution",
        keywords=["opened malicious file", "user opened attachment", "executed file"],
    ),

    # Persistence
    "T1547": TechniqueInfo(
        id="T1547",
        name="Boot or Logon Autostart Execution",
        tactic="Persistence",
        keywords=["autostart", "autorun", "startup", "boot persistence"],
    ),
    "T1547.001": TechniqueInfo(
        id="T1547.001",
        name="Registry Run Keys / Startup Folder",
        tactic="Persistence",
        keywords=[
            "run key", "registry persistence", "startup folder",
            "hklm\\software\\microsoft\\windows\\currentversion\\run",
            "hkcu\\software\\microsoft\\windows\\currentversion\\run",
        ],
    ),
    "T1053": TechniqueInfo(
        id="T1053",
        name="Scheduled Task/Job",
        tactic="Persistence",
        keywords=[
            "scheduled task", "schtasks", "cron", "at job",
            "task scheduler", "scheduled job",
        ],
    ),
    "T1053.005": TechniqueInfo(
        id="T1053.005",
        name="Scheduled Task",
        tactic="Persistence",
        keywords=["scheduled task", "schtasks", "windows task scheduler"],
    ),
    "T1078": TechniqueInfo(
        id="T1078",
        name="Valid Accounts",
        tactic="Persistence",
        keywords=[
            "valid account", "compromised account", "stolen credentials",
            "legitimate account", "account compromise",
        ],
    ),
    "T1543": TechniqueInfo(
        id="T1543",
        name="Create or Modify System Process",
        tactic="Persistence",
        keywords=["service creation", "system service", "daemon"],
    ),
    "T1543.003": TechniqueInfo(
        id="T1543.003",
        name="Windows Service",
        tactic="Persistence",
        keywords=["windows service", "service install", "sc create", "service persistence"],
    ),

    # Privilege Escalation
    "T1068": TechniqueInfo(
        id="T1068",
        name="Exploitation for Privilege Escalation",
        tactic="Privilege Escalation",
        keywords=[
            "privilege escalation exploit", "local privilege escalation",
            "lpe", "kernel exploit", "elevation of privilege",
        ],
    ),
    "T1055": TechniqueInfo(
        id="T1055",
        name="Process Injection",
        tactic="Privilege Escalation",
        keywords=[
            "process injection", "dll injection", "code injection",
            "thread injection", "hollowing",
        ],
    ),

    # Defense Evasion
    "T1027": TechniqueInfo(
        id="T1027",
        name="Obfuscated Files or Information",
        tactic="Defense Evasion",
        keywords=[
            "obfuscation", "obfuscated", "encoded", "base64", "encryption",
            "packed", "packer", "crypter", "string encoding",
        ],
    ),
    "T1027.001": TechniqueInfo(
        id="T1027.001",
        name="Binary Padding",
        tactic="Defense Evasion",
        keywords=["binary padding", "file padding", "null padding"],
    ),
    "T1027.002": TechniqueInfo(
        id="T1027.002",
        name="Software Packing",
        tactic="Defense Evasion",
        keywords=["packer", "packed", "upx", "themida", "vmprotect"],
    ),
    "T1070": TechniqueInfo(
        id="T1070",
        name="Indicator Removal",
        tactic="Defense Evasion",
        keywords=[
            "log deletion", "clear logs", "indicator removal", "evidence removal",
            "timestomping", "file deletion",
        ],
    ),
    "T1070.001": TechniqueInfo(
        id="T1070.001",
        name="Clear Windows Event Logs",
        tactic="Defense Evasion",
        keywords=["clear event logs", "wevtutil", "event log deletion"],
    ),
    "T1070.004": TechniqueInfo(
        id="T1070.004",
        name="File Deletion",
        tactic="Defense Evasion",
        keywords=["file deletion", "delete malware", "remove traces"],
    ),
    "T1562": TechniqueInfo(
        id="T1562",
        name="Impair Defenses",
        tactic="Defense Evasion",
        keywords=[
            "disable security", "disable antivirus", "disable defender",
            "disable edr", "impair defenses", "disable firewall",
        ],
    ),
    "T1036": TechniqueInfo(
        id="T1036",
        name="Masquerading",
        tactic="Defense Evasion",
        keywords=[
            "masquerading", "file rename", "legitimate process name",
            "disguise", "fake process",
        ],
    ),

    # Credential Access
    "T1003": TechniqueInfo(
        id="T1003",
        name="OS Credential Dumping",
        tactic="Credential Access",
        keywords=[
            "credential dump", "password dump", "hash dump", "mimikatz",
            "lsass dump", "sam dump", "credential theft", "credential extraction",
        ],
    ),
    "T1003.001": TechniqueInfo(
        id="T1003.001",
        name="LSASS Memory",
        tactic="Credential Access",
        keywords=[
            "lsass", "lsass.exe", "lsass memory", "procdump lsass",
            "comsvcs.dll", "minidump",
        ],
    ),
    "T1003.002": TechniqueInfo(
        id="T1003.002",
        name="Security Account Manager",
        tactic="Credential Access",
        keywords=["sam", "sam dump", "sam database", "registry sam"],
    ),
    "T1003.003": TechniqueInfo(
        id="T1003.003",
        name="NTDS",
        tactic="Credential Access",
        keywords=["ntds.dit", "ntds", "domain controller", "dcsync", "dcshad"],
    ),
    "T1110": TechniqueInfo(
        id="T1110",
        name="Brute Force",
        tactic="Credential Access",
        keywords=[
            "brute force", "password spray", "credential stuffing",
            "password guessing", "failed login", "authentication failure",
        ],
    ),
    "T1110.001": TechniqueInfo(
        id="T1110.001",
        name="Password Guessing",
        tactic="Credential Access",
        keywords=["password guessing", "brute force attack"],
    ),
    "T1110.003": TechniqueInfo(
        id="T1110.003",
        name="Password Spraying",
        tactic="Credential Access",
        keywords=["password spray", "password spraying", "spray attack"],
    ),
    "T1555": TechniqueInfo(
        id="T1555",
        name="Credentials from Password Stores",
        tactic="Credential Access",
        keywords=[
            "password store", "credential vault", "browser credentials",
            "keychain", "saved passwords",
        ],
    ),
    "T1558": TechniqueInfo(
        id="T1558",
        name="Steal or Forge Kerberos Tickets",
        tactic="Credential Access",
        keywords=[
            "kerberos", "golden ticket", "silver ticket", "kerberoasting",
            "ticket forging", "pass the ticket",
        ],
    ),

    # Discovery
    "T1087": TechniqueInfo(
        id="T1087",
        name="Account Discovery",
        tactic="Discovery",
        keywords=[
            "account discovery", "user enumeration", "net user",
            "whoami", "account enumeration",
        ],
    ),
    "T1083": TechniqueInfo(
        id="T1083",
        name="File and Directory Discovery",
        tactic="Discovery",
        keywords=["file discovery", "directory listing", "dir", "ls", "find files"],
    ),
    "T1057": TechniqueInfo(
        id="T1057",
        name="Process Discovery",
        tactic="Discovery",
        keywords=["process list", "tasklist", "ps", "process discovery"],
    ),
    "T1018": TechniqueInfo(
        id="T1018",
        name="Remote System Discovery",
        tactic="Discovery",
        keywords=[
            "network scan", "host discovery", "ping sweep",
            "arp scan", "remote system discovery",
        ],
    ),

    # Lateral Movement
    "T1021": TechniqueInfo(
        id="T1021",
        name="Remote Services",
        tactic="Lateral Movement",
        keywords=[
            "lateral movement", "remote service", "remote access",
            "network propagation", "remote execution",
        ],
    ),
    "T1021.001": TechniqueInfo(
        id="T1021.001",
        name="Remote Desktop Protocol",
        tactic="Lateral Movement",
        keywords=["rdp", "remote desktop", "mstsc", "rdp session"],
    ),
    "T1021.002": TechniqueInfo(
        id="T1021.002",
        name="SMB/Windows Admin Shares",
        tactic="Lateral Movement",
        keywords=[
            "smb", "admin share", "c$", "admin$", "psexec",
            "windows admin shares", "file share",
        ],
    ),
    "T1021.004": TechniqueInfo(
        id="T1021.004",
        name="SSH",
        tactic="Lateral Movement",
        keywords=["ssh", "secure shell", "ssh connection", "ssh session"],
    ),
    "T1021.006": TechniqueInfo(
        id="T1021.006",
        name="Windows Remote Management",
        tactic="Lateral Movement",
        keywords=["winrm", "wsman", "powershell remoting", "psremoting"],
    ),
    "T1570": TechniqueInfo(
        id="T1570",
        name="Lateral Tool Transfer",
        tactic="Lateral Movement",
        keywords=[
            "tool transfer", "copy malware", "transfer payload",
            "distribute malware",
        ],
    ),

    # Collection
    "T1005": TechniqueInfo(
        id="T1005",
        name="Data from Local System",
        tactic="Collection",
        keywords=[
            "data collection", "local data", "file collection",
            "data staging", "sensitive files",
        ],
    ),
    "T1114": TechniqueInfo(
        id="T1114",
        name="Email Collection",
        tactic="Collection",
        keywords=[
            "email collection", "mailbox access", "email theft",
            "outlook", "exchange", "pst files",
        ],
    ),
    "T1113": TechniqueInfo(
        id="T1113",
        name="Screen Capture",
        tactic="Collection",
        keywords=["screen capture", "screenshot", "screen recording"],
    ),

    # Command and Control
    "T1071": TechniqueInfo(
        id="T1071",
        name="Application Layer Protocol",
        tactic="Command and Control",
        keywords=[
            "c2", "c&c", "command and control", "beacon",
            "http c2", "dns c2", "covert channel",
        ],
    ),
    "T1071.001": TechniqueInfo(
        id="T1071.001",
        name="Web Protocols",
        tactic="Command and Control",
        keywords=["http c2", "https c2", "web c2", "web beacon"],
    ),
    "T1071.004": TechniqueInfo(
        id="T1071.004",
        name="DNS",
        tactic="Command and Control",
        keywords=["dns c2", "dns tunneling", "dns exfiltration"],
    ),
    "T1105": TechniqueInfo(
        id="T1105",
        name="Ingress Tool Transfer",
        tactic="Command and Control",
        keywords=[
            "tool download", "malware download", "payload download",
            "download and execute", "certutil download", "bitsadmin download",
        ],
    ),
    "T1572": TechniqueInfo(
        id="T1572",
        name="Protocol Tunneling",
        tactic="Command and Control",
        keywords=["tunneling", "ssh tunnel", "proxy", "socks", "port forwarding"],
    ),

    # Exfiltration
    "T1041": TechniqueInfo(
        id="T1041",
        name="Exfiltration Over C2 Channel",
        tactic="Exfiltration",
        keywords=[
            "data exfiltration", "exfil", "data theft", "data upload",
            "exfiltration over c2",
        ],
    ),
    "T1048": TechniqueInfo(
        id="T1048",
        name="Exfiltration Over Alternative Protocol",
        tactic="Exfiltration",
        keywords=[
            "dns exfiltration", "ftp exfiltration", "alternative protocol",
            "exfil over dns",
        ],
    ),
    "T1567": TechniqueInfo(
        id="T1567",
        name="Exfiltration Over Web Service",
        tactic="Exfiltration",
        keywords=[
            "cloud exfil", "dropbox exfil", "google drive exfil",
            "pastebin", "web service exfiltration",
        ],
    ),

    # Impact
    "T1486": TechniqueInfo(
        id="T1486",
        name="Data Encrypted for Impact",
        tactic="Impact",
        keywords=[
            "ransomware", "encryption", "file encryption", "crypto locker",
            "ransom", "data encrypted",
        ],
    ),
    "T1490": TechniqueInfo(
        id="T1490",
        name="Inhibit System Recovery",
        tactic="Impact",
        keywords=[
            "delete backups", "vssadmin delete", "shadow copy deletion",
            "disable recovery", "inhibit recovery",
        ],
    ),
    "T1489": TechniqueInfo(
        id="T1489",
        name="Service Stop",
        tactic="Impact",
        keywords=["stop service", "kill service", "service termination"],
    ),
}


def map_to_mitre(description: str) -> list[MITRETechnique]:
    """Map a description to MITRE ATT&CK techniques.

    Performs fuzzy matching of the description against known technique
    keywords to identify relevant MITRE ATT&CK techniques.

    Args:
        description: Text description of activity or behavior to map.

    Returns:
        List of MITRETechnique objects matching the description,
        sorted by relevance (more specific matches first).
    """
    if not description:
        return []

    description_lower = description.lower()
    matches: list[tuple[int, TechniqueInfo]] = []

    for technique_id, info in MITRE_MAPPINGS.items():
        match_score = _calculate_match_score(description_lower, info)
        if match_score > 0:
            matches.append((match_score, info))

    # Sort by score (higher is better) and prefer more specific techniques
    matches.sort(key=lambda x: (-x[0], len(x[1].id)))

    # Convert to MITRETechnique objects
    seen_ids = set()
    results = []

    for score, info in matches:
        # Skip if we already have this technique (prefer subtechnique)
        parent_id = info.id.split(".")[0]
        if info.id in seen_ids:
            continue

        # If this is a parent technique, check if we already have a subtechnique
        if "." not in info.id:
            has_subtechnique = any(
                tid.startswith(f"{info.id}.")
                for tid in seen_ids
            )
            if has_subtechnique:
                continue

        seen_ids.add(info.id)

        # Generate relevance explanation
        relevance = _generate_relevance(description, info)

        results.append(
            MITRETechnique(
                id=info.id,
                name=info.name,
                tactic=info.tactic,
                relevance=relevance,
            )
        )

    return results


def _calculate_match_score(description: str, info: TechniqueInfo) -> int:
    """Calculate how well a description matches a technique.

    Returns:
        Score from 0-100, where higher is a better match.
    """
    score = 0

    # Check each keyword
    for keyword in info.keywords:
        keyword_lower = keyword.lower()

        # Exact phrase match (highest value)
        if keyword_lower in description:
            # Longer matches are more valuable
            score += 10 + len(keyword_lower)

            # Bonus for exact word boundaries
            if re.search(rf"\b{re.escape(keyword_lower)}\b", description):
                score += 5

    # Check for technique name match
    if info.name.lower() in description:
        score += 20

    # Check for technique ID mention
    if info.id.lower() in description:
        score += 50  # Direct ID mention is very strong signal

    return score


def _generate_relevance(description: str, info: TechniqueInfo) -> str:
    """Generate a relevance explanation for why this technique matches."""
    matching_keywords = []
    description_lower = description.lower()

    for keyword in info.keywords:
        if keyword.lower() in description_lower:
            matching_keywords.append(keyword)

    if matching_keywords:
        keywords_str = ", ".join(matching_keywords[:3])
        return f"Matched keywords: {keywords_str}"
    elif info.name.lower() in description_lower:
        return f"Description mentions {info.name}"
    elif info.id.lower() in description_lower:
        return f"Technique ID {info.id} explicitly mentioned"
    else:
        return f"Related to {info.tactic} techniques"


def get_technique_info(technique_id: str) -> Optional[TechniqueInfo]:
    """Get information about a specific MITRE technique.

    Args:
        technique_id: MITRE ATT&CK technique ID (e.g., "T1059.001")

    Returns:
        TechniqueInfo if found, None otherwise.
    """
    return MITRE_MAPPINGS.get(technique_id)


def get_techniques_by_tactic(tactic: str) -> list[TechniqueInfo]:
    """Get all techniques for a given tactic.

    Args:
        tactic: Tactic name (e.g., "Initial Access", "Execution")

    Returns:
        List of TechniqueInfo objects for techniques in that tactic.
    """
    tactic_lower = tactic.lower()
    return [
        info for info in MITRE_MAPPINGS.values()
        if info.tactic.lower() == tactic_lower
    ]
