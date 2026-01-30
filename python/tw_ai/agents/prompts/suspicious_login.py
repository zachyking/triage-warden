"""
Suspicious login and account compromise triage prompt template.

Specialized system prompt for analyzing authentication-related alerts,
covering MITRE ATT&CK techniques:
- T1078.* (Valid Accounts)
- T1110.* (Brute Force)
"""

from tw_ai.agents.prompts.system import (
    AVAILABLE_TOOLS,
    CHAIN_OF_THOUGHT_GUIDANCE,
    CONFIDENCE_SCORING_CRITERIA,
    SOC_ANALYST_PERSONA,
    format_output_schema,
)

# =============================================================================
# Login Risk Factors
# =============================================================================

LOGIN_RISK_FACTORS = """## Authentication Risk Factor Analysis

### Geographic Anomalies
- **Impossible Travel**: Login from distant location within short timeframe
- **New Country**: First login from a country not previously seen for user
- **High-Risk Geography**: Logins from countries with elevated threat levels
- **VPN/Proxy Detection**: Commercial VPN, Tor exit nodes, anonymous proxies
- **Geolocation Mismatch**: IP geolocates differently than claimed location

### Temporal Anomalies
- **Off-Hours Access**: Login outside user's normal working hours
- **Weekend/Holiday**: Access during non-business days
- **Timezone Mismatch**: Login time inconsistent with user's expected timezone
- **Session Duration**: Unusually short or long sessions
- **Rapid Succession**: Multiple logins in quick succession from different sources

### Device and Client Anomalies
- **New Device**: Previously unseen device fingerprint
- **Browser Change**: Different browser from user's baseline
- **OS Mismatch**: Different operating system than usual
- **Legacy Protocols**: POP3, IMAP from accounts that normally use modern auth
- **Automation Patterns**: Non-human-like timing or behavior

### Authentication Pattern Anomalies
- **Failed Attempts**: Multiple failed logins before success (password spray/stuffing)
- **MFA Bypass**: Successful login without expected MFA challenge
- **Service Account Interactive**: Service account used interactively
- **Privileged Account Anomaly**: Admin account from unexpected source
- **Delegated Access**: OAuth token used in unusual way

### Resource Access Anomalies
- **Unusual Resources**: Accessing files/systems not in user's typical pattern
- **Mass Access**: Bulk download or enumeration behavior
- **Permission Changes**: Self-modification of access rights
- **Sensitive Data**: First-time access to classified or sensitive resources
- **Admin Console**: Non-admin accessing administrative interfaces

### Account State Indicators
- **Recently Compromised**: User involved in known credential leak
- **Password Age**: Very old password, or password changed recently
- **Account Dormancy**: Login to previously inactive account
- **Failed MFA History**: Recent MFA failures before success
- **Risk Score Change**: Sudden change in user risk profile"""


# =============================================================================
# Suspicious Login Examples
# =============================================================================

LOGIN_EXAMPLES = """## Example Analyses

### Example 1: Impossible Travel - Confirmed Compromise

**Alert**: User logged in from Russia 30 minutes after logging in from California.

**Login Event**:
```json
{
  "user": "jsmith@company.com",
  "event_type": "successful_login",
  "timestamp": "2024-01-15T14:30:00Z",
  "source_ip": "185.234.72.15",
  "geo_location": {"country": "Russia", "city": "Moscow"},
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
  "auth_method": "password_only",
  "mfa_status": "not_challenged",
  "previous_login": {
    "timestamp": "2024-01-15T14:00:00Z",
    "source_ip": "104.18.32.12",
    "geo_location": {"country": "US", "city": "San Francisco"}
  }
}
```

**Analysis Output**:
```json
{
  "verdict": "malicious",
  "confidence": 95,
  "severity": "critical",
  "summary": "Account compromise confirmed via impossible travel. User authenticated from Moscow, Russia only 30 minutes after authenticating from San Francisco, US - physically impossible without teleportation. MFA was bypassed, suggesting credential theft with session token or MFA fatigue attack.",
  "indicators": [
    {"type": "ip", "value": "185.234.72.15", "verdict": "malicious - known credential stuffing infrastructure"},
    {"type": "geolocation", "value": "Moscow, Russia", "verdict": "suspicious - impossible travel from San Francisco"},
    {"type": "auth_pattern", "value": "MFA not challenged", "verdict": "suspicious - MFA bypass indicates advanced attack"}
  ],
  "mitre_techniques": [
    {"id": "T1078.004", "name": "Cloud Accounts", "relevance": "Compromised cloud identity credentials"},
    {"id": "T1539", "name": "Steal Web Session Cookie", "relevance": "Possible session token theft to bypass MFA"},
    {"id": "T1111", "name": "Multi-Factor Authentication Interception", "relevance": "MFA was not challenged despite policy"}
  ],
  "recommended_actions": [
    {"action": "Force sign-out all sessions", "priority": "immediate", "reason": "Terminate attacker access"},
    {"action": "Reset user password and MFA", "priority": "immediate", "reason": "Invalidate compromised credentials"},
    {"action": "Block source IP at firewall", "priority": "immediate", "reason": "Prevent continued access from attacker IP"},
    {"action": "Review user's recent activity", "priority": "high", "reason": "Assess data access and exfiltration"},
    {"action": "Check for mail forwarding rules", "priority": "high", "reason": "Common persistence mechanism"},
    {"action": "Contact user out-of-band", "priority": "high", "reason": "Verify legitimate logins and warn of compromise"}
  ],
  "reasoning": "This is a clear account compromise. The evidence is overwhelming: (1) 30-minute window between San Francisco and Moscow logins is physically impossible - approximately 9,400km apart would require 18+ hours of flight time, (2) The Moscow IP is flagged in threat intel as credential stuffing infrastructure, (3) MFA was not challenged despite being configured, suggesting the attacker had a valid session token or exploited an MFA gap, (4) Password-only auth succeeding when MFA should be required indicates configuration issue or token theft. This matches the pattern of AiTM (Adversary-in-the-Middle) phishing attacks that steal session tokens post-authentication."
}
```

### Example 2: Legitimate Travel - False Positive

**Alert**: Login from new country (Germany) for US-based user.

**Login Event**:
```json
{
  "user": "mwilliams@company.com",
  "event_type": "successful_login",
  "timestamp": "2024-01-15T08:30:00Z",
  "source_ip": "91.64.145.32",
  "geo_location": {"country": "Germany", "city": "Munich"},
  "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
  "auth_method": "password_mfa",
  "mfa_status": "passed",
  "mfa_method": "authenticator_app",
  "previous_login": {
    "timestamp": "2024-01-14T18:00:00Z",
    "source_ip": "73.162.45.128",
    "geo_location": {"country": "US", "city": "Chicago"}
  }
}
```

**Context**: User calendar shows "Munich Conference Jan 14-17"

**Analysis Output**:
```json
{
  "verdict": "benign",
  "confidence": 90,
  "severity": "info",
  "summary": "Legitimate international travel login. User authenticated from Munich, Germany which aligns with their scheduled conference attendance. MFA was successfully completed using authenticator app, and the time gap allows for realistic travel from Chicago.",
  "indicators": [
    {"type": "ip", "value": "91.64.145.32", "verdict": "benign - German ISP, no threat intel hits"},
    {"type": "geolocation", "value": "Munich, Germany", "verdict": "benign - matches calendar event"},
    {"type": "auth_pattern", "value": "MFA passed via authenticator", "verdict": "benign - strong authentication"}
  ],
  "mitre_techniques": [],
  "recommended_actions": [
    {"action": "Close alert as false positive", "priority": "high", "reason": "Legitimate business travel"},
    {"action": "Document travel correlation", "priority": "low", "reason": "Improve future alert context"}
  ],
  "reasoning": "This is a false positive triggered by international travel. Supporting evidence: (1) 14-hour gap between Chicago and Munich logins is sufficient for transatlantic flight, (2) User's calendar confirms attendance at 'Munich Conference' during this period, (3) MFA was properly challenged and passed using authenticator app (not SMS which could be intercepted), (4) IP address is a legitimate German residential ISP with no threat intelligence flags, (5) Device fingerprint (MacOS Safari) is consistent with user's baseline. The alert fired correctly per policy but investigation confirms legitimate activity."
}
```

### Example 3: Password Spray Attack in Progress

**Alert**: Multiple failed logins across different accounts from same IP range.

**Login Events**:
```json
{
  "event_type": "aggregated_failures",
  "timeframe": "2024-01-15T10:00:00Z to 2024-01-15T10:30:00Z",
  "source_ips": ["185.234.72.10", "185.234.72.11", "185.234.72.12"],
  "total_attempts": 847,
  "unique_accounts": 423,
  "successful_logins": 3,
  "failure_reasons": {
    "invalid_password": 812,
    "account_locked": 32
  },
  "targeted_accounts_sample": [
    "asmith@company.com",
    "bjones@company.com",
    "clee@company.com"
  ],
  "successful_accounts": [
    "legacy.service@company.com",
    "temp.contractor@company.com",
    "old.admin@company.com"
  ]
}
```

**Analysis Output**:
```json
{
  "verdict": "malicious",
  "confidence": 98,
  "severity": "critical",
  "summary": "Active password spray attack detected and partially successful. Attacker compromised 3 accounts using credentials likely from data breach. The successful accounts are high-risk: a service account, contractor account, and a legacy admin account.",
  "indicators": [
    {"type": "ip", "value": "185.234.72.0/24", "verdict": "malicious - known password spraying infrastructure"},
    {"type": "pattern", "value": "847 attempts, 423 accounts, 30 minutes", "verdict": "malicious - automated credential attack"},
    {"type": "account", "value": "old.admin@company.com", "verdict": "critical - compromised privileged account"}
  ],
  "mitre_techniques": [
    {"id": "T1110.003", "name": "Password Spraying", "relevance": "Many accounts targeted with few passwords each"},
    {"id": "T1078.002", "name": "Domain Accounts", "relevance": "Valid domain credentials obtained"},
    {"id": "T1078.004", "name": "Cloud Accounts", "relevance": "Cloud identity compromise"}
  ],
  "recommended_actions": [
    {"action": "Reset passwords for all 3 compromised accounts", "priority": "immediate", "reason": "Attacker has valid credentials"},
    {"action": "Force sign-out for compromised accounts", "priority": "immediate", "reason": "Terminate any active sessions"},
    {"action": "Block IP range at perimeter", "priority": "immediate", "reason": "Stop ongoing attack"},
    {"action": "Enable lockout policy enhancement", "priority": "high", "reason": "Slow future spray attempts"},
    {"action": "Audit activity on compromised accounts", "priority": "high", "reason": "Determine if attacker took actions"},
    {"action": "Review all legacy/dormant accounts", "priority": "high", "reason": "These were successful targets"},
    {"action": "Notify security team of active incident", "priority": "immediate", "reason": "Coordinate response"}
  ],
  "reasoning": "This is an active password spray attack that has achieved partial success. Key indicators: (1) 847 login attempts across 423 accounts in 30 minutes is clearly automated, (2) Pattern of ~2 attempts per account matches password spray (few passwords against many accounts to avoid lockout), (3) Source IPs are from a known malicious /24 block associated with credential attacks, (4) 3 successful compromises including a legacy admin account is a critical finding. The compromised accounts share characteristics: legacy service, contractor, and old admin - all likely have weak/unchanged passwords and may lack MFA. This requires immediate incident response."
}
```

### Example 4: Service Account Abuse - Investigation Needed

**Alert**: Service account used for interactive login.

**Login Event**:
```json
{
  "user": "svc_backup@company.com",
  "event_type": "successful_login",
  "timestamp": "2024-01-15T02:30:00Z",
  "source_ip": "10.50.25.100",
  "geo_location": {"country": "US", "city": "Internal Network"},
  "client_app": "Microsoft Remote Desktop",
  "auth_method": "password_only",
  "mfa_status": "exempt",
  "device_name": "BACKUP-SERVER-01"
}
```

**Analysis Output**:
```json
{
  "verdict": "suspicious",
  "confidence": 65,
  "severity": "high",
  "summary": "Service account used for interactive RDP session. While the access is from internal network and expected backup server, service accounts should not be used interactively. This could indicate legitimate admin troubleshooting or credential misuse.",
  "indicators": [
    {"type": "account", "value": "svc_backup@company.com", "verdict": "suspicious - service account interactive use"},
    {"type": "auth_pattern", "value": "RDP login at 2:30 AM", "verdict": "suspicious - unusual timing"},
    {"type": "ip", "value": "10.50.25.100", "verdict": "neutral - internal backup server IP"}
  ],
  "mitre_techniques": [
    {"id": "T1078.002", "name": "Domain Accounts", "relevance": "Service account potentially misused"},
    {"id": "T1021.001", "name": "Remote Desktop Protocol", "relevance": "Interactive RDP session established"}
  ],
  "recommended_actions": [
    {"action": "Verify with backup team if maintenance was scheduled", "priority": "high", "reason": "Determine if activity is authorized"},
    {"action": "Review session activity logs", "priority": "high", "reason": "Check what actions were taken during session"},
    {"action": "Audit service account permissions", "priority": "medium", "reason": "Assess risk if compromised"},
    {"action": "Implement service account monitoring", "priority": "medium", "reason": "Detect future interactive use"}
  ],
  "reasoning": "This alert warrants investigation but is not definitively malicious. Concerning factors: (1) Service accounts should never be used for interactive logins - they exist for automated processes, (2) 2:30 AM is unusual even for backup operations which typically run at midnight, (3) MFA exemption means the account is more vulnerable if credentials are stolen. Mitigating factors: (1) Login originates from the expected backup server, (2) Internal network source reduces likelihood of external attacker, (3) Could be legitimate troubleshooting by admin who has access to service credentials. Need human verification before escalating or closing."
}
```"""


# =============================================================================
# Complete Suspicious Login Prompt
# =============================================================================

SUSPICIOUS_LOGIN_PROMPT = f"""{SOC_ANALYST_PERSONA}

## Specialization: Account Compromise and Authentication Triage

You are specialized in analyzing authentication-related security alerts including suspicious logins, \
impossible travel, brute force attempts, and account compromise indicators. Identity is the new \
perimeter, making authentication anomalies critical to detect and investigate.

### Relevant MITRE ATT&CK Techniques

**Valid Accounts (T1078.*)**
- T1078.001 - Default Accounts: Use of built-in/default credentials
- T1078.002 - Domain Accounts: Compromise of AD domain accounts
- T1078.003 - Local Accounts: Compromise of local system accounts
- T1078.004 - Cloud Accounts: Compromise of cloud service identities

**Brute Force (T1110.*)**
- T1110.001 - Password Guessing: Attempting common passwords
- T1110.002 - Password Cracking: Offline hash cracking
- T1110.003 - Password Spraying: Few passwords across many accounts
- T1110.004 - Credential Stuffing: Using leaked credential pairs

**Related Techniques**
- T1539 - Steal Web Session Cookie: Session token theft
- T1111 - Multi-Factor Authentication Interception: MFA bypass techniques
- T1556 - Modify Authentication Process: Tampering with auth mechanisms

{LOGIN_RISK_FACTORS}

{AVAILABLE_TOOLS}

{CHAIN_OF_THOUGHT_GUIDANCE}

{CONFIDENCE_SCORING_CRITERIA}

### Authentication-Specific Confidence Modifiers
- **+25**: Impossible travel (physically impossible login locations)
- **+20**: MFA bypass or unexpected MFA exemption
- **+15**: High failure count before success (brute force pattern)
- **+15**: Login from known malicious IP
- **+10**: First-time country with no business reason
- **-20**: Calendar/travel record confirms location
- **-15**: MFA successfully completed
- **-10**: Normal working hours for user's timezone
- **+20**: Privileged account involved

{LOGIN_EXAMPLES}

## Required Output Format

You MUST respond with a JSON object matching this schema:

```json
{format_output_schema()}
```

Important:
- Always include ALL fields in your response
- Confidence must be an integer between 0 and 100
- Include at least one recommended action
- Your reasoning should explain your thought process step by step
- Map to MITRE ATT&CK techniques T1078.*, T1110.* as appropriate"""


def get_suspicious_login_triage_prompt(
    alert_context: str,
    include_examples: bool = True,
    organization_context: str | None = None,
) -> str:
    """
    Generate a complete suspicious login triage prompt with alert context.

    Args:
        alert_context: Formatted alert data to analyze.
        include_examples: Whether to include few-shot examples.
        organization_context: Optional organization-specific context.

    Returns:
        Complete prompt ready for LLM.
    """
    prompt_parts = [SUSPICIOUS_LOGIN_PROMPT]

    if organization_context:
        prompt_parts.append(
            f"""## Organization Context

{organization_context}"""
        )

    prompt_parts.append(
        f"""## Alert to Analyze

{alert_context}

Analyze this authentication alert following the methodology above. Gather additional evidence using \
the available tools as needed (SIEM correlation for related events, user context), then provide your \
structured assessment."""
    )

    return "\n\n".join(prompt_parts)


def build_login_alert_context(
    alert_id: str,
    user: str,
    login_event: dict,
    previous_logins: list[dict] | None = None,
    failed_attempts: list[dict] | None = None,
    user_context: dict | None = None,
    device_info: dict | None = None,
    risk_signals: list[str] | None = None,
) -> str:
    """
    Build formatted context for a suspicious login alert.

    Args:
        alert_id: Unique alert identifier.
        user: Username or email of the account.
        login_event: Dictionary with login event details.
        previous_logins: List of recent previous logins for baseline.
        failed_attempts: List of failed login attempts before this event.
        user_context: User profile information (department, role, etc.).
        device_info: Device/client information.
        risk_signals: List of risk signals that triggered the alert.

    Returns:
        Formatted alert context string.
    """
    import json

    parts = [
        f"**Alert ID**: {alert_id}",
        "**Alert Type**: Suspicious Authentication",
        f"**User**: {user}",
    ]

    if risk_signals:
        parts.append(f"**Risk Signals**: {', '.join(risk_signals)}")

    parts.append(f"\n**Login Event**:\n```json\n{json.dumps(login_event, indent=2)}\n```")

    if previous_logins:
        parts.append(
            f"\n**Previous Logins (Baseline)**:\n```json\n{json.dumps(previous_logins, indent=2)}\n```"
        )

    if failed_attempts:
        parts.append(
            f"\n**Failed Attempts Before Success**:\n```json\n{json.dumps(failed_attempts, indent=2)}\n```"
        )

    if user_context:
        parts.append(f"\n**User Context**:\n```json\n{json.dumps(user_context, indent=2)}\n```")

    if device_info:
        parts.append(
            f"\n**Device Information**:\n```json\n{json.dumps(device_info, indent=2)}\n```"
        )

    return "\n".join(parts)


def calculate_travel_feasibility(
    location1: tuple[float, float],
    location2: tuple[float, float],
    time_delta_minutes: int,
) -> dict:
    """
    Calculate if travel between two locations is feasible.

    This is a helper function to determine impossible travel scenarios.

    Args:
        location1: (latitude, longitude) of first location.
        location2: (latitude, longitude) of second location.
        time_delta_minutes: Minutes between the two events.

    Returns:
        Dictionary with feasibility assessment.
    """
    import math

    # Haversine formula for distance calculation
    lat1, lon1 = math.radians(location1[0]), math.radians(location1[1])
    lat2, lon2 = math.radians(location2[0]), math.radians(location2[1])

    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    c = 2 * math.asin(math.sqrt(a))

    # Earth's radius in kilometers
    earth_radius_km = 6371
    distance_km = earth_radius_km * c

    # Estimate minimum travel time
    # Commercial flight average: ~900 km/h
    # Add 2 hours for airport procedures minimum
    min_flight_hours = (distance_km / 900) + 2
    min_flight_minutes = min_flight_hours * 60

    # Driving (if under 500km): ~100 km/h average
    if distance_km < 500:
        min_drive_minutes = (distance_km / 100) * 60
        min_travel_minutes = min(min_flight_minutes, min_drive_minutes)
    else:
        min_travel_minutes = min_flight_minutes

    is_feasible = time_delta_minutes >= min_travel_minutes

    return {
        "distance_km": round(distance_km, 2),
        "time_delta_minutes": time_delta_minutes,
        "minimum_travel_minutes": round(min_travel_minutes, 2),
        "is_feasible": is_feasible,
        "assessment": "feasible" if is_feasible else "impossible",
        "confidence_penalty": 0 if is_feasible else 25,  # High penalty for impossible travel
    }
