# Host Actions

Actions for endpoint containment and investigation.

## isolate_host

Network-isolate a compromised host via EDR.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `host_id` | string | Yes | EDR host/agent ID |
| `reason` | string | No | Reason for isolation |

**Output:**

```json
{
  "isolation_id": "iso-abc123",
  "host_id": "aid:xyz789",
  "hostname": "WORKSTATION-01",
  "isolated_at": "2024-01-15T10:40:00Z",
  "status": "isolated"
}
```

**Behavior:**
- Host network access blocked
- EDR agent maintains cloud connectivity
- User notified (configurable)

**Rollback:** `unisolate_host`

**Policy:** Typically requires senior analyst or manager approval.

## unisolate_host

Remove network isolation from a host.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `host_id` | string | Yes | EDR host/agent ID |
| `reason` | string | No | Reason for removing isolation |

**Output:**

```json
{
  "host_id": "aid:xyz789",
  "hostname": "WORKSTATION-01",
  "unisolated_at": "2024-01-15T14:00:00Z",
  "status": "active"
}
```

## scan_host

Trigger on-demand malware scan on a host.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `host_id` | string | Yes | EDR host/agent ID |
| `scan_type` | string | No | `quick` or `full` (default: quick) |

**Output:**

```json
{
  "scan_id": "scan-abc123",
  "host_id": "aid:xyz789",
  "scan_type": "quick",
  "started_at": "2024-01-15T10:45:00Z",
  "status": "running"
}
```

**Note:** Scan results are retrieved separately as they may take time.

## Usage Examples

### Malware Response Playbook

```yaml
name: malware_response
steps:
  - action: isolate_host
    parameters:
      host_id: "{{ incident.raw_data.host_id }}"
      reason: "Malware detection - automated isolation"
    output: isolation

  - action: scan_host
    parameters:
      host_id: "{{ incident.raw_data.host_id }}"
      scan_type: full

  - action: create_ticket
    parameters:
      title: "Malware Incident - {{ incident.raw_data.hostname }}"
      priority: high

  - action: notify_user
    parameters:
      user: "{{ incident.raw_data.user }}"
      message: "Your workstation has been isolated due to a security incident"
```

### CLI Example

```bash
# Isolate compromised host
tw-cli action execute \
  --action isolate_host \
  --param host_id="aid:xyz789" \
  --param reason="Active malware infection"

# This action typically requires approval
# Check approval status:
tw-cli action status act-123456

# After investigation, remove isolation:
tw-cli action execute \
  --action unisolate_host \
  --param host_id="aid:xyz789" \
  --param reason="Malware cleaned, host verified"
```

### API Example

```bash
# Request host isolation
curl -X POST http://localhost:8080/api/incidents/INC-2024-001/actions \
  -H "Content-Type: application/json" \
  -d '{
    "action": "isolate_host",
    "parameters": {
      "host_id": "aid:xyz789",
      "reason": "Suspected compromise"
    }
  }'

# Response (if requires approval):
{
  "action_id": "act-abc123",
  "status": "pending_approval",
  "approval_level": "manager",
  "message": "Action requires SOC Manager approval"
}
```

## Policy Configuration

Host actions are typically high-impact and require approval:

```toml
[[policy.rules]]
name = "isolate_requires_approval"
action = "isolate_host"
approval_level = "senior"

[[policy.rules]]
name = "critical_isolate_requires_manager"
action = "isolate_host"
severity = ["critical"]
approval_level = "manager"
```
