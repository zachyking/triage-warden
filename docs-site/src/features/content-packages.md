# Content Packages

Share playbooks, hunts, knowledge articles, and saved queries between Triage Warden instances using distributable content packages.

## Overview

The content package system (Stage 5.5) provides:

- **Import/export** of playbooks, hunts, knowledge, and queries
- **Package validation** before import
- **Conflict resolution** when imported content already exists
- **Semantic versioning** and compatibility tracking

## Package Format

A content package consists of a manifest and a list of content items:

```json
{
  "manifest": {
    "name": "phishing-response-kit",
    "version": "1.2.0",
    "description": "Playbooks and hunts for phishing incident response",
    "author": "Security Team",
    "license": "MIT",
    "tags": ["phishing", "email", "social-engineering"],
    "compatibility": ">=2.0.0"
  },
  "contents": [
    {
      "type": "playbook",
      "name": "phishing-triage",
      "data": { "stages": [...] }
    },
    {
      "type": "hunt",
      "name": "credential-harvesting-detection",
      "data": { "hypothesis": "...", "queries": [...] }
    },
    {
      "type": "knowledge",
      "title": "Phishing Indicators Guide",
      "content": "Common phishing indicators include..."
    },
    {
      "type": "query",
      "name": "failed-logins-by-source",
      "query_type": "siem",
      "query": "event.type:authentication AND event.outcome:failure | stats count by source.ip"
    }
  ]
}
```

### Content Types

| Type | Description | Stored in |
|------|-------------|-----------|
| `playbook` | Automated response workflows | Playbook repository |
| `hunt` | Threat hunt definitions with queries | Hunt store |
| `knowledge` | Reference articles and guides | Knowledge base |
| `query` | Saved search queries | Query library |

### Manifest Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique package name |
| `version` | Yes | Semantic version string |
| `description` | Yes | What the package contains |
| `author` | Yes | Creator name or organization |
| `license` | No | License identifier (e.g., "MIT", "Apache-2.0") |
| `tags` | No | Categorization tags |
| `compatibility` | No | Minimum Triage Warden version required |

## Importing Packages

```bash
curl -X POST http://localhost:8080/api/v1/packages/import \
  -H "Content-Type: application/json" \
  -d '{
    "package": { ... },
    "conflict_resolution": "skip"
  }'
```

Response:

```json
{
  "imported": 3,
  "skipped": 1,
  "errors": []
}
```

### Conflict Resolution

When an imported item has the same name as an existing one:

| Mode | Behavior |
|------|----------|
| `skip` | Keep existing, ignore the imported item (default) |
| `overwrite` | Replace existing with the imported version |
| `rename` | Import with a modified name (e.g., `phishing-triage-imported-1`) |

## Validating Packages

Check a package for errors before importing:

```bash
curl -X POST http://localhost:8080/api/v1/packages/validate \
  -H "Content-Type: application/json" \
  -d '{ "manifest": { ... }, "contents": [ ... ] }'
```

Response:

```json
{
  "valid": true,
  "warnings": ["Package author is not specified"],
  "errors": [],
  "content_count": 4
}
```

Validation checks:

- Package name and version are present
- All content items have non-empty names
- Warns on missing author or empty content list

## Exporting Content

### Export a Playbook

```bash
curl -X POST http://localhost:8080/api/v1/packages/export/playbook/{playbook_id} \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-playbook-package",
    "version": "1.0.0",
    "description": "Exported playbook",
    "author": "Security Team",
    "license": "MIT",
    "tags": ["phishing"]
  }'
```

### Export a Hunt

```bash
curl -X POST http://localhost:8080/api/v1/packages/export/hunt/{hunt_id} \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-hunt-package",
    "version": "1.0.0",
    "description": "Exported hunt",
    "author": "Threat Hunting Team"
  }'
```

Both return the full package JSON that can be shared or imported into another instance.
