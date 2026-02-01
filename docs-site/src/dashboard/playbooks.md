# Playbooks

Managing playbooks in the web dashboard.

## Playbook List

Access at `/playbooks`

### Views

- **Active**: Currently enabled playbooks
- **Inactive**: Disabled playbooks
- **All**: Complete list

### Information Displayed

- Name and description
- Trigger conditions
- Last run time
- Success rate

## Creating Playbooks

Click "New Playbook" button.

### Basic Information

- **Name**: Unique identifier
- **Description**: What this playbook does
- **Version**: Semantic version

### Triggers

Configure when playbook runs:
- **Incident Type**: Phishing, malware, etc.
- **Auto Run**: Run automatically on new incidents
- **Conditions**: Additional criteria

### Variables

Define playbook variables:

```yaml
quarantine_threshold: 0.7
notification_channel: "#security"
```

## Step Editor

Visual editor for playbook steps.

### Adding Steps

1. Click "Add Step"
2. Select action type
3. Configure parameters
4. Set output variable name

### Step Types

- **Action**: Execute an action
- **Condition**: Branch logic
- **AI Analysis**: Get AI verdict
- **Parallel**: Run steps concurrently

### Connections

- Drag to reorder steps
- Connect condition branches
- Set dependencies

## Testing Playbooks

### Dry Run

1. Click "Test"
2. Select or create test incident
3. Toggle "Dry Run"
4. View step-by-step execution

### With Live Data

1. Click "Test"
2. Select real incident
3. Leave "Dry Run" off
4. Actions will execute (with approval)

## Execution History

View past executions:
- Execution timestamp
- Incident processed
- Steps completed
- Final verdict
- Duration

Click execution for detailed trace.

## Import/Export

### Export

1. Select playbook
2. Click "Export"
3. Download YAML file

### Import

1. Click "Import"
2. Upload YAML file
3. Review parsed playbook
4. Click "Create"

## Playbook Versions

Playbooks are versioned:

1. Edit playbook
2. Bump version number
3. Save as new version
4. Old version kept for rollback

View version history and compare changes.
