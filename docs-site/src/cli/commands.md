# CLI Commands

Detailed reference for all CLI commands.

## incident

Manage security incidents.

### list

```bash
tw-cli incident list [OPTIONS]

Options:
  --status <STATUS>      Filter by status (open, triaged, resolved)
  --severity <SEVERITY>  Filter by severity
  --type <TYPE>          Filter by incident type
  --limit <N>            Maximum results (default: 20)
  --offset <N>           Skip first N results
  --sort <FIELD>         Sort field (created_at, severity)
  --desc                 Sort descending
```

### get

```bash
tw-cli incident get <ID> [OPTIONS]

Options:
  --format <FORMAT>      Output format (table, json, yaml)
  --include-actions      Include action history
  --include-enrichment   Include enrichment data
```

### create

```bash
tw-cli incident create [OPTIONS]

Options:
  --type <TYPE>          Incident type (required)
  --source <SOURCE>      Incident source (required)
  --severity <SEVERITY>  Initial severity (default: medium)
  --data <JSON>          Raw incident data as JSON
  --file <FILE>          Read data from file
  --auto-triage          Run triage after creation
```

### update

```bash
tw-cli incident update <ID> [OPTIONS]

Options:
  --severity <SEVERITY>  Update severity
  --status <STATUS>      Update status
  --assignee <USER>      Assign to user
```

### resolve

```bash
tw-cli incident resolve <ID> [OPTIONS]

Options:
  --resolution <TEXT>    Resolution notes
  --false-positive       Mark as false positive
```

## action

Execute and manage actions.

### execute

```bash
tw-cli action execute [OPTIONS]

Options:
  --incident <ID>        Associated incident
  --action <NAME>        Action to execute (required)
  --param <KEY=VALUE>    Action parameter (repeatable)
  --emergency            Emergency override (manager only)
```

### list

```bash
tw-cli action list [OPTIONS]

Options:
  --incident <ID>        Filter by incident
  --status <STATUS>      Filter by status
  --pending              Show only pending approval
```

### get

```bash
tw-cli action get <ID>
```

### approve

```bash
tw-cli action approve <ID> [OPTIONS]

Options:
  --comment <TEXT>       Approval comment
```

### reject

```bash
tw-cli action reject <ID> [OPTIONS]

Options:
  --reason <TEXT>        Rejection reason (required)
```

### rollback

```bash
tw-cli action rollback <ID> [OPTIONS]

Options:
  --reason <TEXT>        Rollback reason
```

## triage

Run AI triage.

### run

```bash
tw-cli triage run [OPTIONS]

Options:
  --incident <ID>        Incident to triage (required)
  --playbook <NAME>      Specific playbook
  --model <MODEL>        AI model override
  --wait                 Wait for completion
```

### status

```bash
tw-cli triage status <TRIAGE_ID>
```

## playbook

Manage playbooks.

### list

```bash
tw-cli playbook list [OPTIONS]

Options:
  --enabled              Only enabled playbooks
  --trigger-type <TYPE>  Filter by trigger type
```

### get

```bash
tw-cli playbook get <ID>
```

### add

```bash
tw-cli playbook add <FILE>
```

### update

```bash
tw-cli playbook update <ID> <FILE>
```

### delete

```bash
tw-cli playbook delete <ID>
```

### run

```bash
tw-cli playbook run <ID> [OPTIONS]

Options:
  --incident <ID>        Incident to process
  --var <KEY=VALUE>      Override variable (repeatable)
  --dry-run              Don't execute actions
```

### test

```bash
tw-cli playbook test <NAME> [OPTIONS]

Options:
  --incident <ID>        Use existing incident
  --data <JSON>          Use mock data
  --dry-run              Don't execute actions
```

### validate

```bash
tw-cli playbook validate <FILE>
```

### export

```bash
tw-cli playbook export <ID> [OPTIONS]

Options:
  -o, --output <FILE>    Output file (default: stdout)
```

## policy

Manage policy rules.

### list

```bash
tw-cli policy list
```

### add

```bash
tw-cli policy add [OPTIONS]

Options:
  --name <NAME>          Rule name (required)
  --action <ACTION>      Action to match
  --pattern <PATTERN>    Action pattern (glob)
  --severity <SEVERITY>  Severity condition
  --approval-level <L>   Required approval level
  --allow                Auto-allow
  --deny                 Deny with reason
  --reason <TEXT>        Denial reason
```

### delete

```bash
tw-cli policy delete <NAME>
```

### test

```bash
tw-cli policy test [OPTIONS]

Options:
  --action <ACTION>      Action to test
  --severity <SEVERITY>  Incident severity
  --proposer-type <T>    Proposer type
  --confidence <N>       AI confidence score
```

## connector

Manage connectors.

### status

```bash
tw-cli connector status
```

### test

```bash
tw-cli connector test <NAME>
```

### configure

```bash
tw-cli connector configure <NAME> [OPTIONS]

Options:
  --mode <MODE>          Connector mode
  --api-key <KEY>        API key
  --url <URL>            Service URL
```

## user

User management.

### list

```bash
tw-cli user list
```

### create

```bash
tw-cli user create [OPTIONS]

Options:
  --username <NAME>      Username (required)
  --email <EMAIL>        Email address
  --role <ROLE>          User role
  --service-account      Create as service account
```

### update

```bash
tw-cli user update <ID> [OPTIONS]

Options:
  --role <ROLE>          New role
  --enabled              Enable user
  --disabled             Disable user
```

### delete

```bash
tw-cli user delete <ID>
```

## api-key

API key management.

### list

```bash
tw-cli api-key list
```

### create

```bash
tw-cli api-key create [OPTIONS]

Options:
  --name <NAME>          Key name (required)
  --scopes <SCOPES>      Comma-separated scopes
  --user <USER>          Associated user
  --expires <DATE>       Expiration date
```

### revoke

```bash
tw-cli api-key revoke <PREFIX>
```

### rotate

```bash
tw-cli api-key rotate <PREFIX>
```

## webhook

Webhook management.

### list

```bash
tw-cli webhook list
```

### add

```bash
tw-cli webhook add <SOURCE> [OPTIONS]

Options:
  --secret <SECRET>      Webhook secret
  --auto-triage          Enable auto-triage
  --playbook <NAME>      Playbook to run
```

### test

```bash
tw-cli webhook test <SOURCE>
```

### delete

```bash
tw-cli webhook delete <SOURCE>
```

## db

Database operations.

### migrate

```bash
tw-cli db migrate
```

### backup

```bash
tw-cli db backup [OPTIONS]

Options:
  -o, --output <FILE>    Backup file path
```

### restore

```bash
tw-cli db restore <FILE>
```

## serve

Start the API server.

```bash
tw-cli serve [OPTIONS]

Options:
  --host <HOST>          Bind address (default: 0.0.0.0)
  --port <PORT>          Port number (default: 8080)
  --config <FILE>        Configuration file
```
