# Settings

System configuration in the web dashboard.

## Settings Tabs

Access at `/settings`

### General

- **Instance Name**: Display name for this installation
- **Time Zone**: Default timezone for display
- **Date Format**: Date/time display format
- **Theme**: Light/dark mode preference

### Connectors

Configure external integrations.

#### Threat Intelligence

- Mode: Mock or VirusTotal
- API Key (for VirusTotal)
- Rate limit settings

#### SIEM

- Mode: Mock or Splunk
- URL and authentication
- Default search index

#### EDR

- Mode: Mock or CrowdStrike
- OAuth credentials
- Region selection

#### Email Gateway

- Mode: Mock or Microsoft 365
- Azure AD configuration
- Tenant settings

#### Ticketing

- Mode: Mock or Jira
- Instance URL
- Project configuration

### Policies

Manage policy rules.

#### Creating Rules

1. Click "Add Rule"
2. Enter rule name
3. Define matching criteria
4. Set decision (allow/deny/approval)
5. Save

#### Rule Priority

Drag rules to reorder. First matching rule wins.

### Users

User management (admin only).

#### User List

- Username and email
- Role (viewer/analyst/senior/admin)
- Last login
- Status (active/disabled)

#### Creating Users

1. Click "Add User"
2. Enter email and username
3. Set initial role
4. Generate or set password
5. Send invitation email

#### Role Management

Assign roles:
- **Viewer**: Read-only access
- **Analyst**: Execute actions, approve analyst-level
- **Senior**: Approve senior-level
- **Admin**: Full access

### Notifications

Configure notification preferences.

#### Channels

- **Email**: SMTP settings
- **Slack**: Webhook URL
- **Teams**: Connector URL
- **PagerDuty**: Integration key

#### Preferences

For each notification type:
- Enable/disable channel
- Set priority threshold
- Configure quiet hours

### Audit Logs

View system audit trail.

#### Filtering

- Date range
- Event type
- User
- Resource

#### Export

Export logs to CSV for compliance.

### API Keys

Manage API credentials.

#### Creating Keys

1. Click "Create API Key"
2. Enter name and description
3. Select scopes
4. Set expiration (optional)
5. Copy generated key

#### Revoking Keys

Click "Revoke" on any key. Revocation is immediate.

### Backup & Restore

Database management.

#### Backup

1. Click "Create Backup"
2. Wait for completion
3. Download backup file

#### Restore

1. Click "Restore"
2. Upload backup file
3. Confirm restore
4. System restarts

### About

System information:
- Version number
- Build information
- License status
- Support links
