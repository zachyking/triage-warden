# Changelog

All notable changes to Triage Warden.

## [Unreleased]

### Added
- AI-powered triage agent with Claude integration
- Configurable playbooks for automated investigation
- Policy engine with approval workflows
- Connector framework for external integrations
- Web dashboard with HTMX
- REST API for programmatic access
- CLI for command-line operations

### Connectors
- VirusTotal threat intelligence
- Splunk SIEM integration
- CrowdStrike EDR integration
- Microsoft 365 email gateway
- Jira ticketing integration

### Actions
- Email: parse_email, check_email_authentication, quarantine_email, block_sender
- Lookup: lookup_sender_reputation, lookup_urls, lookup_attachments
- Host: isolate_host, scan_host
- Notification: notify_user, escalate, create_ticket

## [0.1.0] - 2024-01-15

### Added
- Initial release
- Core incident management
- Basic web interface
- SQLite database support
- Mock connectors for development

---

## Version Numbering

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: Incompatible API changes
- **MINOR**: Backwards-compatible new features
- **PATCH**: Backwards-compatible bug fixes

## Upgrade Guide

### From 0.x to 1.0

When 1.0 is released, an upgrade guide will be provided here.
