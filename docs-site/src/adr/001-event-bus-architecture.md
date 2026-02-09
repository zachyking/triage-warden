# ADR-001: Event Bus Architecture

## Status

Accepted

## Context

Triage Warden needs to coordinate multiple components (enrichment, analysis, action execution, notifications) in response to security incidents. We needed a way to:

1. Decouple components for independent development and testing
2. Enable real-time updates to the dashboard
3. Support both synchronous and asynchronous processing
4. Maintain an audit trail of all system events

## Decision

We implemented an in-process event bus using Tokio channels with the following design:

### Event Types

All significant system events are captured as `TriageEvent` variants:

- `AlertReceived` - New alert from webhook
- `IncidentCreated` - Incident created from alert
- `EnrichmentComplete` - Single enrichment finished
- `EnrichmentPhaseComplete` - All enrichments done
- `AnalysisComplete` - AI analysis finished
- `ActionsProposed` - Response actions proposed
- `ActionApproved/Denied` - Action approval decision
- `ActionExecuted` - Action completed
- `StatusChanged` - Incident status transition
- `TicketCreated` - External ticket created
- `IncidentEscalated` - Incident escalated
- `IncidentResolved` - Incident resolved
- `KillSwitchActivated` - Emergency stop triggered

### Delivery Mechanisms

1. **Broadcast Channel**: For real-time dashboard updates via SSE
2. **Named Subscribers**: For component-specific processing queues
3. **Event History**: In-memory buffer for recent event retrieval

### Error Handling

Events are fire-and-forget with fallback logging:
- `publish()` - Returns Result for cases where failure matters
- `publish_with_fallback()` - Logs errors, never fails (for non-critical events)

## Consequences

### Positive

- Components are loosely coupled and independently testable
- Dashboard receives real-time updates without polling
- Complete event history available for debugging
- Failed subscribers don't block the main processing flow

### Negative

- In-process only - no distributed event bus
- Event history is limited and in-memory (lost on restart)
- No guaranteed delivery or replay capability
- Broadcast channel has limited buffer (may drop events under load)

### Future Considerations

For high-availability deployments, consider:
- Redis Pub/Sub for distributed events
- PostgreSQL LISTEN/NOTIFY for persistent events
- External message queue (RabbitMQ, Kafka) for durability
