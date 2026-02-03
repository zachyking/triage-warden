# ADR-002: Dual Database Support (SQLite + PostgreSQL)

## Status

Accepted

## Context

Triage Warden needed to support different deployment scenarios:

1. **Development/Testing**: Quick setup without external dependencies
2. **Small Deployments**: Single-server installations with minimal infrastructure
3. **Production**: Scalable deployments with high availability requirements

We evaluated:
- SQLite only (simple but limited scalability)
- PostgreSQL only (powerful but heavy for small deployments)
- Dual support (flexibility but increased complexity)

## Decision

We implemented dual database support using SQLx with compile-time query verification:

### Architecture

```
┌─────────────────────────────────────────┐
│              Application                │
├─────────────────────────────────────────┤
│           Repository Traits             │
│   (IncidentRepository, UserRepository)  │
├──────────────────┬──────────────────────┤
│  SqliteXxxRepo   │    PgXxxRepo         │
├──────────────────┼──────────────────────┤
│   SQLite Pool    │   PostgreSQL Pool    │
└──────────────────┴──────────────────────┘
```

### Implementation

- `DbPool` enum wraps both pool types
- Each repository has SQLite and PostgreSQL implementations
- Factory functions create the appropriate implementation based on pool type
- Migrations are maintained separately for each database

### Database Selection

Determined by `DATABASE_URL` environment variable:
- `sqlite:path/to/file.db` → SQLite
- `postgres://user:pass@host/db` → PostgreSQL

## Consequences

### Positive

- Zero-config development with SQLite
- Production-ready PostgreSQL support
- Same API regardless of database backend
- Compile-time query verification for both backends

### Negative

- Duplicate migration files
- Some features may have different behavior (e.g., JSON querying)
- More complex testing matrix
- Cannot use PostgreSQL-specific features (CTEs, window functions) without SQLite equivalents

### Trade-offs

| Feature | SQLite | PostgreSQL |
|---------|--------|------------|
| Setup complexity | None | Requires server |
| Concurrent writes | Limited | Excellent |
| JSON indexing | Basic | JSONB with GIN |
| Full-text search | Limited | Excellent |
| Connection pooling | In-process | Network |
| Backup | File copy | pg_dump |
