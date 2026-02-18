# Database Migrations

Triage Warden maintains parallel migration sets for SQLite and PostgreSQL.

## Directory Layout

```
migrations/
  sqlite/     -- 17 migrations (dev/single-node)
  postgres/   -- 19 migrations (production/multi-tenant)
```

## Migration Parity

The two backends share the same logical schema. Most migrations have a 1:1
counterpart (with minor SQL dialect differences). The table below lists every
migration and maps across backends.

| # | SQLite | PostgreSQL | Notes |
|---|--------|------------|-------|
| 1 | `20240101_000001_initial_schema` | `20240101_000001_initial_schema` | Core tables: incidents, audit_logs, actions, approvals |
| 2 | `20240102_000001_create_playbooks` | `20240102_000001_create_playbooks` | |
| 3 | `20240103_000001_create_connectors` | `20240103_000001_create_connectors` | |
| 4 | `20240104_000001_create_policies` | `20240104_000001_create_policies` | |
| 5 | `20240105_000001_create_notification_channels` | `20240105_000001_create_notification_channels` | |
| 6 | `20240106_000001_create_settings` | `20240106_000001_create_settings` | |
| 7 | `20240107_000001_create_auth_tables` | `20240201_000001_create_auth_tables` | |
| 8 | `20240202_000001_add_composite_indexes` | `20240202_000001_add_composite_indexes` | |
| 9 | `20240210_000001_create_feature_flags` | `20240210_000001_create_feature_flags` | |
| 10 | `20240215_000001_create_tenants` | `20240215_000001_create_tenants` | |
| 11 | `20240215_000002_add_tenant_id_to_tables` | -- | SQLite-only backfill path |
| 12 | -- | `20240220_000001_add_tenant_id_to_tables` | **PG-only.** Adds FK constraints, composite indexes, and migrates settings table to (tenant_id, key) PK. SQLite handles this in migration #11. |
| 13 | -- | `20240221_000001_enable_rls` | **PG-only.** Enables Row-Level Security on all tenant-scoped tables with per-tenant policies and helper functions. SQLite has no RLS equivalent. |
| 14 | `20240225_000001_add_optimized_indexes` | `20240225_000001_add_optimized_indexes` | |
| 15 | `20240301_000001_create_analyst_feedback` | `20240301_000001_create_analyst_feedback` | |
| 16 | `20240302_000001_create_knowledge_base` | `20240302_000001_create_knowledge_base` | |
| 17 | `20240310_000001_create_comments_activity` | `20240310_000001_create_comments_activity` | |
| 18 | `20240311_000001_create_lessons_handoffs` | `20240311_000001_create_lessons_handoffs` | |
| 19 | `20240312_000001_create_rbac_tables` | `20240312_000001_create_rbac_tables` | |

## Intentional Differences

PostgreSQL has two extra migrations that do not exist in SQLite:

1. **`20240220_000001_add_tenant_id_to_tables`** -- Uses PG-specific syntax
   (`ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, `ALTER COLUMN ... SET NOT NULL`,
   `ADD CONSTRAINT ... FOREIGN KEY`, `UPDATE ... SET ... FROM`) to add tenant_id
   columns, foreign keys, and composite indexes. SQLite cannot alter columns
   in-place, so its equivalent logic is folded into `20240215_000002`.

2. **`20240221_000001_enable_rls`** -- Enables PostgreSQL Row-Level Security
   for defense-in-depth tenant isolation. Creates per-table RLS policies that
   filter all queries by `app.current_tenant`, a `tw_app` database role, and
   helper functions (`set_tenant_context`, `clear_tenant_context`,
   `get_current_tenant`). SQLite does not support RLS, so tenant isolation is
   enforced purely at the application layer via `tenant_id` filters in queries.

These differences are intentional and expected. Both backends produce the same
logical schema; the PG backend simply adds database-level security guarantees.

## Adding New Migrations

When adding a migration, create matching files in both `sqlite/` and `postgres/`
directories. Use the naming convention `YYYYMMDD_NNNNNN_description.sql`. Keep
the description and timestamp identical across backends when the migration is
logically the same.
