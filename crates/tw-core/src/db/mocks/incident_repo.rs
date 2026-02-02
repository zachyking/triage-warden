//! Mock implementation of IncidentRepository for testing.

use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::db::{DbError, IncidentFilter, IncidentRepository, IncidentUpdate, Pagination};
use crate::incident::Incident;

/// Mock implementation of IncidentRepository using in-memory storage.
pub struct MockIncidentRepository {
    incidents: Arc<RwLock<HashMap<Uuid, Incident>>>,
}

impl Default for MockIncidentRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl MockIncidentRepository {
    /// Creates a new mock repository.
    pub fn new() -> Self {
        Self {
            incidents: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Creates a mock repository pre-populated with incidents.
    pub fn with_incidents(incidents: Vec<Incident>) -> Self {
        let map: HashMap<Uuid, Incident> = incidents.into_iter().map(|i| (i.id, i)).collect();
        Self {
            incidents: Arc::new(RwLock::new(map)),
        }
    }

    /// Gets a snapshot of all incidents in the mock.
    pub async fn snapshot(&self) -> Vec<Incident> {
        self.incidents.read().await.values().cloned().collect()
    }

    /// Clears all incidents from the mock.
    pub async fn clear(&self) {
        self.incidents.write().await.clear();
    }
}

#[async_trait]
impl IncidentRepository for MockIncidentRepository {
    async fn create(&self, incident: &Incident) -> Result<Incident, DbError> {
        let mut incidents = self.incidents.write().await;

        if incidents.contains_key(&incident.id) {
            return Err(DbError::Constraint(format!(
                "Incident with id '{}' already exists",
                incident.id
            )));
        }

        incidents.insert(incident.id, incident.clone());
        Ok(incident.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<Incident>, DbError> {
        let incidents = self.incidents.read().await;
        Ok(incidents.get(&id).cloned())
    }

    async fn list(
        &self,
        filter: &IncidentFilter,
        pagination: &Pagination,
    ) -> Result<Vec<Incident>, DbError> {
        let incidents = self.incidents.read().await;

        let mut result: Vec<Incident> = incidents
            .values()
            .filter(|i| {
                if let Some(statuses) = &filter.status {
                    if !statuses.contains(&i.status) {
                        return false;
                    }
                }
                if let Some(severities) = &filter.severity {
                    if !severities.contains(&i.severity) {
                        return false;
                    }
                }
                if let Some(since) = &filter.since {
                    if i.created_at < *since {
                        return false;
                    }
                }
                if let Some(until) = &filter.until {
                    if i.created_at > *until {
                        return false;
                    }
                }
                if let Some(tags) = &filter.tags {
                    if !tags.iter().any(|t| i.tags.contains(t)) {
                        return false;
                    }
                }
                if let Some(has_ticket) = &filter.has_ticket {
                    let incident_has_ticket = i.ticket_id.is_some();
                    if incident_has_ticket != *has_ticket {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        // Sort by created_at descending
        result.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        // Apply pagination
        let offset = pagination.offset() as usize;
        let limit = pagination.limit() as usize;

        Ok(result.into_iter().skip(offset).take(limit).collect())
    }

    async fn count(&self, filter: &IncidentFilter) -> Result<u64, DbError> {
        let pagination = Pagination {
            page: 1,
            per_page: u32::MAX,
        };
        let list = self.list(filter, &pagination).await?;
        Ok(list.len() as u64)
    }

    async fn update(&self, id: Uuid, update: &IncidentUpdate) -> Result<Incident, DbError> {
        let mut incidents = self.incidents.write().await;

        let incident = incidents.get_mut(&id).ok_or_else(|| DbError::NotFound {
            entity: "Incident".to_string(),
            id: id.to_string(),
        })?;

        if let Some(status) = &update.status {
            incident.status = status.clone();
        }

        if let Some(severity) = &update.severity {
            incident.severity = *severity;
        }

        if let Some(analysis) = &update.analysis {
            // Convert JSON Value to TriageAnalysis
            if let Ok(parsed) = serde_json::from_value(analysis.clone()) {
                incident.analysis = Some(parsed);
            }
        }

        if let Some(ticket_id) = &update.ticket_id {
            incident.ticket_id = Some(ticket_id.clone());
        }

        if let Some(tags) = &update.tags {
            incident.tags = tags.clone();
        }

        incident.updated_at = Utc::now();
        Ok(incident.clone())
    }

    async fn save(&self, incident: &Incident) -> Result<Incident, DbError> {
        let mut incidents = self.incidents.write().await;

        if !incidents.contains_key(&incident.id) {
            return Err(DbError::NotFound {
                entity: "Incident".to_string(),
                id: incident.id.to_string(),
            });
        }

        let mut updated = incident.clone();
        updated.updated_at = Utc::now();
        incidents.insert(incident.id, updated.clone());
        Ok(updated)
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let mut incidents = self.incidents.write().await;
        Ok(incidents.remove(&id).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incident::{AlertSource, IncidentStatus, Severity};
    use std::collections::HashMap;

    fn test_incident(id: Uuid, status: IncidentStatus, severity: Severity) -> Incident {
        Incident {
            id,
            source: AlertSource::Siem("test".to_string()),
            severity,
            status,
            alert_data: serde_json::json!({}),
            enrichments: vec![],
            analysis: None,
            proposed_actions: vec![],
            audit_log: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            ticket_id: None,
            tags: vec![],
            metadata: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_create_and_get() {
        let repo = MockIncidentRepository::new();
        let incident = test_incident(Uuid::new_v4(), IncidentStatus::New, Severity::High);

        repo.create(&incident).await.unwrap();

        let retrieved = repo.get(incident.id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().status, IncidentStatus::New);
    }

    #[tokio::test]
    async fn test_list_with_status_filter() {
        let repo = MockIncidentRepository::new();

        repo.create(&test_incident(
            Uuid::new_v4(),
            IncidentStatus::New,
            Severity::High,
        ))
        .await
        .unwrap();
        repo.create(&test_incident(
            Uuid::new_v4(),
            IncidentStatus::Resolved,
            Severity::Low,
        ))
        .await
        .unwrap();
        repo.create(&test_incident(
            Uuid::new_v4(),
            IncidentStatus::New,
            Severity::Medium,
        ))
        .await
        .unwrap();

        let filter = IncidentFilter {
            status: Some(vec![IncidentStatus::New]),
            ..Default::default()
        };

        let result = repo.list(&filter, &Pagination::default()).await.unwrap();
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn test_list_with_pagination() {
        let repo = MockIncidentRepository::new();

        for _ in 0..10 {
            repo.create(&test_incident(
                Uuid::new_v4(),
                IncidentStatus::New,
                Severity::High,
            ))
            .await
            .unwrap();
        }

        let pagination = Pagination {
            page: 2,
            per_page: 3,
        };

        let result = repo
            .list(&IncidentFilter::default(), &pagination)
            .await
            .unwrap();
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn test_update() {
        let repo = MockIncidentRepository::new();
        let incident = test_incident(Uuid::new_v4(), IncidentStatus::New, Severity::High);
        repo.create(&incident).await.unwrap();

        let update = IncidentUpdate {
            status: Some(IncidentStatus::Resolved),
            ticket_id: Some("TICKET-123".to_string()),
            ..Default::default()
        };

        let updated = repo.update(incident.id, &update).await.unwrap();
        assert_eq!(updated.status, IncidentStatus::Resolved);
        assert_eq!(updated.ticket_id, Some("TICKET-123".to_string()));
    }

    #[tokio::test]
    async fn test_count() {
        let repo = MockIncidentRepository::new();

        for _ in 0..5 {
            repo.create(&test_incident(
                Uuid::new_v4(),
                IncidentStatus::New,
                Severity::High,
            ))
            .await
            .unwrap();
        }

        let count = repo.count(&IncidentFilter::default()).await.unwrap();
        assert_eq!(count, 5);
    }
}
