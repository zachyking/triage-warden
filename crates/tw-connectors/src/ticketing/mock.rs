//! Mock ticketing connector for testing.

use crate::traits::{
    ConnectorHealth, ConnectorResult, CreateTicketRequest, Ticket, TicketStatus,
    TicketingConnector, UpdateTicketRequest,
};
#[cfg(test)]
use crate::traits::TicketPriority;
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Mock ticketing connector for testing.
pub struct MockTicketingConnector {
    name: String,
    tickets: Arc<RwLock<HashMap<String, Ticket>>>,
    counter: AtomicU64,
}

impl MockTicketingConnector {
    /// Creates a new mock ticketing connector.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            tickets: Arc::new(RwLock::new(HashMap::new())),
            counter: AtomicU64::new(1),
        }
    }

    fn next_id(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::SeqCst)
    }
}

#[async_trait]
impl crate::traits::Connector for MockTicketingConnector {
    fn name(&self) -> &str {
        &self.name
    }

    fn connector_type(&self) -> &str {
        "ticketing"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        Ok(ConnectorHealth::Healthy)
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        Ok(true)
    }
}

#[async_trait]
impl TicketingConnector for MockTicketingConnector {
    async fn create_ticket(&self, request: CreateTicketRequest) -> ConnectorResult<Ticket> {
        let id = self.next_id();
        let key = format!("MOCK-{}", id);
        let now = Utc::now();

        let ticket = Ticket {
            id: id.to_string(),
            key: key.clone(),
            title: request.title,
            description: request.description,
            status: "Open".to_string(),
            priority: request.priority,
            assignee: request.assignee,
            reporter: "mock-user".to_string(),
            labels: request.labels,
            created_at: now,
            updated_at: now,
            url: format!("https://mock.jira.example.com/browse/{}", key),
            custom_fields: request.custom_fields,
        };

        let mut tickets = self.tickets.write().await;
        tickets.insert(key.clone(), ticket.clone());

        Ok(ticket)
    }

    async fn get_ticket(&self, ticket_id: &str) -> ConnectorResult<Ticket> {
        let tickets = self.tickets.read().await;
        tickets
            .get(ticket_id)
            .cloned()
            .ok_or_else(|| crate::traits::ConnectorError::NotFound(ticket_id.to_string()))
    }

    async fn update_ticket(
        &self,
        ticket_id: &str,
        update: UpdateTicketRequest,
    ) -> ConnectorResult<Ticket> {
        let mut tickets = self.tickets.write().await;
        let ticket = tickets
            .get_mut(ticket_id)
            .ok_or_else(|| crate::traits::ConnectorError::NotFound(ticket_id.to_string()))?;

        if let Some(title) = update.title {
            ticket.title = title;
        }
        if let Some(description) = update.description {
            ticket.description = description;
        }
        if let Some(status) = update.status {
            ticket.status = status;
        }
        if let Some(priority) = update.priority {
            ticket.priority = priority;
        }
        if let Some(assignee) = update.assignee {
            ticket.assignee = Some(assignee);
        }

        for label in update.add_labels {
            if !ticket.labels.contains(&label) {
                ticket.labels.push(label);
            }
        }
        ticket.labels.retain(|l| !update.remove_labels.contains(l));

        ticket.updated_at = Utc::now();

        Ok(ticket.clone())
    }

    async fn add_comment(&self, ticket_id: &str, _comment: &str) -> ConnectorResult<()> {
        let tickets = self.tickets.read().await;
        if tickets.contains_key(ticket_id) {
            Ok(())
        } else {
            Err(crate::traits::ConnectorError::NotFound(
                ticket_id.to_string(),
            ))
        }
    }

    async fn search_tickets(&self, query: &str, limit: usize) -> ConnectorResult<Vec<Ticket>> {
        let tickets = self.tickets.read().await;
        let results: Vec<Ticket> = tickets
            .values()
            .filter(|t| {
                t.title.contains(query)
                    || t.description.contains(query)
                    || t.labels.iter().any(|l| l.contains(query))
            })
            .take(limit)
            .cloned()
            .collect();

        Ok(results)
    }

    async fn get_statuses(&self) -> ConnectorResult<Vec<TicketStatus>> {
        Ok(vec![
            TicketStatus {
                id: "1".to_string(),
                name: "Open".to_string(),
                category: "To Do".to_string(),
            },
            TicketStatus {
                id: "2".to_string(),
                name: "In Progress".to_string(),
                category: "In Progress".to_string(),
            },
            TicketStatus {
                id: "3".to_string(),
                name: "Resolved".to_string(),
                category: "Done".to_string(),
            },
            TicketStatus {
                id: "4".to_string(),
                name: "Closed".to_string(),
                category: "Done".to_string(),
            },
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_and_get_ticket() {
        let connector = MockTicketingConnector::new("test");

        let request = CreateTicketRequest {
            title: "Test Ticket".to_string(),
            description: "Test description".to_string(),
            ticket_type: "Task".to_string(),
            priority: TicketPriority::High,
            labels: vec!["security".to_string()],
            assignee: None,
            custom_fields: HashMap::new(),
        };

        let created = connector.create_ticket(request).await.unwrap();
        assert_eq!(created.title, "Test Ticket");
        assert_eq!(created.priority, TicketPriority::High);

        let fetched = connector.get_ticket(&created.key).await.unwrap();
        assert_eq!(fetched.id, created.id);
    }

    #[tokio::test]
    async fn test_update_ticket() {
        let connector = MockTicketingConnector::new("test");

        let request = CreateTicketRequest {
            title: "Original Title".to_string(),
            description: "Original".to_string(),
            ticket_type: "Task".to_string(),
            priority: TicketPriority::Medium,
            labels: vec![],
            assignee: None,
            custom_fields: HashMap::new(),
        };

        let created = connector.create_ticket(request).await.unwrap();

        let update = UpdateTicketRequest {
            title: Some("Updated Title".to_string()),
            status: Some("In Progress".to_string()),
            add_labels: vec!["urgent".to_string()],
            ..Default::default()
        };

        let updated = connector.update_ticket(&created.key, update).await.unwrap();
        assert_eq!(updated.title, "Updated Title");
        assert_eq!(updated.status, "In Progress");
        assert!(updated.labels.contains(&"urgent".to_string()));
    }

    #[tokio::test]
    async fn test_search_tickets() {
        let connector = MockTicketingConnector::new("test");

        // Create a few tickets
        for i in 0..5 {
            let request = CreateTicketRequest {
                title: format!("Test Ticket {}", i),
                description: if i % 2 == 0 {
                    "security related".to_string()
                } else {
                    "other".to_string()
                },
                ticket_type: "Task".to_string(),
                priority: TicketPriority::Medium,
                labels: vec![],
                assignee: None,
                custom_fields: HashMap::new(),
            };
            connector.create_ticket(request).await.unwrap();
        }

        let results = connector.search_tickets("security", 10).await.unwrap();
        assert_eq!(results.len(), 3); // 0, 2, 4
    }
}
