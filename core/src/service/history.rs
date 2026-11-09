use super::*;

impl PersonaService {
    /// Get change history for an entity
    pub async fn get_entity_history(
        &self,
        entity_type: EntityType,
        entity_id: &Uuid,
    ) -> Result<Vec<ChangeHistory>> {
        self.change_history_repo
            .get_entity_history(entity_type, entity_id)
            .await
    }

    /// Get specific version of an entity
    pub async fn get_entity_version(
        &self,
        entity_type: EntityType,
        entity_id: &Uuid,
        version: u32,
    ) -> Result<Option<ChangeHistory>> {
        self.change_history_repo
            .get_version(entity_type, entity_id, version)
            .await
    }

    /// Query change history with filters
    pub async fn query_change_history(
        &self,
        query: &ChangeHistoryQuery,
    ) -> Result<Vec<ChangeHistory>> {
        self.change_history_repo.query(query).await
    }

    /// Get change history statistics
    pub async fn get_change_history_stats(&self) -> Result<ChangeHistoryStats> {
        self.change_history_repo.get_stats().await
    }

    /// Delete old change history (for cleanup/GDPR compliance)
    pub async fn cleanup_old_history(
        &self,
        before_date: chrono::DateTime<chrono::Utc>,
    ) -> Result<usize> {
        self.change_history_repo
            .delete_before_date(before_date)
            .await
    }
}
