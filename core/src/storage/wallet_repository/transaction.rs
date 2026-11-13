//! 交易域（LAY-022 拆分）：交易请求、签名交易、统计与行→模型映射。

use super::*;

impl CryptoWalletRepository {
    /// Create transaction request
    pub async fn create_transaction_request(
        &self,
        request: &TransactionRequest,
    ) -> PersonaResult<TransactionRequest> {
        sqlx::query(
            r#"
            INSERT INTO transaction_requests (
                id, wallet_id, network, from_address, to_address, amount, fee,
                gas_price, gas_limit, nonce, memo, raw_transaction_data,
                required_signatures, created_at, expires_at, metadata, status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, 'pending')
            "#,
        )
        .bind(request.id.to_string())
        .bind(request.wallet_id.to_string())
        .bind(serde_json::to_string(&request.network)?)
        .bind(&request.from_address)
        .bind(&request.to_address)
        .bind(&request.amount)
        .bind(&request.fee)
        .bind(&request.gas_price)
        .bind(request.gas_limit.map(|v| v as i64))
        .bind(request.nonce.map(|v| v as i64))
        .bind(&request.memo)
        .bind(&request.raw_transaction_data)
        .bind(request.required_signatures as i32)
        .bind(request.created_at.timestamp())
        .bind(request.expires_at.map(|d| d.timestamp()))
        .bind(serde_json::to_string(&request.metadata)?)
        .execute(self.db.pool())
        .await?;

        // Return the request as-is since we just inserted it
        Ok(request.clone())
    }

    /// Create signed transaction
    ///
    /// 同一事务内写入签名结果并把原请求标记为已签（2026-11-13 codex 深审
    /// Major 修复）：此前只插 signed_transactions、不动
    /// transaction_requests.signed_at，待签查询（`signed_at IS NULL`）
    /// 会把已签请求永远再列出来，可重复触发签名。请求不存在时报 NotFound
    /// 并回滚插入。
    pub async fn create_signed_transaction(
        &self,
        signed_tx: &SignedTransaction,
    ) -> PersonaResult<SignedTransaction> {
        let mut tx = self.db.pool().begin().await?;

        sqlx::query(
            r#"
            INSERT INTO signed_transactions (
                id, wallet_id, request, signatures, raw_signed_transaction,
                transaction_hash, signed_at, broadcast_status, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
        )
        .bind(signed_tx.id.to_string())
        .bind(signed_tx.request.wallet_id.to_string())
        .bind(serde_json::to_string(&signed_tx.request)?)
        .bind(serde_json::to_string(&signed_tx.signatures)?)
        .bind(&signed_tx.raw_signed_transaction)
        .bind(&signed_tx.transaction_hash)
        .bind(signed_tx.signed_at.timestamp())
        .bind(serde_json::to_string(&signed_tx.broadcast_status)?)
        .bind(chrono::Utc::now().timestamp())
        .execute(tx.as_mut())
        .await?;

        let marked = sqlx::query("UPDATE transaction_requests SET signed_at = $1 WHERE id = $2")
            .bind(signed_tx.signed_at.timestamp())
            .bind(signed_tx.request.id.to_string())
            .execute(tx.as_mut())
            .await?;

        if marked.rows_affected() == 0 {
            return Err(PersonaError::NotFound("Transaction request".to_string()));
        }

        tx.commit().await?;

        Ok(signed_tx.clone())
    }

    /// Get pending transaction requests for a wallet
    pub async fn get_pending_requests(
        &self,
        wallet_id: &Uuid,
    ) -> PersonaResult<Vec<TransactionRequest>> {
        let rows = sqlx::query(
            r#"
            SELECT id, wallet_id, network, from_address, to_address, amount, fee,
                   gas_price, gas_limit, nonce, memo, raw_transaction_data,
                   required_signatures, created_at, signed_at, expires_at, metadata, status
            FROM transaction_requests
            WHERE wallet_id = $1 AND signed_at IS NULL
            ORDER BY created_at DESC
            "#,
        )
        .bind(wallet_id.to_string())
        .fetch_all(self.db.pool())
        .await?;

        let mut requests = Vec::new();
        for row in rows {
            requests.push(self.transaction_request_from_row(&row)?);
        }

        Ok(requests)
    }

    /// Get a single transaction request by ID
    pub async fn get_request_by_id(
        &self,
        request_id: &Uuid,
    ) -> PersonaResult<Option<TransactionRequest>> {
        let row = sqlx::query(
            r#"
            SELECT id, wallet_id, network, from_address, to_address, amount, fee,
                   gas_price, gas_limit, nonce, memo, raw_transaction_data,
                   required_signatures, created_at, signed_at, expires_at, metadata, status
            FROM transaction_requests
            WHERE id = $1
            "#,
        )
        .bind(request_id.to_string())
        .fetch_optional(self.db.pool())
        .await?;

        row.map(|r| self.transaction_request_from_row(&r))
            .transpose()
    }

    /// Get transaction statistics for a wallet
    pub async fn get_transaction_stats(
        &self,
        wallet_id: &Uuid,
    ) -> PersonaResult<WalletTransactionStats> {
        let row = sqlx::query(
            r#"
            SELECT
                COUNT(*) as total_transactions,
                COUNT(CASE WHEN broadcast_status LIKE '%BroadcastSuccess%' THEN 1 END) as successful_transactions,
                COUNT(CASE WHEN broadcast_status LIKE '%BroadcastFailed%' THEN 1 END) as failed_transactions
            FROM signed_transactions
            WHERE wallet_id = $1
            "#,
        )
        .bind(wallet_id.to_string())
        .fetch_one(self.db.pool())
        .await?;

        Ok(WalletTransactionStats {
            total_transactions: row.get::<i64, _>("total_transactions") as u64,
            successful_transactions: row.get::<i64, _>("successful_transactions") as u64,
            failed_transactions: row.get::<i64, _>("failed_transactions") as u64,
            total_amount_sent: 0.0, // Not easily computed without parsing amounts
        })
    }

    // Private helper methods

    pub(super) fn transaction_request_from_row(
        &self,
        row: &sqlx::sqlite::SqliteRow,
    ) -> PersonaResult<TransactionRequest> {
        let id_str: String = row.get("id");
        let wallet_id_str: String = row.get("wallet_id");
        let network_str: String = row.get("network");
        let metadata_str: String = row.get("metadata");
        let created_at_ts: i64 = row.get("created_at");
        let expires_at_ts: Option<i64> = row.get("expires_at");

        Ok(TransactionRequest {
            id: Uuid::parse_str(&id_str).map_err(|e| PersonaError::InvalidInput(e.to_string()))?,
            wallet_id: Uuid::parse_str(&wallet_id_str)
                .map_err(|e| PersonaError::InvalidInput(e.to_string()))?,
            network: serde_json::from_str(&network_str)?,
            from_address: row.get("from_address"),
            to_address: row.get("to_address"),
            amount: row.get("amount"),
            fee: row.get("fee"),
            gas_price: row.get("gas_price"),
            gas_limit: row.get::<Option<i64>, _>("gas_limit").map(|v| v as u64),
            nonce: row.get::<Option<i64>, _>("nonce").map(|v| v as u64),
            memo: row.get("memo"),
            raw_transaction_data: row.get("raw_transaction_data"),
            required_signatures: row.get::<i32, _>("required_signatures") as usize,
            created_at: timestamp_to_datetime(created_at_ts)?,
            expires_at: expires_at_ts.map(timestamp_to_datetime).transpose()?,
            metadata: serde_json::from_str(&metadata_str)?,
        })
    }

    #[allow(dead_code)]
    pub(super) fn signed_transaction_from_row(
        &self,
        row: &sqlx::sqlite::SqliteRow,
    ) -> PersonaResult<SignedTransaction> {
        let id_str: String = row.get("id");
        let request_str: String = row.get("request");
        let signatures_str: String = row.get("signatures");
        let broadcast_status_str: String = row.get("broadcast_status");
        let signed_at_ts: i64 = row.get("signed_at");

        Ok(SignedTransaction {
            id: Uuid::parse_str(&id_str).map_err(|e| PersonaError::InvalidInput(e.to_string()))?,
            request: serde_json::from_str(&request_str)?,
            signatures: serde_json::from_str(&signatures_str)?,
            raw_signed_transaction: row.get("raw_signed_transaction"),
            transaction_hash: row.get("transaction_hash"),
            signed_at: timestamp_to_datetime(signed_at_ts)?,
            broadcast_status: serde_json::from_str(&broadcast_status_str)?,
        })
    }
}
