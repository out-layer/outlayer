use crate::*;

/// Ids one call looks at for pending requests (`get_pending_request_ids`,
/// `clear_all_pending_requests`). Each look is a storage read of about 0.06 TGas, so a
/// window stays far inside the gas of a view or a transaction.
pub const PENDING_SCAN_WINDOW: u64 = 1_000;

/// A pending request without its input and output (`get_request_status`): what a cleanup needs,
/// in a few hundred bytes whatever the request holds.
#[near(serializers = [json])]
#[derive(Debug, PartialEq)]
pub struct RequestStatus {
    pub request_id: u64,
    pub sender_id: AccountId,
    pub payer_account_id: AccountId,
    /// Block timestamp (ns) of the admission.
    pub timestamp: u64,
    pub payment: U128,
    pub output_submitted: bool,
    pub input_bytes: u64,
    pub output_bytes: u64,
    /// Stale at this block (`execution::is_stale`): `cancel_stale_execution` accepts it.
    pub stale: bool,
}

/// A page of `get_pending_request_ids`.
#[near(serializers = [json])]
#[derive(Debug, PartialEq)]
pub struct PendingRequestIds {
    pub ids: Vec<u64>,
    /// Where the next page starts; `None` when the scan has reached id 0.
    pub next_from_id: Option<u64>,
}

impl Contract {
    /// Pending ids from `from_id` (clamped to the newest id) downwards, over at most
    /// `PENDING_SCAN_WINDOW` ids and at most `limit` found; with where to go on.
    pub(crate) fn scan_pending(&self, from_id: Option<u64>, limit: u64) -> (Vec<u64>, Option<u64>) {
        near_sdk::require!(limit > 0, "limit must be at least 1");
        let Some(newest) = self.next_request_id.checked_sub(1) else {
            return (Vec::new(), None);
        };
        let top = from_id.unwrap_or(newest).min(newest);
        let bottom = top.saturating_sub(PENDING_SCAN_WINDOW - 1);
        let mut ids = Vec::new();
        let mut id = top;
        loop {
            if self.pending_requests.contains_key(&id) {
                ids.push(id);
                if ids.len() as u64 >= limit {
                    return (ids, id.checked_sub(1));
                }
            }
            if id == bottom {
                return (ids, bottom.checked_sub(1));
            }
            id -= 1;
        }
    }
}

#[near_bindgen]
impl Contract {
    /// Get execution request by ID
    pub fn get_request(&self, request_id: u64) -> Option<ExecutionRequest> {
        self.pending_requests.get(&request_id)
    }

    /// Get contract statistics
    pub fn get_stats(&self) -> (u64, U128) {
        (self.total_executions, U128(self.total_fees_collected))
    }

    /// Get current NEAR pricing (for backward compatibility)
    /// Returns: (base_fee, per_million_instructions_fee, per_ms_fee, per_compile_ms_fee)
    pub fn get_pricing(&self) -> (U128, U128, U128, U128) {
        (
            U128(self.base_fee),
            U128(self.per_million_instructions_fee),
            U128(self.per_ms_fee),
            U128(self.per_compile_ms_fee),
        )
    }

    /// The subscription price list, for the coordinator to sync.
    ///
    /// Returned whole, withdrawn plans included: a key bought under a plan that
    /// is no longer on sale is still a key somebody paid for, and whoever
    /// answers their question has to be able to look the plan up.
    pub fn get_subscription_plans(&self) -> Vec<crate::payment::SubscriptionPlan> {
        self.subscription_plans.clone()
    }

    /// What a project charges, or `None` if it charges nothing.
    ///
    /// The coordinator reads this to bill the exact operation and to know whom
    /// to credit; it is the only copy of those numbers, so there is nothing to
    /// reconcile it against.
    pub fn get_project_pricing(&self, project_id: String) -> Option<crate::payment::ProjectPricing> {
        self.project_pricing.get(&project_id)
    }

    /// The most a single call to this project can cost — what
    /// `request_execution` requires to be attached. Zero when the project is
    /// not priced.
    ///
    /// Published so a caller can work out what to attach without having to
    /// reimplement the maximum over the price list themselves.
    pub fn get_project_max_price(&self, project_id: String) -> U128 {
        U128(
            self.project_pricing
                .get(&project_id)
                .map(|p| crate::payment::max_price(&p))
                .unwrap_or(0),
        )
    }

    /// Every project that has a price, paginated.
    ///
    /// This is why `project_pricing` is an `UnorderedMap` and not a
    /// `LookupMap`: without it the coordinator could only mirror prices for
    /// project ids it already knew, and it took that list from its own
    /// connector registry. A project priced here but missing from that registry
    /// would then be charged on chain and free over HTTPS — one project, two
    /// prices, with nothing to notice the difference.
    ///
    /// Paginated because a view has a gas ceiling like anything else, and a list
    /// that grows past it stops answering at all rather than answering slowly.
    pub fn get_priced_projects(&self, from_index: Option<u64>, limit: Option<u64>) -> Vec<String> {
        let from = from_index.unwrap_or(0);
        // A caller that names no limit gets a page, not the whole table: the
        // default has to be safe for the biggest table this could become, not
        // for the empty one it starts as.
        let limit = limit.unwrap_or(100).min(500);
        self.project_pricing
            .keys()
            .skip(from as usize)
            .take(limit as usize)
            .collect()
    }

    /// How many projects have a price. Lets a caller size the pages above.
    pub fn get_priced_project_count(&self) -> u64 {
        self.project_pricing.len()
    }

    /// Get full pricing (NEAR and USD)
    /// USD pricing is for HTTPS API, values are in minimal token units (e.g., 1 = 0.000001 USDT)
    pub fn get_pricing_full(&self) -> PricingView {
        PricingView {
            // NEAR pricing
            base_fee: U128(self.base_fee),
            per_million_instructions_fee: U128(self.per_million_instructions_fee),
            per_ms_fee: U128(self.per_ms_fee),
            per_compile_ms_fee: U128(self.per_compile_ms_fee),
            // USD pricing
            base_fee_usd: U128(self.base_fee_usd),
            per_million_instructions_fee_usd: U128(self.per_million_instructions_fee_usd),
            per_sec_fee_usd: U128(self.per_sec_fee_usd),
            per_compile_ms_fee_usd: U128(self.per_compile_ms_fee_usd),
        }
    }

    /// Get payment token contract for HTTPS API
    pub fn get_payment_token_contract(&self) -> Option<AccountId> {
        self.payment_token_contract.clone()
    }

    /// What `request_execution` requires attached: the compute estimate for
    /// the limits, plus the deposit held for `input_len` bytes of `input_data`
    /// beyond `INPUT_DATA_FREE_BYTES`, plus the deposit held for an output of
    /// `output_len` bytes, every byte (both returned at settlement). Either
    /// length may be omitted; absent, it is taken as small.
    /// The input deposit is required at admission; the output's is checked
    /// when the output arrives, and an output the payment cannot hold fails
    /// the request with the amount to attach.
    pub fn estimate_execution_cost(
        &self,
        resource_limits: Option<ResourceLimits>,
        input_len: Option<u64>,
        output_len: Option<u64>,
    ) -> U128 {
        let limits = resource_limits.unwrap_or_default();
        U128(
            self.estimate_cost(&limits)
                + input_storage_deposit(input_len.unwrap_or(0) as usize)
                + output_storage_deposit(output_len.unwrap_or(0) as usize),
        )
    }

    /// Get maximum resource limits (hard caps)
    /// Returns: (max_instructions, max_execution_seconds, max_compilation_seconds)
    pub fn get_max_limits(&self) -> (u64, u64, u64) {
        (MAX_INSTRUCTIONS, MAX_EXECUTION_SECONDS, MAX_COMPILATION_SECONDS)
    }

    /// Check if contract is paused
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Get owner and operator
    pub fn get_config(&self) -> (AccountId, AccountId) {
        (self.owner_id.clone(), self.operator_id.clone())
    }

    /// Get event metadata (standard name and version)
    /// Used by workers to filter events
    pub fn get_event_metadata(&self) -> (String, String) {
        (self.event_standard.clone(), self.event_version.clone())
    }

    /// Get pending output data for a given request_id
    /// Used by coordinator to check if large output was submitted
    pub fn get_pending_output(&self, request_id: u64) -> Option<ExecutionOutput> {
        let request = self.pending_requests.get(&request_id)?;
        // Convert from internal storage format to ExecutionOutput
        request.pending_output.map(|stored| stored.into())
    }

    /// Check if pending output exists for a given request_id
    pub fn has_pending_output(&self, request_id: u64) -> bool {
        self.pending_requests
            .get(&request_id)
            .map(|req| req.output_submitted)
            .unwrap_or(false)
    }

    /// Get developer earnings balance for an account (stablecoin)
    ///
    /// Earnings are credited when users call request_execution with attached_usd
    /// for projects owned by this account.
    ///
    /// # Arguments
    /// * `account_id` - Developer account (project owner)
    ///
    /// # Returns
    /// Balance in minimal stablecoin units (e.g., 1000000 = 1 USD with 6 decimals)
    pub fn get_developer_earnings(&self, account_id: AccountId) -> U128 {
        U128(self.developer_earnings.get(&account_id).unwrap_or(0))
    }

    /// Get user's stablecoin balance for attached_usd payments
    ///
    /// Users deposit stablecoins via ft_transfer_call with action=deposit_balance.
    /// This balance is used when calling request_execution with attached_usd parameter.
    ///
    /// # Arguments
    /// * `account_id` - User account
    ///
    /// # Returns
    /// Balance in minimal stablecoin units (e.g., 1000000 = 1 USD with 6 decimals)
    pub fn get_user_stablecoin_balance(&self, account_id: AccountId) -> U128 {
        U128(self.user_stablecoin_balances.get(&account_id).unwrap_or(0))
    }

    /// A pending request without its input and output, and whether it is stale by this block's
    /// time. `get_request` returns both, and a request holding over ~1.3 MB of them is more than
    /// a view may return.
    pub fn get_request_status(&self, request_id: u64) -> Option<RequestStatus> {
        self.pending_requests.get(&request_id).map(|r| {
            let output_bytes = match &r.pending_output {
                Some(StoredOutput::Bytes(b)) | Some(StoredOutput::Text(b)) | Some(StoredOutput::Json(b)) => b.len() as u64,
                None => 0,
            };
            RequestStatus {
                request_id: r.request_id,
                sender_id: r.sender_id,
                payer_account_id: r.payer_account_id,
                timestamp: r.timestamp,
                payment: U128(r.payment),
                output_submitted: r.output_submitted,
                input_bytes: r.input_data.as_ref().map_or(0, |d| d.len() as u64),
                output_bytes,
                stale: crate::execution::is_stale(request_id, r.timestamp),
            }
        })
    }

    /// Pending request ids, newest first, from `from_id` down (default: the newest id). One call
    /// looks at no more than `PENDING_SCAN_WINDOW` ids and returns at most `limit` (default 100);
    /// `next_from_id` is where the next call goes on, `None` once id 0 has been looked at.
    /// Bounded by ids looked at, not by ids found: a scan of every id from 0 runs out of a
    /// view's gas once there are some thousands of requests.
    pub fn get_pending_request_ids(&self, from_id: Option<u64>, limit: Option<u64>) -> PendingRequestIds {
        let (ids, next_from_id) = self.scan_pending(from_id, limit.unwrap_or(100));
        PendingRequestIds { ids, next_from_id }
    }

    /// The lowest nonce a new payment key of `account_id` may use: one above both
    /// its live keys and its floor (`Contract::payment_key_nonce_floor`, the
    /// highest nonce the contract has seen it create or delete). 1 for an
    /// account with neither.
    pub fn get_next_payment_key_nonce(&self, account_id: AccountId) -> u32 {
        let floor = self.payment_key_nonce_floor(&account_id);
        let user_secrets = self.user_secrets_index.get(&account_id);
        let live = match user_secrets {
            Some(secrets_set) => {
                let max_nonce = secrets_set
                    .iter()
                    .filter(|key| {
                        matches!(
                            key.accessor,
                            SecretAccessor::System(SystemSecretType::PaymentKey)
                        )
                    })
                    .filter_map(|key| key.profile.parse::<u32>().ok())
                    .max()
                    .unwrap_or(0);
                max_nonce
            }
            None => 0,
        };
        live.max(floor).saturating_add(1)
    }

    /// The highest payment-key nonce `account_id` has held, as far as the
    /// contract knows; 0 when nothing is recorded. A new key must be above it.
    pub fn get_payment_key_nonce_floor(&self, account_id: AccountId) -> u32 {
        self.payment_key_nonce_floor(&account_id)
    }
}
