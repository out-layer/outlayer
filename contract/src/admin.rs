use crate::*;

/// How many offers the price list may hold.
///
/// Not a product limit — nobody wants sixteen plans — but a bound on state that
/// every call pays to read.
const MAX_SUBSCRIPTION_PLANS: usize = 16;

/// How many operations one project may price.
///
/// Read whole on every call to that project, so it bounds the gas a priced
/// project costs to admit. A connector sells a handful of actions; a hundred
/// would be a different kind of thing.
const MAX_PROJECT_OPERATIONS: usize = 32;

/// Basis points of a whole.
const FULL_SHARE_BP: u16 = 10_000;

impl Contract {
    pub(crate) fn assert_owner(&self) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "Only owner can call this method"
        );
    }
}

#[near_bindgen]
impl Contract {
    /// Governance: replace the owner (the ops role).
    pub fn set_owner(&mut self, new_owner_id: AccountId) {
        self.assert_governance();
        let old_owner = self.owner_id.clone();
        self.owner_id = new_owner_id.clone();

        log!("Owner changed from {} to {}", old_owner, new_owner_id);
    }

    /// Governance: replace the operator. The operator resolves executions and answers
    /// payment-key yields, so choosing it is a governance decision.
    pub fn set_operator(&mut self, new_operator_id: AccountId) {
        self.assert_governance();
        let old_operator = self.operator_id.clone();
        self.operator_id = new_operator_id.clone();

        log!(
            "Operator changed from {} to {}",
            old_operator,
            new_operator_id
        );
    }

    /// Pause/unpause contract (only owner can call)
    pub fn set_paused(&mut self, paused: bool) {
        self.assert_owner();
        self.paused = paused;

        log!("Contract {}", if paused { "paused" } else { "unpaused" });
    }

    /// Update pricing (only owner can call)
    /// Supports both NEAR pricing (for blockchain transactions) and USD pricing (for HTTPS API)
    pub fn set_pricing(
        &mut self,
        // NEAR pricing
        base_fee: Option<U128>,
        per_million_instructions_fee: Option<U128>,
        per_ms_fee: Option<U128>,
        per_compile_ms_fee: Option<U128>,
        // USD pricing (for HTTPS API)
        base_fee_usd: Option<U128>,
        per_million_instructions_fee_usd: Option<U128>,
        per_sec_fee_usd: Option<U128>,
        per_compile_ms_fee_usd: Option<U128>,
    ) {
        self.assert_owner();

        // NEAR pricing
        if let Some(fee) = base_fee {
            self.base_fee = fee.0;
            log!("Base fee (NEAR) updated to {}", fee.0);
        }
        if let Some(fee) = per_million_instructions_fee {
            self.per_million_instructions_fee = fee.0;
            log!("Per million instructions fee (NEAR) updated to {}", fee.0);
        }
        if let Some(fee) = per_ms_fee {
            self.per_ms_fee = fee.0;
            log!("Per millisecond fee (NEAR, execution) updated to {}", fee.0);
        }
        if let Some(fee) = per_compile_ms_fee {
            self.per_compile_ms_fee = fee.0;
            log!("Per millisecond fee (NEAR, compilation) updated to {}", fee.0);
        }

        // USD pricing
        if let Some(fee) = base_fee_usd {
            self.base_fee_usd = fee.0;
            log!("Base fee (USD) updated to {}", fee.0);
        }
        if let Some(fee) = per_million_instructions_fee_usd {
            self.per_million_instructions_fee_usd = fee.0;
            log!("Per million instructions fee (USD) updated to {}", fee.0);
        }
        if let Some(fee) = per_sec_fee_usd {
            self.per_sec_fee_usd = fee.0;
            log!("Per second fee (USD, execution) updated to {}", fee.0);
        }
        if let Some(fee) = per_compile_ms_fee_usd {
            self.per_compile_ms_fee_usd = fee.0;
            log!("Per millisecond fee (USD, compilation) updated to {}", fee.0);
        }
    }

    /// Set payment token contract for HTTPS API (only owner can call)
    /// This is the stablecoin contract used for Payment Keys (e.g., "usdt.tether-token.near")
    /// Replace the subscription price list.
    ///
    /// Wholesale, not row by row: a price list is read as a whole by everything
    /// that uses it, and a partial update is how a plan ends up half-changed
    /// between two transactions.
    ///
    /// **An index is never reused.** A payment names a plan by index, and it is
    /// signed before it lands; letting index 2 mean `starter` today and `pro`
    /// tomorrow means a payment in flight buys something its payer did not
    /// choose. Withdraw a plan by setting `active = false` and leave the row
    /// where it is.
    pub fn set_subscription_plans(&mut self, plans: Vec<crate::payment::SubscriptionPlan>) {
        self.assert_owner();

        // The list lives in the contract's root state, so every call — every
        // execution request, every top-up — deserialises all of it. A price
        // list is a handful of offers; a thousand would be a gas cost paid by
        // users who are not buying anything, forever. Bounded here rather than
        // trusted to stay small.
        assert!(
            plans.len() <= MAX_SUBSCRIPTION_PLANS,
            "at most {} plans; the list is deserialised on every call",
            MAX_SUBSCRIPTION_PLANS
        );

        let mut seen: Vec<u8> = Vec::with_capacity(plans.len());
        for plan in &plans {
            assert!(
                !seen.contains(&plan.index),
                "duplicate plan index {}: an index identifies exactly one offer",
                plan.index
            );
            assert!(!plan.name.trim().is_empty(), "a plan needs a name");
            assert!(
                plan.price_usd.0 > 0,
                "plan {} has no price: a free plan is granted, not sold",
                plan.name
            );
            seen.push(plan.index);
        }

        // Refuse to renumber what is already on sale. An index that disappears
        // is fine — that is a plan being retired — but one that stays must keep
        // meaning the same offer.
        for existing in &self.subscription_plans {
            if let Some(new) = plans.iter().find(|p| p.index == existing.index) {
                assert!(
                    new.name == existing.name,
                    "plan index {} is already `{}`; an index may not be repointed at `{}`",
                    existing.index,
                    existing.name,
                    new.name
                );
            }
        }

        log!("Subscription plans set: {} offer(s)", plans.len());
        self.subscription_plans = plans;
    }

    /// Price a project, or reprice one.
    ///
    /// Wholesale, like the subscription plans and for the same reason: the list
    /// is read as a whole, and a row-by-row update is how a project ends up
    /// half-repriced between two transactions.
    ///
    /// Owner-only, and deliberately not the project owner's to call. The price
    /// is what a subscription's allowance may be spent against, so whoever sets
    /// it writes invoices against credit we already sold; that decision is the
    /// same one as whether the project is in the subscription at all.
    ///
    /// The project must exist. A price on a name nobody registered would admit
    /// calls to a project that cannot resolve, and would silently start
    /// applying the day somebody else registered that name.
    pub fn set_project_pricing(
        &mut self,
        project_id: String,
        pricing: crate::payment::ProjectPricing,
    ) {
        self.assert_owner();

        assert!(
            self.projects.get(&project_id).is_some(),
            "Project '{}' does not exist; register it before pricing it",
            project_id
        );

        assert!(
            !pricing.operations.is_empty(),
            "no operations priced: use remove_project_pricing to unprice a project"
        );
        assert!(
            pricing.operations.len() <= MAX_PROJECT_OPERATIONS,
            "at most {} operations; the list is read on every call to this project",
            MAX_PROJECT_OPERATIONS
        );
        let mut seen: Vec<&str> = Vec::with_capacity(pricing.operations.len());
        for op in &pricing.operations {
            assert!(!op.operation.trim().is_empty(), "an operation needs a name");
            assert!(
                op.developer_share_bp <= FULL_SHARE_BP,
                "operation '{}' has developer_share_bp {} exceeding {}",
                op.operation,
                op.developer_share_bp,
                FULL_SHARE_BP
            );
            // A duplicate would price one operation twice, and which of the two
            // applies would depend on lookup order — cheap or expensive by
            // accident.
            assert!(
                !seen.contains(&op.operation.as_str()),
                "duplicate operation '{}': one operation has one price",
                op.operation
            );
            seen.push(&op.operation);
        }

        log!(
            "Priced project {}: {} operation(s), max {}, author {}",
            project_id,
            pricing.operations.len(),
            crate::payment::max_price(&pricing),
            pricing.author_account_id
        );
        self.project_pricing.insert(&project_id, &pricing);
    }

    /// Stop pricing a project: it goes back to being an ordinary project that
    /// admits any call, including one with no `attached_usd` at all.
    ///
    /// Removal rather than an empty list, because "priced at nothing" and "not
    /// priced" are the same state and there is no reason to have two spellings
    /// of it.
    pub fn remove_project_pricing(&mut self, project_id: String) {
        self.assert_owner();
        match self.project_pricing.remove(&project_id) {
            Some(_) => log!("Unpriced project {}", project_id),
            None => log!("Project {} had no price", project_id),
        }
    }

    /// Governance: the stablecoin top-ups are accepted in and payouts are made in.
    pub fn set_payment_token_contract(&mut self, token_contract: Option<AccountId>) {
        self.assert_governance();
        self.payment_token_contract = token_contract.clone();
        match token_contract {
            Some(contract) => log!("Payment token contract set to {}", contract),
            None => log!("Payment token contract cleared"),
        }
    }

    /// Emergency function to cancel pending execution and refund payer (only owner can call)
    pub fn emergency_cancel_execution(&mut self, request_id: u64) {
        self.assert_owner();

        if let Some(request) = self.pending_requests.remove(&request_id) {
            // Refund payment to payer
            near_sdk::Promise::new(request.payer_account_id.clone())
                .transfer(NearToken::from_yoctonear(request.payment));

            // And the stablecoin, to whoever attached it. Cancelling on
            // somebody's behalf must not cost them the developer payment for an
            // execution we just threw away.
            self.return_attached_usd(
                &request.sender_id,
                request.attached_usd,
                "the execution was cancelled by the operator",
            );

            log!(
                "Emergency cancelled execution {} and refunded {} yoctoNEAR to {}",
                request_id,
                request.payment,
                request.payer_account_id
            );
        } else {
            env::panic_str("Execution request not found");
        }
    }

    /// Set event metadata (only owner can call)
    /// Used to customize event standard name and version for different deployments
    pub fn set_event_metadata(&mut self, standard: Option<String>, version: Option<String>) {
        self.assert_owner();

        if let Some(s) = standard {
            self.event_standard = s.clone();
            log!("Event standard updated to {}", s);
        }
        if let Some(v) = version {
            self.event_version = v.clone();
            log!("Event version updated to {}", v);
        }
    }

    /// Cancel multiple pending executions by IDs and refund payers (only owner can call)
    ///
    /// # Arguments
    /// * `request_ids` - Array of request IDs to cancel
    ///
    /// # Returns
    /// Number of requests successfully cancelled
    pub fn cancel_pending_requests(&mut self, request_ids: Vec<u64>) -> u64 {
        self.assert_owner();

        let mut cancelled = 0;

        for request_id in request_ids {
            if let Some(request) = self.pending_requests.remove(&request_id) {
                near_sdk::Promise::new(request.payer_account_id.clone())
                    .transfer(NearToken::from_yoctonear(request.payment));

                // And the stablecoin, as on every other path that ends a request without
                // earning anything.
                self.return_attached_usd(
                    &request.sender_id,
                    request.attached_usd,
                    "the request was cancelled by the operator",
                );

                log!(
                    "Cancelled request {} and refunded {} yoctoNEAR to {}",
                    request_id,
                    request.payment,
                    request.payer_account_id
                );

                cancelled += 1;
            }
        }

        log!("Cancelled {} pending requests", cancelled);
        cancelled
    }

    /// Admin method to clear all pending requests (only owner can call)
    /// Used for emergency cleanup or testing
    ///
    /// # Arguments
    /// * `limit` - Maximum number of requests to clear in this call (to avoid gas limits)
    ///
    /// # Returns
    /// Number of requests cleared
    pub fn clear_all_pending_requests(&mut self, limit: Option<u64>) -> u64 {
        self.assert_owner();

        let max_limit = limit.unwrap_or(100); // Default to 100 to avoid gas issues
        let mut cleared = 0;

        for request_id in 0..self.next_request_id {
            if cleared >= max_limit {
                break;
            }

            if let Some(request) = self.pending_requests.remove(&request_id) {
                // Refund payment to payer
                near_sdk::Promise::new(request.payer_account_id.clone())
                    .transfer(NearToken::from_yoctonear(request.payment));

                // And the stablecoin, for the same reason as every other path
                // that ends a request without earning anything.
                self.return_attached_usd(
                    &request.sender_id,
                    request.attached_usd,
                    "the request was cleared by the operator",
                );

                log!(
                    "Cleared request {} and refunded {} yoctoNEAR to {}",
                    request_id,
                    request.payment,
                    request.payer_account_id
                );

                cleared += 1;
            }
        }

        log!("Cleared {} pending requests", cleared);
        cleared
    }
}
