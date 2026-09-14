use crate::*;
use near_sdk::serde_json::json;

#[near_bindgen]
impl Contract {
    /// Request off-chain execution
    ///
    /// # Arguments
    /// * `source` - Execution source: GitHub repo, WasmUrl, or Project reference
    /// * `resource_limits` - Optional resource limits for execution (default: 1B instructions, 128MB, 60s)
    ///                      If None, only compilation is performed (compile-only mode)
    /// * `input_data` - Optional input data for the WASM program (default: empty string)
    /// * `secrets_ref` - Optional reference to secrets (profile + account_id)
    /// * `response_format` - Optional output format: Bytes, Text, or Json (default: Text)
    /// * `payer_account_id` - Optional account to receive refunds (default: sender)
    /// * `params` - Optional request parameters (force_rebuild, store_on_fastfs)
    ///
    /// # Execution Source
    /// You can specify code in three ways:
    /// - `GitHub { repo, commit, build_target }` - Compile from GitHub repository
    /// - `WasmUrl { url, hash, build_target }` - Use pre-compiled WASM from URL
    /// - `Project { project_id, version_key }` - Use registered project (version_key=None for active version)
    ///
    /// # Compile-only Mode
    /// If `resource_limits` is None, only compilation is performed:
    /// - WASM is compiled and cached
    /// - No execution occurs
    /// - Useful for pre-compiling expensive builds
    ///
    /// # Secrets
    /// Secrets are stored in contract and accessed via references:
    /// 1. Store secrets once: `store_secrets(accessor, profile, encrypted_data, access_rules)`
    /// 2. Reference them in execution: `secrets_ref: { profile: "default", account_id: "alice.near" }`
    /// 3. Worker will fetch and decrypt secrets via keystore
    #[payable]
    pub fn request_execution(
        &mut self,
        source: ExecutionSource,
        resource_limits: Option<ResourceLimits>,
        input_data: Option<String>,
        secrets_ref: Option<SecretsReference>,
        response_format: Option<ResponseFormat>,
        payer_account_id: Option<AccountId>,
        params: Option<RequestParams>,
    ) {
        self.assert_not_paused();

        // A reference to a profile the contract could never have stored is
        // refused at the door, naming the rule — the one `store_secrets`
        // applies — so the worker never asks the keystore for it and nothing
        // sits in `pending_requests` for a run that cannot have a secret.
        if let Some(why) = secrets_ref.as_ref().and_then(|r| crate::secrets::profile_shape_error(&r.profile)) {
            env::panic_str(&format!(
                "secrets_ref.profile must be {} ({why}); the contract stores no such profile",
                crate::secrets::PROFILE_RULE
            ));
        }

        // Resolve ExecutionSource to CodeSource (and get project_uuid if applicable)
        let (resolved_source, project_uuid) = self.resolve_execution_source(&source);

        // Use provided limits or defaults (for execute mode)
        let limits = resource_limits.clone().unwrap_or_default();

        // Get params or defaults, but override project_uuid if resolved from Project source
        let mut request_params = params.unwrap_or_default();
        if project_uuid.is_some() {
            request_params.project_uuid = project_uuid;
        }

        // Determine if this is compile-only mode
        let compile_only = request_params.compile_only || resource_limits.is_none();

        // Validate: WasmUrl source cannot have force_rebuild
        if matches!(resolved_source, CodeSource::WasmUrl { .. }) && request_params.force_rebuild {
            env::panic_str("force_rebuild is not applicable for WasmUrl code source");
        }

        // Validate: store_on_fastfs requires force_rebuild (to ensure fresh compilation)
        if request_params.store_on_fastfs && !request_params.force_rebuild {
            env::panic_str("store_on_fastfs requires force_rebuild to ensure fresh compilation and upload");
        }

        // Validate: compile_only mode should not have input_data
        if compile_only && input_data.is_some() && !input_data.as_ref().unwrap().is_empty() {
            env::panic_str("input_data must be empty for compile_only mode - compilation does not use input_data");
        }

        // Validate resource limits against hard caps (only in execute mode)
        if !compile_only {
            let max_instructions = limits.max_instructions.unwrap_or_default();
            let max_execution_seconds = limits.max_execution_seconds.unwrap_or_default();

            assert!(
                max_instructions <= MAX_INSTRUCTIONS,
                "Requested max_instructions {} exceeds hard limit of {}",
                max_instructions,
                MAX_INSTRUCTIONS
            );

            assert!(
                max_execution_seconds <= MAX_EXECUTION_SECONDS,
                "Requested max_execution_seconds {} exceeds hard limit of {} seconds",
                max_execution_seconds,
                MAX_EXECUTION_SECONDS
            );
        }

        // Calculate cost: base fee for compile-only, full estimate for execute
        let estimated_cost = if compile_only {
            self.base_fee // Only base fee for compile-only
        } else {
            self.estimate_cost(&limits)
        };

        // Parse attached_usd for project owner (developer payment in stablecoin)
        let attached_usd = request_params.attached_usd.map(|d| d.0).unwrap_or(0);

        // Extract project_id from ExecutionSource if it's a Project source
        let project_id = match &source {
            ExecutionSource::Project { project_id, .. } => Some(project_id.clone()),
            _ => None,
        };

        // A priced project is charged for the operation it was asked to
        // perform, exactly.
        //
        // The operation is read out of `input_data` — the SAME bytes the guest
        // will dispatch on, under the one universal field name. That is the
        // whole reason the format is fixed rather than per-connector: there is
        // one value, so there is nothing to bind to anything and nothing that
        // can diverge. The contract does not need to know what a connector is
        // or how it reads its requests.
        //
        // At LEAST the price, not exactly it. It WAS exact, to avoid the
        // question of who returns the difference; the answer turned out to be
        // the settlement itself, which already re-reads the price to find the
        // author's share and can hand the excess back with no second copy of
        // the price anywhere. See `payment::settle_attached`.
        //
        // Not applied to compile-only requests: they compile and stop, so there
        // is no operation to charge for and no output to obtain.
        //
        // This is the ONLY gate. Connectors are reachable exclusively as
        // ordinary projects under `connectors.outlayer.near`, so there is no
        // second route to guard — the check follows the project, not the entry
        // point it was called through.
        if !compile_only {
            if let Some(pricing) = project_id.as_ref().and_then(|id| self.project_pricing.get(id)) {
                let id = project_id.as_deref().unwrap_or_default();

                let operation = crate::payment::operation_from_input(input_data.as_deref())
                    .unwrap_or_else(|e| {
                        env::panic_str(&format!("Project '{}' is priced per operation. {}", id, e.message()))
                    });

                // An operation with no row is refused, never run for free:
                // otherwise naming an operation we never priced is how a caller
                // runs our workers for nothing.
                let price = crate::payment::price_for_operation(&pricing, &operation)
                    .unwrap_or_else(|| {
                        env::panic_str(&format!(
                            "Project '{}' does not sell operation '{}'. See get_project_pricing.",
                            id, operation
                        ))
                    });

                // At LEAST the price. Attaching more is allowed and the excess
                // comes back — see the callback, which credits the difference
                // to the caller's balance and splits only the price.
                //
                // The alternative was to require the exact figure, which meant
                // every caller reading the price list before every call and
                // getting it wrong when a price moved between the two. Change
                // is cheaper: the contract already knows the price at
                // settlement, because it re-reads the same `operation` to find
                // the author's share, so nothing new has to be looked up and
                // no second copy of the price exists anywhere.
                assert!(
                    attached_usd >= price,
                    "Operation '{}' of '{}' costs {}; attach at least that as attached_usd (got {}). Anything over comes back.",
                    operation, id, price, attached_usd
                );
            }
        }

        // Validate: attached_usd only valid for Project source
        if attached_usd > 0 {
            assert!(
                matches!(source, ExecutionSource::Project { .. }),
                "attached_usd is only valid for Project execution source"
            );

            // Check user has enough stablecoin balance
            let caller = env::predecessor_account_id();
            let user_balance = self.user_stablecoin_balances.get(&caller).unwrap_or(0);
            assert!(
                user_balance >= attached_usd,
                "Insufficient stablecoin balance. Required: {}, available: {}",
                attached_usd,
                user_balance
            );

            // Deduct from user's stablecoin balance
            self.user_stablecoin_balances.insert(&caller, &(user_balance - attached_usd));
            log!(
                "Deducted {} stablecoin from {} for developer payment (remaining: {})",
                attached_usd,
                caller,
                user_balance - attached_usd
            );
        }

        // NEAR payment is only for compute costs now
        let payment = env::attached_deposit().as_yoctonear();

        assert!(
            payment >= estimated_cost,
            "Insufficient payment: required {} yoctoNEAR for compute, got {} yoctoNEAR",
            estimated_cost,
            payment
        );

        let request_id = self.next_request_id;
        self.next_request_id += 1;

        // predecessor_id = contract that called OutLayer (e.g. token.near)
        // signer_id = real user who signed the transaction (e.g. alice.near)
        let predecessor_id = env::predecessor_account_id();
        let signer_id = env::signer_account_id();

        // Payer: explicitly provided account or fallback to predecessor
        let payer_account_id = payer_account_id.unwrap_or_else(|| predecessor_id.clone());
        let format = response_format.unwrap_or_default();

        // Check if input_data is too large for event log (NEAR has 16KB limit per log)
        // Large payloads are stored in state only, worker fetches via get_request()
        let input_data_in_state = input_data
            .as_ref()
            .map(|d| d.len() >= INPUT_DATA_EVENT_THRESHOLD)
            .unwrap_or(false);

        // For large payloads, don't include in event - worker will fetch from state
        let input_data_for_event = if input_data_in_state {
            String::new()
        } else {
            input_data.as_ref().cloned().unwrap_or_default()
        };

        // Create execution request data for yield (send resolved_source to worker)
        let request_data = json!({
            "request_id": request_id,
            "sender_id": signer_id,
            "predecessor_id": predecessor_id,
            "code_source": resolved_source,
            "resource_limits": limits,
            "input_data": input_data_for_event,
            "input_data_in_state": input_data_in_state,
            "secrets_ref": secrets_ref.as_ref(),
            "response_format": format,
            "payment": U128::from(payment),
            "attached_usd": U128::from(attached_usd),
            "timestamp": env::block_timestamp(),
            "compile_only": compile_only,
            "force_rebuild": request_params.force_rebuild,
            "store_on_fastfs": request_params.store_on_fastfs,
            "use_bound_identity": request_params.use_bound_identity,
            "project_uuid": request_params.project_uuid,
            "project_id": project_id
        });

        // Create yield promise to pause execution
        let promise_idx = env::promise_yield_create(
            "on_execution_response",
            &request_data.to_string().into_bytes(),
            MIN_RESPONSE_GAS,
            GasWeight::default(),
            DATA_ID_REGISTER,
        );

        // Get data_id for the yield promise
        let data_id: CryptoHash = env::read_register(DATA_ID_REGISTER)
            .expect("Register is empty")
            .try_into()
            .expect("Wrong register length");

        // Store the pending execution request
        // Note: sender_id in ExecutionRequest stores predecessor (contract that called us)
        // This is used for authorization checks (cancel_stale_execution)
        let execution_request = ExecutionRequest {
            request_id,
            data_id,
            sender_id: predecessor_id.clone(),
            execution_source: source.clone(),
            resolved_source: resolved_source.clone(),
            resource_limits: limits.clone(),
            payment,
            timestamp: env::block_timestamp(),
            secrets_ref,
            response_format: format.clone(),
            input_data,
            payer_account_id,
            attached_usd,
            pending_output: None,
            output_submitted: false,
        };

        self.pending_requests
            .insert(&request_id, &execution_request);

        // Emit event for workers to catch
        events::emit::execution_requested(&self.event_standard, &self.event_version, &request_data.to_string(), data_id);

        // Return the promise to pause execution
        env::promise_return(promise_idx)
    }



    /// Worker calls this to submit large execution output (> 1024 bytes)
    /// This is the first step of 2-call flow for large outputs
    pub fn submit_execution_output(&mut self, request_id: u64, output: ExecutionOutput) {
        // Only operator can submit execution data
        self.assert_operator();

        self.submit_execution_output_internal(request_id, output);
    }

    /// Worker calls this to submit large output AND resolve in one transaction (recommended)
    ///
    /// This method combines submit_execution_output + resolve_execution into a single call:
    /// 1. Stores the large output in contract storage
    /// 2. Immediately calls resolve_execution_internal with metadata only
    ///
    /// This saves ~1-2 seconds compared to two separate transactions.
    ///
    /// # Arguments
    /// * `request_id` - Request ID
    /// * `output` - Large execution output (> 1024 bytes)
    /// * `success` - Whether execution succeeded
    /// * `error` - Error message if failed
    /// * `resources_used` - Actual resource consumption
    pub fn submit_execution_output_and_resolve(
        &mut self,
        request_id: u64,
        output: ExecutionOutput,
        success: bool,
        error: Option<String>,
        resources_used: ResourceMetrics,
        compilation_note: Option<String>,
    ) {
        // Only operator can submit execution data
        self.assert_operator();

        // Step 1: Store the large output
        self.submit_execution_output_internal(request_id, output);

        // Step 2: Immediately resolve with metadata only (no Promise needed!)
        let response = ExecutionResponse {
            success,
            output: None, // Output already stored above
            error,
            resources_used,
            compilation_note,
            refund_usd: None, // Large output flow doesn't support refund
        };

        log!(
            "Resolving execution for request_id: {} (combined flow)",
            request_id
        );

        // Call resolve directly in the same function call
        self.resolve_execution_internal(request_id, response);
    }



    /// Worker calls this to resolve execution (small output) or finalize after submit_execution_output (large output)
    ///
    /// For outputs <= 1024 bytes: Call this directly with output in response
    /// For outputs > 1024 bytes: Call submit_execution_output first, then call this
    /// Or use submit_execution_output_and_resolve for optimized 1-call flow
    pub fn resolve_execution(&mut self, request_id: u64, response: ExecutionResponse) {
        // Only operator can resolve executions
        self.assert_operator();

        self.resolve_execution_internal(request_id, response);
    }

    #[allow(unused_variables)]
    #[private]
    /// Callback function to handle execution completion
    pub fn on_execution_response(
        &mut self,
        request_id: u64,
        sender_id: AccountId,
        code_source: CodeSource,
        resource_limits: ResourceLimits,
        payment: U128,
        #[callback_result] response: Result<ExecutionResponse, PromiseError>,
    ) -> Option<serde_json::Value> {
        // Remove the pending request and check if output was submitted separately
        if let Some(request) = self.pending_requests.remove(&request_id) {
            self.total_executions += 1;

            match response {
                Ok(mut exec_response) => {
                    // If output was submitted separately, retrieve it from storage
                    if request.output_submitted && exec_response.success {
                        log!("Retrieving large output from storage for request_id: {}", request_id);
                        if let Some(stored_output) = request.pending_output.clone() {
                            let output: crate::ExecutionOutput = stored_output.into();
                            exec_response.output = Some(output);
                        }
                    }

                    if exec_response.success {
                        // Calculate actual cost (NEAR only)
                        let cost = self.calculate_cost(&exec_response.resources_used);

                        // Handle stablecoin payment with refund support
                        if request.attached_usd > 0 {
                            // What the operation cost, and what was merely
                            // attached. For a priced project those differ
                            // whenever the caller rounded up — admission takes
                            // at least the price and the excess is theirs.
                            //
                            // Read from the same table and the same
                            // `input_data` the price came from, so there is one
                            // copy of the price and it is the chain's.
                            let priced: Option<(AccountId, u128, u16)> =
                                if let ExecutionSource::Project { project_id, .. } =
                                    &request.execution_source
                                {
                                    self.project_pricing.get(project_id).and_then(|pricing| {
                                        let operation = crate::payment::operation_from_input(
                                            request.input_data.as_deref(),
                                        )
                                        .ok()?;
                                        let op = pricing
                                            .operations
                                            .iter()
                                            .find(|o| o.operation == operation)?;
                                        Some((
                                            pricing.author_account_id.clone(),
                                            op.price_usd.0,
                                            op.developer_share_bp,
                                        ))
                                    })
                                } else {
                                    None
                                };

                            // An unpriced project keeps the old meaning: what
                            // was attached is what was meant for the developer.
                            let price = priced
                                .as_ref()
                                .map(|(_, p, _)| *p)
                                .unwrap_or(request.attached_usd);

                            // The guest may still hand part of the PRICE back —
                            // its own decision about the work it did — and it
                            // cannot reach past the price into the change,
                            // which is not its money to give.
                            let (refund_usd, developer_amount) = crate::payment::settle_attached(
                                request.attached_usd,
                                price,
                                exec_response.refund_usd.map(|r| r as u128).unwrap_or(0),
                            );

                            // Both refunds belong to the caller: the change is
                            // theirs because they attached it, and the guest's
                            // own refund was taken out of the price on their
                            // behalf.
                            self.return_attached_usd(
                                &request.sender_id,
                                refund_usd,
                                "change and guest refund",
                            );

                            // Credit developer earnings if developer_amount > 0
                            if developer_amount > 0 {
                                // Who is left to pay. Resolved first, and as an
                                // option, because a project can be deleted
                                // between admission and settlement — and money
                                // with no payee has to go somewhere it can be
                                // accounted for.
                                let payee = match &request.execution_source {
                                    ExecutionSource::Project { project_id, .. } => self
                                        .projects
                                        .get(project_id)
                                        .map(|project| (project_id.clone(), project)),
                                    _ => None,
                                };

                                match payee {
                                    Some((project_id, project)) => {
                                        // For a PRICED project the money is split: the
                                        // connector's author takes the share their
                                        // operation carries, and what is left belongs to
                                        // the project's owner — us, since every connector
                                        // lives under our namespace.
                                        //
                                        // Everything needed is already on the request:
                                        // `input_data` was stored with it, so the operation
                                        // is re-read from the same bytes admission priced,
                                        // and the share comes from the same table.
                                        //
                                        // The table is read again HERE rather than snapshot
                                        // at admission. The window is one execution and the
                                        // table is owner-only, so a change mid-flight is
                                        // both rare and ours; the alternative is a side map
                                        // holding a copy of the share for every pending
                                        // request, forever, to close a gap nobody but us
                                        // can open.
                                        //
                                        // The amount being split is NOT fixed at admission
                                        // any more, and saying so was wrong once the gate
                                        // became `>=`: the split base is the price as read
                                        // HERE, so raising a price — or unpricing the
                                        // project, which makes the whole attachment the
                                        // price — mid-flight turns a caller's change into
                                        // developer earnings. Bounded by what was attached,
                                        // owner-only, and accepted as such.
                                        let split = priced.as_ref().map(|(author, _, share)| {
                                            (
                                                author.clone(),
                                                crate::payment::split_payment(
                                                    developer_amount,
                                                    *share,
                                                ),
                                            )
                                        });

                                        match split {
                                            Some((author, split)) if split.author_usd > 0 => {
                                                let current = self.developer_earnings.get(&author).unwrap_or(0);
                                                self.developer_earnings.insert(&author, &(current + split.author_usd));
                                                let current = self.developer_earnings.get(&project.owner).unwrap_or(0);
                                                self.developer_earnings.insert(&project.owner, &(current + split.owner_usd));
                                                log!(
                                                    "Split {} stablecoin for project {}: {} to author {}, {} to owner {} (attached={}, refund={})",
                                                    developer_amount, project_id,
                                                    split.author_usd, author,
                                                    split.owner_usd, project.owner,
                                                    request.attached_usd, refund_usd
                                                );
                                            }
                                            // No price, no operation, or a zero share:
                                            // everything to the project's owner, exactly as
                                            // before. This is the path every ordinary
                                            // project takes and must keep taking.
                                            _ => {
                                                let current = self.developer_earnings.get(&project.owner).unwrap_or(0);
                                                self.developer_earnings.insert(&project.owner, &(current + developer_amount));
                                                log!(
                                                    "Credited {} stablecoin to developer {} for project {} (attached={}, refund={})",
                                                    developer_amount, project.owner, project_id, request.attached_usd, refund_usd
                                                );
                                            }
                                        }
                                    }
                                    // The project was deleted while this
                                    // execution was in flight, so there is
                                    // nobody left to credit. The caller gets
                                    // their money back: keeping it would leave
                                    // tokens on the contract that no balance
                                    // and no earnings row accounts for.
                                    None => self.return_attached_usd(
                                        &request.sender_id,
                                        developer_amount,
                                        "the project no longer exists",
                                    ),
                                }
                            }
                        }

                        // Refund excess NEAR payment (minus compute cost only, stablecoin is separate)
                        let refund = payment.0.saturating_sub(cost);
                        if refund > 0 {
                            // Transfer refund to payer account
                            near_sdk::Promise::new(request.payer_account_id.clone())
                                .transfer(NearToken::from_yoctonear(refund));
                        }

                        // Collect fee
                        self.total_fees_collected += cost;

                        // Log payment charged in easy-to-parse format for worker
                        log!("[[yNEAR charged: \"{}\"]]", cost);

                        // Emit success event
                        events::emit::execution_completed(
                            &self.event_standard,
                            &self.event_version,
                            &sender_id,
                            &code_source,
                            &exec_response.resources_used,
                            true,
                            None,
                            U128(cost),    // payment_charged
                            U128(refund),  // payment_refunded
                            exec_response.compilation_note.as_deref(),
                        );

                        // Log the execution result with resources used
                        if let Some(output) = exec_response.output {
                            // Convert ExecutionOutput to plain JSON value (without enum wrapper)
                            let json_value = match &output {
                                ExecutionOutput::Bytes(bytes) => {
                                    // For bytes, encode as base64 string
                                    use near_sdk::base64::{engine::general_purpose::STANDARD, Engine};
                                    serde_json::Value::String(STANDARD.encode(bytes))
                                }
                                ExecutionOutput::Text(text) => {
                                    // For text, return as JSON string
                                    serde_json::Value::String(text.clone())
                                }
                                ExecutionOutput::Json(value) => {
                                    // For JSON, return the value directly
                                    value.clone()
                                }
                            };

                            // Log for debugging (with type info, truncated to avoid log limit)
                            let log_preview = match &output {
                                ExecutionOutput::Bytes(bytes) => format!("Bytes({} bytes)", bytes.len()),
                                ExecutionOutput::Text(text) => {
                                    let preview: String = text.chars().take(100).collect();
                                    if text.len() > 100 {
                                        format!("Text({} bytes): {}...", text.len(), preview)
                                    } else {
                                        format!("Text: {}", text)
                                    }
                                }
                                ExecutionOutput::Json(value) => {
                                    let json_str = serde_json::to_string(value).unwrap_or_default();
                                    let preview: String = json_str.chars().take(100).collect();
                                    if json_str.len() > 100 {
                                        format!("Json({} bytes): {}...", json_str.len(), preview)
                                    } else {
                                        format!("Json: {}", json_str)
                                    }
                                }
                            };

                            let compilation_info = exec_response.compilation_note
                                .as_ref()
                                .map(|note| format!(", {}", note))
                                .unwrap_or_default();

                            log!(
                                "Execution completed successfully. Output: {}, Resources: {{ instructions: {}, time_ms: {} }}, Cost: {} yoctoNEAR, Refund: {} yoctoNEAR{}",
                                log_preview,
                                exec_response.resources_used.instructions,
                                exec_response.resources_used.time_ms,
                                cost,
                                refund,
                                compilation_info
                            );

                            Some(json_value)
                        } else {
                            let compilation_info = exec_response.compilation_note
                                .as_ref()
                                .map(|note| format!(", {}", note))
                                .unwrap_or_default();

                            log!(
                                "Execution has no output value. Resources: {{ instructions: {}, time_ms: {} }}, Cost: {} yoctoNEAR, Refund: {} yoctoNEAR{}",
                                exec_response.resources_used.instructions,
                                exec_response.resources_used.time_ms,
                                cost,
                                refund,
                                compilation_info
                            );

                            None
                        }
                    } else {
                        // Execution failed - refund NEAR (except base fee) and stablecoin
                        // Developer gets nothing on failure

                        // Refund NEAR (minus base fee)
                        let refund = payment.0.saturating_sub(self.base_fee);
                        if refund > 0 {
                            near_sdk::Promise::new(request.payer_account_id.clone())
                                .transfer(NearToken::from_yoctonear(refund));
                        }

                        self.return_attached_usd(
                            &request.sender_id,
                            request.attached_usd,
                            "execution failed",
                        );

                        self.total_fees_collected += self.base_fee;

                        // Log payment charged in easy-to-parse format for worker (only base fee charged on failure)
                        log!("[[yNEAR charged: \"{}\"]]", self.base_fee);

                        // Get error message for event
                        let error_msg = exec_response.error.unwrap_or("Unknown error".to_string());

                        // Emit failure event with error details
                        events::emit::execution_completed(
                            &self.event_standard,
                            &self.event_version,
                            &sender_id,
                            &code_source,
                            &exec_response.resources_used,
                            false,
                            Some(&error_msg),
                            U128(self.base_fee),  // payment_charged (only base fee)
                            U128(refund),         // payment_refunded
                            exec_response.compilation_note.as_deref(),
                        );

                        // Log the failure (don't panic - state changes must persist!)
                        log!(
                            "Execution failed: {}. Resources: {{ instructions: {}, time_ms: {} }}. Refunded {} yoctoNEAR",
                            error_msg,
                            exec_response.resources_used.instructions,
                            exec_response.resources_used.time_ms,
                            refund
                        );

                        // Return None to indicate failure to calling contract
                        None
                    }
                }
                Err(promise_error) => {
                    // Promise failed - refund NEAR (except base fee) and stablecoin
                    // Developer gets nothing on failure

                    // Refund NEAR (minus base fee)
                    let refund = payment.0.saturating_sub(self.base_fee);
                    if refund > 0 {
                        near_sdk::Promise::new(request.payer_account_id.clone())
                            .transfer(NearToken::from_yoctonear(refund));
                    }

                    self.return_attached_usd(
                        &request.sender_id,
                        request.attached_usd,
                        "the execution promise failed",
                    );

                    self.total_fees_collected += self.base_fee;

                    // Log payment charged in easy-to-parse format for worker (only base fee charged on promise failure)
                    log!("[[yNEAR charged: \"{}\"]]", self.base_fee);

                    // Log the promise failure (don't panic - state changes must persist!)
                    log!(
                        "Execution promise failed: {:?}. Refunded {} yoctoNEAR",
                        promise_error, refund
                    );

                    // Return None to indicate failure to calling contract
                    None
                }
            }
        } else {
            log!(
                "Warning: Execution request {} not found in pending requests",
                request_id
            );

            None
        }
    }

    /// Cancel stale execution request if timeout has passed
    pub fn cancel_stale_execution(&mut self, request_id: u64) {
        let request = self
            .pending_requests
            .get(&request_id)
            .expect("Execution request not found");

        // Ensure the caller is the original sender
        assert_eq!(
            env::predecessor_account_id(),
            request.sender_id,
            "Only the sender can cancel this execution"
        );

        // Check if the timeout period has passed
        let is_stale = env::block_timestamp() > request.timestamp + EXECUTION_TIMEOUT;
        assert!(is_stale, "Execution is not yet stale, please wait");

        // Remove the request and return BOTH sides of what it took: the NEAR
        // held for compute, and the stablecoin admission debited for the
        // developers. A cancelled request earns nobody anything, so leaving the
        // stablecoin behind would take a caller's money for work that never
        // happened.
        //
        // Removal is what makes this safe to pay out. It is the same single
        // token `on_execution_response` claims, so a request is settled here or
        // there, never in both.
        if let Some(stale_request) = self.pending_requests.remove(&request_id) {
            near_sdk::Promise::new(stale_request.payer_account_id.clone())
                .transfer(NearToken::from_yoctonear(stale_request.payment));

            self.return_attached_usd(
                &stale_request.sender_id,
                stale_request.attached_usd,
                "the execution was cancelled as stale",
            );


            log!(
                "Cancelled stale execution {} and refunded payer {}",
                request_id,
                stale_request.payer_account_id
            );
        }
    }
}

// ============================================================================
// Execution Source Resolution
// ============================================================================

impl Contract {
    /// Give an execution's stablecoin back to the account that attached it.
    ///
    /// One function, because the money can fail to be earned in SEVEN different
    /// ways — the guest hands part of it back, the guest fails, the promise
    /// dies, the project is gone by settlement, the caller cancels a stuck
    /// request, we cancel one for them, we clear a batch — and every one of them
    /// has to end in the same place.
    ///
    /// That count said five when this was written, and it was wrong: the two
    /// BULK admin paths were missed, and each destroyed a caller's stablecoin
    /// while dutifully returning their NEAR. An enumeration in a comment is not
    /// a guard. What to check when adding a caller is `pending_requests.remove`
    /// — the operation that ends a request is the one that owes the money back. A path that forgets is
    /// invisible from the outside: the tokens stay on the contract with no
    /// ledger row pointing at them, so no balance anyone can read ever says
    /// they are missing.
    ///
    /// Always `sender_id`, never `payer_account_id`. Admission debits the
    /// predecessor and stores exactly that account as `sender_id`, so it is the
    /// one the money came out of; `payer_account_id` is the NEAR side and may
    /// be somebody else entirely.
    pub(crate) fn return_attached_usd(&mut self, account: &AccountId, amount: u128, reason: &str) {
        if amount == 0 {
            return;
        }
        let current = self.user_stablecoin_balances.get(account).unwrap_or(0);
        self.user_stablecoin_balances.insert(account, &(current + amount));
        log!(
            "Returned {} stablecoin to {} ({})",
            amount,
            account,
            reason
        );
    }

    /// Resolve ExecutionSource to CodeSource for worker
    /// Returns (resolved_source, project_uuid)
    /// Secrets are passed as-is through secrets_ref parameter, no auto-lookup
    fn resolve_execution_source(
        &self,
        source: &ExecutionSource,
    ) -> (CodeSource, Option<String>) {
        match source {
            ExecutionSource::GitHub { repo, commit, build_target } => {
                (
                    CodeSource::GitHub {
                        repo: repo.clone(),
                        commit: commit.clone(),
                        build_target: build_target.clone(),
                    },
                    None,
                )
            }
            ExecutionSource::WasmUrl { url, hash, build_target } => {
                (
                    CodeSource::WasmUrl {
                        url: url.clone(),
                        hash: hash.clone(),
                        build_target: build_target.clone(),
                    },
                    None,
                )
            }
            ExecutionSource::Project { project_id, version_key } => {
                // Get project
                let project = self.projects.get(project_id)
                    .expect("Project not found");

                // Determine which version to use
                let version_to_use = version_key.clone().unwrap_or_else(|| {
                    assert!(
                        !project.active_version.is_empty(),
                        "Project has no active version"
                    );
                    project.active_version.clone()
                });

                // Get version info to get CodeSource
                let versions = self.project_versions.get(&project.uuid)
                    .expect("Project versions not found");

                let version_info = versions.get(&version_to_use)
                    .expect("Version not found");

                log!(
                    "Resolved project: {}, version: {}, source: {:?}, uuid: {}",
                    project_id, version_to_use, version_info.source, project.uuid
                );

                (version_info.source.clone(), Some(project.uuid.clone()))
            }
        }
    }

    /// Internal helper to submit execution output (used by both public methods)
    pub(crate) fn submit_execution_output_internal(&mut self, request_id: u64, output: ExecutionOutput) {
        // Get the pending request
        let mut request = self
            .pending_requests
            .get(&request_id)
            .expect("Execution request not found");

        // Ensure output was not already submitted
        assert!(
            !request.output_submitted,
            "Output already submitted for this request"
        );

        // Store the output in the request (convert to internal storage format)
        let stored_output: crate::StoredOutput = output.into();
        request.pending_output = Some(stored_output);
        request.output_submitted = true;

        // Save updated request
        self.pending_requests.insert(&request_id, &request);

        log!(
            "Stored pending output for request_id: {}, data_id: {:?}",
            request_id,
            request.data_id
        );
    }

    /// Internal helper to resolve execution (no operator check)
    fn resolve_execution_internal(&mut self, request_id: u64, response: ExecutionResponse) {
        // Get the pending request
        let request = self
            .pending_requests
            .get(&request_id)
            .expect("Execution request not found");

        let data_id = request.data_id;

        // Calculate estimated cost for logging
        let estimated_cost = self.calculate_cost(&response.resources_used);

        log!(
            "Resolving execution for request_id: {}, data_id: {:?}, success: {}, output_submitted: {}, resources_used: {{ instructions: {}, time_ms: {}, compile_time_ms: {:?} }}",
            request_id,
            data_id,
            response.success,
            request.output_submitted,
            response.resources_used.instructions,
            response.resources_used.time_ms,
            response.resources_used.compile_time_ms
        );

        // Log cost in easy-to-parse format for worker
        log!("[[yNEAR charged: \"{}\"]]", estimated_cost);

        // For large outputs, we only pass metadata through resume (output stays in storage)
        // The callback will retrieve it from pending_output field
        // This avoids the 1024 byte limit of promise_yield_resume
        if !env::promise_yield_resume(&data_id, &serde_json::to_vec(&response).unwrap()) {
            env::panic_str("Unable to resume execution promise");
        }
    }
}

#[cfg(test)]
mod who_the_on_chain_door_judges {
    //! The plan defines the identity a secret's condition is judged against
    //! (Phase 0, entry point 2): `user_account_id` = the transaction's SIGNER on
    //! this door, the payment key's owner over HTTPS. `request_execution` hands
    //! that identity to the worker as the `sender_id` of the
    //! `execution_requested` payload; the worker forwards it as
    //! `user_account_id` and the keystore validates the row's condition against
    //! it. This pins which account that is when the predecessor and the signer
    //! differ — a contract relaying a request a human signed. Should the plan
    //! move to the predecessor, the assertion flips with it: the payload
    //! already carries `predecessor_id`.
    use super::*;
    use near_sdk::test_utils::{accounts, get_logs, VMContextBuilder};
    use near_sdk::{testing_env, NearToken};

    fn context(predecessor: AccountId, signer: AccountId, deposit: NearToken) -> VMContextBuilder {
        let mut b = VMContextBuilder::new();
        b.predecessor_account_id(predecessor)
            .signer_account_id(signer)
            .attached_deposit(deposit)
            .prepaid_gas(Gas::from_tgas(300));
        b
    }

    /// The `sender_id` inside the payload handed to the worker — the string
    /// the `execution_requested` event carries. Nested JSON is unescaped by
    /// parsing, never by string surgery.
    fn worker_payload_sender() -> String {
        for log in get_logs() {
            let Some(json) = log.strip_prefix("EVENT_JSON:") else { continue };
            let event: serde_json::Value = serde_json::from_str(json).expect("event is JSON");
            if event["event"] != "execution_requested" {
                continue;
            }
            fn find(v: &serde_json::Value) -> Option<String> {
                match v {
                    serde_json::Value::String(s) if s.contains("\"sender_id\"") => {
                        serde_json::from_str::<serde_json::Value>(s)
                            .ok()
                            .and_then(|p| p["sender_id"].as_str().map(str::to_string))
                    }
                    serde_json::Value::Object(m) => m.values().find_map(find),
                    serde_json::Value::Array(a) => a.iter().find_map(find),
                    _ => None,
                }
            }
            if let Some(s) = find(&event) {
                return s;
            }
        }
        panic!("no execution_requested event with a sender_id in the logs");
    }

    #[test]
    fn the_worker_is_handed_the_signer_to_judge_the_condition_against() {
        let owner = accounts(0);
        let operator = accounts(1);
        let deputy = accounts(2);
        let victim = accounts(3);
        testing_env!(context(owner.clone(), owner.clone(), NearToken::from_near(0)).build());
        let mut contract = Contract::new(owner, Some(operator), None, None);

        // A contract (the deputy) is the predecessor; a human (the victim) signed.
        testing_env!(context(deputy.clone(), victim.clone(), NearToken::from_near(1)).build());
        contract.request_execution(
            ExecutionSource::GitHub {
                repo: "https://github.com/out-layer/anything".to_string(),
                commit: "0000000000000000000000000000000000000000".to_string(),
                build_target: None,
            },
            None, // compile-only: the cheapest shape that still yields
            None,
            Some(SecretsReference { profile: "sec".to_string(), account_id: victim.clone() }),
            None,
            None,
            None,
        );
        assert_eq!(
            worker_payload_sender(),
            victim.to_string(),
            "the judged identity is the transaction's signer; the worker was handed someone else"
        );
    }
}

#[cfg(test)]
mod a_reference_the_contract_could_never_match {
    //! A hostile `secrets_ref` is refused cleanly, and every refusal names its
    //! reason. On this door the contract refuses a profile `store_secrets`
    //! would never have accepted, before yielding.
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::{testing_env, NearToken};

    fn request_with_profile(profile: &str) {
        let owner = accounts(0);
        let mut b = VMContextBuilder::new();
        b.predecessor_account_id(owner.clone()).signer_account_id(owner.clone())
            .attached_deposit(NearToken::from_near(0)).prepaid_gas(Gas::from_tgas(300));
        testing_env!(b.build());
        let mut contract = Contract::new(owner, Some(accounts(1)), None, None);
        let caller = accounts(2);
        let mut b2 = VMContextBuilder::new();
        b2.predecessor_account_id(caller.clone()).signer_account_id(caller.clone())
            .attached_deposit(NearToken::from_near(1)).prepaid_gas(Gas::from_tgas(300));
        testing_env!(b2.build());
        contract.request_execution(
            ExecutionSource::GitHub {
                repo: "https://github.com/out-layer/anything".to_string(),
                commit: "0".repeat(40),
                build_target: None,
            },
            None,
            None,
            Some(SecretsReference { profile: profile.to_string(), account_id: caller }),
            None,
            None,
            None,
        );
    }

    #[test]
    fn a_64_character_profile_is_accepted() {
        request_with_profile(&"p".repeat(64));
    }
    #[test]
    #[should_panic(expected = "'-' or '_' (got 10240 bytes)")]
    fn a_10_kb_profile_is_refused_naming_the_rule() {
        request_with_profile(&"p".repeat(10_240));
    }
    #[test]
    #[should_panic(expected = "secrets_ref.profile must be 1–64 bytes")]
    fn a_65_character_profile_is_refused() {
        request_with_profile(&"p".repeat(65));
    }
    #[test]
    #[should_panic(expected = "secrets_ref.profile must be 1–64 bytes")]
    fn an_empty_profile_is_refused() {
        request_with_profile("");
    }
    #[test]
    #[should_panic(expected = "'-' or '_' (it contains '/')")]
    fn a_profile_with_a_slash_is_refused_naming_the_character() {
        request_with_profile("sec/../author");
    }
    /// The verdict of a real `store_secrets` and of a real `request_execution`
    /// on the same profile, side by side: what one door refuses the other
    /// refuses, for the same reason, and what one stores the other can name.
    /// Through the public entry points, not the predicate — a predicate agrees
    /// with itself for free.
    #[test]
    fn the_door_and_the_store_agree_on_the_rule() {
        use std::panic::{catch_unwind, AssertUnwindSafe};
        fn reason(payload: Box<dyn std::any::Any + Send>) -> String {
            payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default()
        }
        fn store_verdict(profile: &str) -> Result<(), String> {
            catch_unwind(AssertUnwindSafe(|| {
                let owner = accounts(0);
                let mut b = VMContextBuilder::new();
                b.predecessor_account_id(owner.clone()).signer_account_id(owner.clone())
                    .attached_deposit(NearToken::from_near(0)).prepaid_gas(Gas::from_tgas(300));
                testing_env!(b.build());
                let mut contract = Contract::new(owner, Some(accounts(1)), None, None);
                let user = accounts(2);
                let mut b2 = VMContextBuilder::new();
                b2.predecessor_account_id(user.clone()).signer_account_id(user.clone())
                    .attached_deposit(NearToken::from_near(1)).prepaid_gas(Gas::from_tgas(300));
                testing_env!(b2.build());
                contract.store_secrets(
                    SecretAccessor::Repo { repo: "github.com/alice/project".to_string(), branch: None },
                    profile.to_string(),
                    "base64encodeddata".to_string(),
                    crate::types::AccessCondition::AllowAll,
                    None,
                );
            }))
            .map_err(reason)
        }
        fn door_verdict(profile: &str) -> Result<(), String> {
            catch_unwind(AssertUnwindSafe(|| request_with_profile(profile))).map_err(reason)
        }
        // A multi-byte letter is a letter (the charset rule is Unicode) but
        // counts by its bytes: 64 of them is 128 bytes, refused by both doors.
        let sixty_four_cyrillic = "ж".repeat(64);
        let thirty_two_cyrillic = "ж".repeat(32);
        let cases: [&str; 13] = [
            "sec", "a-b_c9", &"x".repeat(64), &thirty_two_cyrillic,
            "", "a/b", "a b", "a:b", "a(b", "a)b", &"x".repeat(65), &sixty_four_cyrillic, &"p".repeat(10_240),
        ];
        for profile in cases {
            let (store, door) = (store_verdict(profile), door_verdict(profile));
            match (&store, &door) {
                (Ok(()), Ok(())) => {}
                (Err(s), Err(d)) => {
                    // The reason is the parenthesised group right after the
                    // rule. The door adds a "; …" tail the store does not, and
                    // the mock wraps the message in `GuestPanic { … "…" }`, so
                    // the group ends at the first `)` followed by `;` or `"`.
                    let why = |m: &str| {
                        let rest = m.split_once(crate::secrets::PROFILE_RULE)?.1.trim_start();
                        let end = rest.find(");").or_else(|| rest.find(")\""))?;
                        Some(rest[..=end].to_string())
                    };
                    assert_eq!(why(s), why(d), "the two doors refuse {profile:?} for different reasons:\n  store: {s}\n  door:  {d}");
                    assert!(s.contains(crate::secrets::PROFILE_RULE) && d.contains(crate::secrets::PROFILE_RULE), "both name the rule");
                }
                _ => panic!("the doors disagree on {profile:?}: store={store:?} door={door:?}"),
            }
        }
    }
}


#[cfg(test)]
mod a_condition_past_the_pattern_bounds_is_not_stored {
    //! The keystore refuses to judge a condition with more than
    //! `MAX_ACCOUNT_PATTERNS` leaves or more than `MAX_ACCOUNT_PATTERN_BYTES`
    //! of pattern text; both store doors refuse to store one.
    use super::*;
    use crate::secrets::{MAX_ACCOUNT_PATTERNS, MAX_ACCOUNT_PATTERN_BYTES};
    use crate::types::{AccessCondition, LogicOperatorV1};
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::{testing_env, NearToken};

    fn contract_and_user() -> (Contract, AccountId) {
        let owner = accounts(0);
        let mut b = VMContextBuilder::new();
        b.predecessor_account_id(owner.clone()).signer_account_id(owner.clone())
            .attached_deposit(NearToken::from_near(0)).prepaid_gas(Gas::from_tgas(300));
        testing_env!(b.build());
        let contract = Contract::new(owner, Some(accounts(1)), None, None);
        let user = accounts(2);
        let mut b2 = VMContextBuilder::new();
        b2.predecessor_account_id(user.clone()).signer_account_id(user.clone())
            .attached_deposit(NearToken::from_near(1)).prepaid_gas(Gas::from_tgas(300));
        testing_env!(b2.build());
        (contract, user)
    }
    fn or_of_patterns(patterns: Vec<String>) -> AccessCondition {
        AccessCondition::Logic {
            operator: LogicOperatorV1::Or,
            conditions: patterns.into_iter().map(|pattern| AccessCondition::AccountPattern { pattern }).collect(),
        }
    }
    fn store(contract: &mut Contract, profile: &str, access: AccessCondition) {
        contract.store_secrets(
            SecretAccessor::Repo { repo: "github.com/alice/project".to_string(), branch: None },
            profile.to_string(),
            "base64encodeddata".to_string(),
            access,
            None,
        );
    }

    #[test]
    fn the_bounds_themselves_are_stored() {
        let (mut contract, _) = contract_and_user();
        store(&mut contract, "leaves", or_of_patterns((0..MAX_ACCOUNT_PATTERNS).map(|i| format!("a{i}\\.near")).collect()));
        store(&mut contract, "bytes", or_of_patterns(vec!["a".repeat(MAX_ACCOUNT_PATTERN_BYTES / 2), "b".repeat(MAX_ACCOUNT_PATTERN_BYTES / 2)]));
    }

    #[test]
    #[should_panic(expected = "holds 17 AccountPattern leaves; at most 16 are judged")]
    fn one_leaf_past_the_count_is_refused_at_store() {
        let (mut contract, _) = contract_and_user();
        store(&mut contract, "leaves", or_of_patterns((0..=MAX_ACCOUNT_PATTERNS).map(|i| format!("a{i}\\.near")).collect()));
    }

    #[test]
    #[should_panic(expected = "AccountPattern text is 4097 bytes in all; at most 4096 are judged")]
    fn one_byte_past_the_text_bound_is_refused_at_store() {
        let (mut contract, _) = contract_and_user();
        store(&mut contract, "bytes", or_of_patterns(vec!["a".repeat(MAX_ACCOUNT_PATTERN_BYTES), "b".to_string()]));
    }

    #[test]
    #[should_panic(expected = "holds 17 AccountPattern leaves")]
    fn the_same_bound_holds_at_update_access() {
        let (mut contract, _) = contract_and_user();
        store(&mut contract, "row", AccessCondition::AllowAll);
        contract.update_access(
            SecretAccessor::Repo { repo: "github.com/alice/project".to_string(), branch: None },
            "row".to_string(),
            or_of_patterns((0..=MAX_ACCOUNT_PATTERNS).map(|i| format!("a{i}\\.near")).collect()),
        );
    }
}
