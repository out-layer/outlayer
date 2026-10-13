#[cfg(test)]
mod tests {
    use crate::tests::{get_context, setup_contract};
    use crate::EXECUTION_TIMEOUT;
    use crate::*;
    use near_sdk::test_utils::accounts;
    use near_sdk::{testing_env, NearToken};

    /// Helper to create test ExecutionRequest
    pub(super) fn test_execution_request(request_id: u64, sender: AccountId, timestamp: u64) -> ExecutionRequest {
        test_execution_request_with_data_id(request_id, sender, timestamp, [0; 32])
    }

    pub(super) fn test_execution_request_with_data_id(request_id: u64, sender: AccountId, timestamp: u64, data_id: [u8; 32]) -> ExecutionRequest {
        let code_source = CodeSource::GitHub {
            repo: "https://github.com/test/repo".to_string(),
            commit: "abc123".to_string(),
            build_target: Some("wasm32-wasi".to_string()),
        };
        ExecutionRequest {
            request_id,
            data_id,
            sender_id: sender.clone(),
            execution_source: ExecutionSource::GitHub {
                repo: "https://github.com/test/repo".to_string(),
                commit: "abc123".to_string(),
                build_target: Some("wasm32-wasi".to_string()),
            },
            resolved_source: code_source,
            resource_limits: ResourceLimits::default(),
            payment: 100_000_000_000_000_000_000_000, // 0.1 NEAR
            timestamp,
            secrets_ref: None,
            input_data: None,
            response_format: ResponseFormat::default(),
            payer_account_id: sender,
            pending_output: None,
            output_submitted: false,
            attached_usd: 0,
        }
    }

    fn test_execution_source() -> ExecutionSource {
        ExecutionSource::GitHub {
            repo: "https://github.com/test/repo".to_string(),
            commit: "main".to_string(),
            build_target: Some("wasm32-wasi".to_string()),
        }
    }

    #[test]
    fn test_cancel_stale_execution_success() {
        let mut contract = setup_contract();
        let sender = accounts(3);
        let initial_timestamp = env::block_timestamp();

        // Manually add a pending execution request
        let execution_request = test_execution_request(0, sender.clone(), initial_timestamp);
        contract.pending_requests.insert(&0, &execution_request);
        assert!(contract.get_request(0).is_some());

        // Set up context:
        // - The caller is the original sender
        // - The block timestamp is *after* the timeout period
        let mut context = get_context(sender.clone(), NearToken::from_near(0));
        context.block_timestamp(initial_timestamp + EXECUTION_TIMEOUT + 1);
        testing_env!(context.build());

        // Call the function
        contract.cancel_stale_execution(0);

        // Assert that the request was removed
        assert!(
            contract.get_request(0).is_none(),
            "Stale execution should have been removed"
        );
    }

    /// Cancelling gives back BOTH sides of what the request took.
    ///
    /// Admission debits the caller's stablecoin the moment the request is
    /// created, and a cancelled request earns nobody anything — so a cancel
    /// that returns only the NEAR takes a caller's money for work that never
    /// happened. The tokens do not go anywhere visible when that happens: they
    /// stay on the contract with no balance and no earnings row pointing at
    /// them, which is why this needs a test rather than a reading.
    #[test]
    fn test_cancel_stale_execution_returns_the_stablecoin_too() {
        let mut contract = setup_contract();
        let sender = accounts(3);
        let initial_timestamp = env::block_timestamp();

        let mut execution_request = test_execution_request(0, sender.clone(), initial_timestamp);
        execution_request.attached_usd = 12_000;
        contract.pending_requests.insert(&0, &execution_request);

        // What admission left the caller with, after taking the 12_000.
        contract.user_stablecoin_balances.insert(&sender, &988_000);

        let mut context = get_context(sender.clone(), NearToken::from_near(0));
        context.block_timestamp(initial_timestamp + EXECUTION_TIMEOUT + 1);
        testing_env!(context.build());

        contract.cancel_stale_execution(0);

        assert_eq!(
            contract.user_stablecoin_balances.get(&sender).unwrap(),
            1_000_000,
            "a cancelled execution returns the developer payment as well as the NEAR"
        );
        assert!(contract.get_request(0).is_none());
    }

    /// The same for the operator's cancel: doing it on somebody's behalf must
    /// not cost them the payment for an execution we threw away.
    #[test]
    fn test_emergency_cancel_returns_the_stablecoin_too() {
        let mut contract = setup_contract();
        let owner = accounts(0);
        let sender = accounts(3);

        let mut execution_request = test_execution_request(0, sender.clone(), env::block_timestamp());
        execution_request.attached_usd = 12_000;
        contract.pending_requests.insert(&0, &execution_request);
        contract.user_stablecoin_balances.insert(&sender, &988_000);

        testing_env!(get_context(owner, NearToken::from_near(0)).build());
        contract.emergency_cancel_execution(0);

        assert_eq!(
            contract.user_stablecoin_balances.get(&sender).unwrap(),
            1_000_000,
            "the money goes back to whoever attached it, not to whoever cancelled"
        );
        assert!(contract.get_request(0).is_none());
    }

    #[test]
    #[should_panic(expected = "Only the sender can cancel this execution")]
    fn test_cancel_stale_execution_unauthorized() {
        let mut contract = setup_contract();
        let sender = accounts(3);
        let unauthorized_caller = accounts(4);
        let initial_timestamp = env::block_timestamp();

        // Add a pending execution from `sender`
        let execution_request = test_execution_request(0, sender.clone(), initial_timestamp);
        contract.pending_requests.insert(&0, &execution_request);

        // Set up context:
        // - The caller is *not* the original sender
        // - The time is after the timeout
        let mut context = get_context(unauthorized_caller, NearToken::from_near(0));
        context.block_timestamp(initial_timestamp + EXECUTION_TIMEOUT + 1);
        testing_env!(context.build());

        // Should panic
        contract.cancel_stale_execution(0);
    }

    #[test]
    fn test_response_format_default() {
        let mut contract = setup_contract();
        let source = test_execution_source();

        let context = get_context(accounts(1), NearToken::from_near(1));
        testing_env!(context.build());

        contract.request_execution(source.clone(), None, None, None, None, None, None);

        // Check that response_format defaults to Text
        let request = contract.get_request(0).expect("Request should exist");
        assert_eq!(request.response_format, ResponseFormat::Text);
    }

    #[test]
    fn test_response_format_json() {
        let mut contract = setup_contract();
        let source = test_execution_source();

        let context = get_context(accounts(1), NearToken::from_near(1));
        testing_env!(context.build());

        contract.request_execution(source.clone(), None, None, None, Some(ResponseFormat::Json), None, None);

        // Check that response_format is Json
        let request = contract.get_request(0).expect("Request should exist");
        assert_eq!(request.response_format, ResponseFormat::Json);
    }

    #[test]
    fn test_response_format_bytes() {
        let mut contract = setup_contract();
        let source = test_execution_source();

        let context = get_context(accounts(1), NearToken::from_near(1));
        testing_env!(context.build());

        contract.request_execution(source.clone(), None, None, None, Some(ResponseFormat::Bytes), None, None);

        // Check that response_format is Bytes
        let request = contract.get_request(0).expect("Request should exist");
        assert_eq!(request.response_format, ResponseFormat::Bytes);
    }

    #[test]
    #[should_panic(expected = "Execution is not yet stale, please wait")]
    fn test_cancel_stale_execution_not_stale() {
        let mut contract = setup_contract();
        let sender = accounts(3);
        let initial_timestamp = env::block_timestamp();

        // Add a pending execution
        let execution_request = test_execution_request(0, sender.clone(), initial_timestamp);
        contract.pending_requests.insert(&0, &execution_request);

        // Set up context:
        // - The caller is the original sender
        // - The block timestamp is *before* the timeout
        let mut context = get_context(sender, NearToken::from_near(0));
        context.block_timestamp(initial_timestamp + EXECUTION_TIMEOUT - 1);
        testing_env!(context.build());

        // Should panic
        contract.cancel_stale_execution(0);
    }

    #[test]
    #[should_panic(expected = "Execution request not found")]
    fn test_cancel_stale_execution_not_found() {
        let mut contract = setup_contract();

        let context = get_context(accounts(3), NearToken::from_near(0));
        testing_env!(context.build());

        // Try to cancel non-existent request
        contract.cancel_stale_execution(999);
    }

    #[test]
    fn test_calculate_cost() {
        let contract = setup_contract();

        let metrics = ResourceMetrics {
            instructions: 10_000_000, // 10M instructions
            time_ms: 5000,            // 5000 ms (5 seconds)
            compile_time_ms: None,    // No compilation
        };

        let cost = contract.calculate_cost(&metrics);

        // Expected:
        // base_fee: 10_000_000_000_000_000_000_000
        // instruction_cost: 10 * 1_000_000_000_000_000 = 10_000_000_000_000_000
        // time_cost: 5000 * 1_000_000_000_000_000_000 = 5_000_000_000_000_000_000_000
        // Total: 1_500_010_000_000_000_000_000

        assert_eq!(cost, 1_500_001_000_000_000_000_000);
    }

    #[test]
    fn test_calculate_cost_with_compilation() {
        let contract = setup_contract();

        let metrics = ResourceMetrics {
            instructions: 10_000_000, // 10M instructions
            time_ms: 5000,            // 5000 ms (5 seconds) execution
            compile_time_ms: Some(3000), // 3000 ms (3 seconds) compilation
        };

        let cost = contract.calculate_cost(&metrics);

        assert_eq!(cost, 1_800_001_000_000_000_000_000);
    }

    #[test]
    fn test_calculate_cost_zero_resources() {
        let contract = setup_contract();

        let metrics = ResourceMetrics {
            instructions: 0,
            time_ms: 0,
            compile_time_ms: None,
        };

        let cost = contract.calculate_cost(&metrics);

        // Should only charge base_fee
        assert_eq!(cost, 1_000_000_000_000_000_000_000); // 0.001 NEAR
    }

    #[test]
    fn test_calculate_cost_only_compilation() {
        let contract = setup_contract();

        let metrics = ResourceMetrics {
            instructions: 0,
            time_ms: 0,
            compile_time_ms: Some(10000), // 10 seconds compilation
        };

        let cost = contract.calculate_cost(&metrics);

        assert_eq!(cost, 2000_000_000_000_000_000_000); // 0.0002 NEAR
    }

    #[test]
    #[should_panic(expected = "Contract is paused")]
    fn test_request_execution_when_paused() {
        let mut contract = setup_contract();

        // Owner pauses contract
        let context = get_context(accounts(0), NearToken::from_near(0));
        testing_env!(context.build());
        contract.set_paused(true);

        // User tries to request execution
        let context = get_context(accounts(2), NearToken::from_millinear(100));
        testing_env!(context.build());

        let source = test_execution_source();
        contract.request_execution(source, None, None, None, None, None, None);
    }

    #[test]
    #[should_panic(expected = "Insufficient payment")]
    fn test_request_execution_insufficient_payment() {
        let mut contract = setup_contract();

        // User tries with insufficient deposit
        let context = get_context(accounts(2), NearToken::from_yoctonear(1000));
        testing_env!(context.build());

        let source = test_execution_source();
        contract.request_execution(source, None, None, None, None, None, None);
    }

    #[test]
    fn test_submit_execution_output() {
        let mut contract = setup_contract();
        let operator = accounts(1);
        let sender = accounts(3);

        // Manually create a pending request
        let execution_request = test_execution_request_with_data_id(0, sender.clone(), env::block_timestamp(), [1; 32]);
        contract.pending_requests.insert(&0, &execution_request);

        // Operator submits large output
        let context = get_context(operator.clone(), NearToken::from_near(0));
        testing_env!(context.build());

        let large_output = ExecutionOutput::Text("A".repeat(2000)); // > 1024 bytes
        contract.submit_execution_output(0, large_output.clone());

        // Check that output was stored
        assert!(contract.has_pending_output(0));
        let stored_output = contract.get_pending_output(0).expect("Output should be stored");

        match (stored_output, large_output) {
            (ExecutionOutput::Text(stored), ExecutionOutput::Text(original)) => {
                assert_eq!(stored, original);
            }
            _ => panic!("Output type mismatch"),
        }
    }

    #[test]
    #[should_panic(expected = "Only operator can call this")]
    fn test_submit_execution_output_unauthorized() {
        let mut contract = setup_contract();
        let unauthorized = accounts(5);
        let sender = accounts(3);

        // Create a pending request
        let execution_request = test_execution_request_with_data_id(0, sender.clone(), env::block_timestamp(), [1; 32]);
        contract.pending_requests.insert(&0, &execution_request);

        // Unauthorized user tries to submit output
        let context = get_context(unauthorized, NearToken::from_near(0));
        testing_env!(context.build());

        contract.submit_execution_output(0, ExecutionOutput::Text("test".to_string()));
    }

    #[test]
    #[should_panic(expected = "Output already submitted for this request")]
    fn test_submit_execution_output_twice() {
        let mut contract = setup_contract();
        let operator = accounts(1);
        let sender = accounts(3);

        // Create a pending request with output already submitted
        let code_source = CodeSource::GitHub {
            repo: "https://github.com/test/repo".to_string(),
            commit: "abc123".to_string(),
            build_target: Some("wasm32-wasi".to_string()),
        };
        let execution_request = ExecutionRequest {
            request_id: 0,
            data_id: [1; 32],
            sender_id: sender.clone(),
            execution_source: ExecutionSource::GitHub {
                repo: "https://github.com/test/repo".to_string(),
                commit: "abc123".to_string(),
                build_target: Some("wasm32-wasi".to_string()),
            },
            resolved_source: code_source,
            resource_limits: ResourceLimits::default(),
            payment: 100_000_000_000_000_000_000_000,
            timestamp: env::block_timestamp(),
            secrets_ref: None,
            input_data: None,
            response_format: ResponseFormat::Text,
            payer_account_id: sender.clone(),
            pending_output: Some(StoredOutput::Text("old".as_bytes().to_vec())),
            output_submitted: true,
            attached_usd: 0,
        };
        contract.pending_requests.insert(&0, &execution_request);

        // Operator tries to submit again
        let context = get_context(operator, NearToken::from_near(0));
        testing_env!(context.build());

        contract.submit_execution_output(0, ExecutionOutput::Text("new".to_string()));
    }

    #[test]
    fn test_resolve_execution_with_pending_output() {
        let mut contract = setup_contract();
        let operator = accounts(1);
        let sender = accounts(3);

        // Create a pending request with submitted output
        let large_text = "B".repeat(2000);
        let code_source = CodeSource::GitHub {
            repo: "https://github.com/test/repo".to_string(),
            commit: "abc123".to_string(),
            build_target: Some("wasm32-wasi".to_string()),
        };
        let execution_request = ExecutionRequest {
            request_id: 0,
            data_id: [1; 32],
            sender_id: sender.clone(),
            execution_source: ExecutionSource::GitHub {
                repo: "https://github.com/test/repo".to_string(),
                commit: "abc123".to_string(),
                build_target: Some("wasm32-wasi".to_string()),
            },
            resolved_source: code_source,
            resource_limits: ResourceLimits::default(),
            payment: 100_000_000_000_000_000_000_000,
            timestamp: env::block_timestamp(),
            secrets_ref: None,
            input_data: None,
            response_format: ResponseFormat::Text,
            payer_account_id: sender.clone(),
            pending_output: Some(StoredOutput::Text(large_text.as_bytes().to_vec())),
            output_submitted: true,
            attached_usd: 0,
        };
        contract.pending_requests.insert(&0, &execution_request);

        // Operator resolves with metadata only (no output in response)
        let context = get_context(operator, NearToken::from_near(0));
        testing_env!(context.build());

        let _response = ExecutionResponse {
            success: true,
            output: None, // Output will be taken from pending_output
            error: None,
            resources_used: ResourceMetrics {
                instructions: 1_000_000,
                time_ms: 100,
                compile_time_ms: None,
            },
            compilation_note: None,
            refund_usd: None,
        };

        // This would normally call promise_yield_resume, which we can't test directly
        // But we can verify the request state before the call
        let request = contract.get_request(0).expect("Request should exist");
        assert!(request.output_submitted);
        assert!(request.pending_output.is_some());
    }

    #[test]
    fn test_stored_output_conversion_text() {
        let text = "Hello, NEAR!";
        let output = ExecutionOutput::Text(text.to_string());
        let stored: StoredOutput = output.clone().into();
        let converted: ExecutionOutput = stored.into();

        match converted {
            ExecutionOutput::Text(t) => assert_eq!(t, text),
            _ => panic!("Wrong type"),
        }
    }

    #[test]
    fn test_stored_output_conversion_bytes() {
        let bytes = vec![1, 2, 3, 4, 5];
        let output = ExecutionOutput::Bytes(bytes.clone());
        let stored: StoredOutput = output.into();
        let converted: ExecutionOutput = stored.into();

        match converted {
            ExecutionOutput::Bytes(b) => assert_eq!(b, bytes),
            _ => panic!("Wrong type"),
        }
    }

    #[test]
    fn test_stored_output_conversion_json() {
        let json_value = serde_json::json!({"key": "value", "number": 42});
        let output = ExecutionOutput::Json(json_value.clone());
        let stored: StoredOutput = output.into();
        let converted: ExecutionOutput = stored.into();

        match converted {
            ExecutionOutput::Json(j) => assert_eq!(j, json_value),
            _ => panic!("Wrong type"),
        }
    }

    #[test]
    fn test_submit_execution_output_and_resolve_stores_output() {
        let mut contract = setup_contract();
        let operator = accounts(1);
        let sender = accounts(3);

        // Create a pending request
        let execution_request = test_execution_request_with_data_id(0, sender.clone(), env::block_timestamp(), [1; 32]);
        contract.pending_requests.insert(&0, &execution_request);

        // Operator calls the internal method (we can't test full flow with promise_yield_resume in unit tests)
        let context = get_context(operator.clone(), NearToken::from_near(0));
        testing_env!(context.build());

        let large_output = ExecutionOutput::Text("C".repeat(2000)); // > 1024 bytes

        // Test just the storage part (not the full promise_yield_resume)
        contract.submit_execution_output_internal(0, large_output.clone());

        // Verify that output was stored correctly
        let request = contract.get_request(0).expect("Request should exist");
        assert!(request.output_submitted, "output_submitted flag should be true");
        assert!(request.pending_output.is_some(), "pending_output should be stored");

        // Verify stored output matches
        let stored = contract.get_pending_output(0).expect("Output should be stored");
        match (stored, large_output) {
            (ExecutionOutput::Text(s), ExecutionOutput::Text(o)) => assert_eq!(s, o),
            _ => panic!("Output type mismatch"),
        }
    }

    #[test]
    #[should_panic(expected = "Only operator can call this")]
    fn test_submit_execution_output_and_resolve_unauthorized() {
        let mut contract = setup_contract();
        let unauthorized = accounts(5);
        let sender = accounts(3);

        // Create a pending request
        let execution_request = test_execution_request_with_data_id(0, sender.clone(), env::block_timestamp(), [1; 32]);
        contract.pending_requests.insert(&0, &execution_request);

        // Unauthorized user tries to call combined method
        let context = get_context(unauthorized, NearToken::from_near(0));
        testing_env!(context.build());

        contract.submit_execution_output_and_resolve(
            0,
            ExecutionOutput::Text("test".to_string()),
            true,
            None,
            ResourceMetrics {
                instructions: 1000,
                time_ms: 10,
                compile_time_ms: None,
            },
            None, // compilation_note
        );
    }
}

/// A large `input_data` is paid for while it is held, the settlement callback
/// is given gas for it, a stale cancel keeps the base fee and stops once the
/// output has been delivered, and the callback's answer to the calling
/// contract is built from the stored bytes without a value tree.
#[cfg(test)]
mod input_storage_and_callback_tests {
    use super::tests::*;
    use crate::tests::{get_context, setup_contract};
    use crate::*;
    use near_sdk::mock::MockAction;
    use near_sdk::test_utils::{accounts, get_created_receipts};
    use near_sdk::{testing_env, NearToken};

    fn transfers() -> Vec<(AccountId, u128)> {
        get_created_receipts()
            .into_iter()
            .flat_map(|r| {
                let to = r.receiver_id.clone();
                r.actions.into_iter().filter_map(move |a| match a {
                    MockAction::Transfer { deposit, .. } => Some((to.clone(), deposit.as_yoctonear())),
                    _ => None,
                })
            })
            .collect()
    }

    fn source() -> ExecutionSource {
        ExecutionSource::GitHub {
            repo: "github.com/test/repo".to_string(),
            commit: "main".to_string(),
            build_target: None,
        }
    }

    fn request_with(c: &mut Contract, deposit: u128, input: Option<String>) {
        testing_env!(get_context(accounts(1), NearToken::from_yoctonear(deposit)).build());
        c.request_execution(source(), Some(ResourceLimits::default()), input, None, None, None, None);
    }

    /// Up to the free allowance the deposit is the compute estimate, as it
    /// always was; the view says the same.
    #[test]
    fn a_small_input_costs_the_compute_estimate_only() {
        let mut c = setup_contract();
        let estimate = c.estimate_execution_cost(None, None).0;
        assert_eq!(c.estimate_execution_cost(None, Some(INPUT_DATA_FREE_BYTES as u64)).0, estimate);
        request_with(&mut c, estimate, Some("x".repeat(INPUT_DATA_FREE_BYTES)));
        assert!(c.get_request(0).is_some());
    }

    #[test]
    #[should_panic(expected = "Insufficient payment")]
    fn a_large_input_is_refused_at_the_compute_estimate() {
        let mut c = setup_contract();
        let estimate = c.estimate_execution_cost(None, None).0;
        request_with(&mut c, estimate, Some("x".repeat(INPUT_DATA_FREE_BYTES + 1)));
    }

    /// Beyond the allowance every byte is held at the storage price, the view
    /// quotes exactly that, and the cancel gives it back less the base fee.
    #[test]
    fn a_large_input_is_held_at_the_storage_price_and_returned() {
        let mut c = setup_contract();
        let len = INPUT_DATA_FREE_BYTES + 8_000;
        let estimate = c.estimate_execution_cost(None, None).0;
        let quoted = c.estimate_execution_cost(None, Some(len as u64)).0;
        assert_eq!(quoted, estimate + 8_000 * STORAGE_PRICE_PER_BYTE);
        assert_eq!(quoted, estimate + input_storage_deposit(len));

        request_with(&mut c, quoted, Some("x".repeat(len)));
        let request = c.get_request(0).expect("admitted at the quote");
        assert_eq!(request.payment, quoted);

        let mut ctx = get_context(accounts(1), NearToken::from_yoctonear(0));
        ctx.block_timestamp(request.timestamp + EXECUTION_TIMEOUT + 1);
        testing_env!(ctx.build());
        c.cancel_stale_execution(0);
        assert_eq!(
            transfers(),
            vec![(accounts(1), quoted - c.base_fee)],
            "everything above the base fee, the storage part included, comes back"
        );
        assert_eq!(c.total_fees_collected, c.base_fee);
    }

    /// The callback is created with gas for the bytes it will remove — above
    /// the free allowance. Within it, a request reserves exactly the minimum,
    /// so no existing caller's gas arithmetic moves.
    #[test]
    fn the_callback_gas_grows_with_the_input_above_the_free_allowance() {
        assert_eq!(response_gas(0), MIN_RESPONSE_GAS);
        assert_eq!(response_gas(INPUT_DATA_FREE_BYTES), MIN_RESPONSE_GAS);
        assert_eq!(
            response_gas(INPUT_DATA_FREE_BYTES + 1),
            MIN_RESPONSE_GAS.saturating_add(Gas::from_gas(CALLBACK_GAS_PER_INPUT_BYTE))
        );
        assert_eq!(
            response_gas(INPUT_DATA_FREE_BYTES + (1 << 20)),
            MIN_RESPONSE_GAS.saturating_add(Gas::from_gas((1u64 << 20) * CALLBACK_GAS_PER_INPUT_BYTE))
        );
        // Two megabytes still leave room for the admission call itself inside
        // one transaction's 300 TGas.
        assert!(response_gas(2 << 20).as_tgas() < 110);
    }

    /// A stale cancel keeps the base fee, like every other end without a
    /// result, and returns the whole of the stablecoin.
    #[test]
    fn a_stale_cancel_keeps_the_base_fee() {
        let mut c = setup_contract();
        let sender = accounts(3);
        let t0 = env::block_timestamp();
        let mut request = test_execution_request(0, sender.clone(), t0);
        request.attached_usd = 12_000;
        c.pending_requests.insert(&0, &request);
        c.user_stablecoin_balances.insert(&sender, &988_000);

        let mut ctx = get_context(sender.clone(), NearToken::from_near(0));
        ctx.block_timestamp(t0 + EXECUTION_TIMEOUT + 1);
        testing_env!(ctx.build());
        c.cancel_stale_execution(0);

        assert_eq!(transfers(), vec![(sender.clone(), request.payment - c.base_fee)]);
        assert_eq!(c.total_fees_collected, c.base_fee);
        assert_eq!(c.user_stablecoin_balances.get(&sender).unwrap(), 1_000_000);
    }

    /// Once the worker has put the output in state the run happened: a
    /// cancel still works — the sender's own way out — but keeps the compute
    /// estimate, so the output is paid for and the rest comes back.
    #[test]
    fn a_delivered_request_is_cancelled_at_the_compute_estimate() {
        let mut c = setup_contract();
        let sender = accounts(3);
        let t0 = env::block_timestamp();
        let mut request = test_execution_request(0, sender.clone(), t0);
        request.output_submitted = true;
        request.pending_output = Some(StoredOutput::Text(b"done".to_vec()));
        request.attached_usd = 5_000;
        c.pending_requests.insert(&0, &request);
        c.user_stablecoin_balances.insert(&sender, &0);
        let estimate = c.estimate_cost(&request.resource_limits);
        assert!(estimate > c.base_fee && estimate < request.payment, "a meaningful middle");

        let mut ctx = get_context(sender.clone(), NearToken::from_near(0));
        ctx.block_timestamp(t0 + EXECUTION_TIMEOUT + 1);
        testing_env!(ctx.build());
        c.cancel_stale_execution(0);

        assert_eq!(transfers(), vec![(sender.clone(), request.payment - estimate)]);
        assert_eq!(c.total_fees_collected, estimate);
        assert_eq!(c.user_stablecoin_balances.get(&sender).unwrap(), 5_000, "the stablecoin comes back whole");
        assert!(c.get_request(0).is_none());
    }

    /// Compile time is not in the estimate, so a run's cost can exceed the
    /// compute deposit; it must never reach into the storage part, which is
    /// held, not offered.
    #[test]
    fn compile_time_cannot_eat_the_storage_deposit() {
        let mut c = setup_contract();
        let len = INPUT_DATA_FREE_BYTES + 8_000;
        let storage_part = input_storage_deposit(len);
        let quoted = c.estimate_execution_cost(None, Some(len as u64)).0;
        request_with(&mut c, quoted, Some("x".repeat(len)));
        let request = c.get_request(0).expect("admitted");

        testing_env!(get_context(accounts(0), NearToken::from_near(0)).build());
        c.on_execution_response(
            0,
            request.sender_id.clone(),
            request.resolved_source.clone(),
            request.resource_limits.clone(),
            U128(request.payment),
            Ok(ExecutionResponse {
                success: true,
                output: Some(ExecutionOutput::Text("ok".to_string())),
                error: None,
                // A compile that alone would cost far more than the deposit.
                resources_used: ResourceMetrics { instructions: 0, time_ms: 0, compile_time_ms: Some(10_000_000) },
                compilation_note: None,
                refund_usd: None,
            }),
        );

        assert_eq!(
            transfers(),
            vec![(accounts(1), storage_part)],
            "the storage part comes back whole; the compute deposit is what the run could burn"
        );
        assert_eq!(c.total_fees_collected, quoted - storage_part);
    }

    /// The bytes handed to the calling contract are what serialising the value
    /// tree gave, for every kind of output — pinned here because the callback
    /// no longer builds that tree.
    #[test]
    fn the_returned_bytes_equal_the_value_tree_form() {
        let tree = |v: serde_json::Value| serde_json::to_vec(&v).unwrap();

        let json = serde_json::json!({"ok": true, "items": [1, 2.5, "x"], "nested": {"a": null}});
        let stored: StoredOutput = ExecutionOutput::Json(json.clone()).into();
        assert_eq!(crate::execution::output_return_bytes(Some(&stored)), tree(json));

        let text = "line one\nline \"two\" — ünïcödé";
        let stored: StoredOutput = ExecutionOutput::Text(text.to_string()).into();
        assert_eq!(
            crate::execution::output_return_bytes(Some(&stored)),
            tree(serde_json::Value::String(text.to_string()))
        );

        let bytes = vec![0u8, 1, 2, 255, 254];
        let stored: StoredOutput = ExecutionOutput::Bytes(bytes.clone()).into();
        use near_sdk::base64::{engine::general_purpose::STANDARD, Engine};
        assert_eq!(
            crate::execution::output_return_bytes(Some(&stored)),
            tree(serde_json::Value::String(STANDARD.encode(&bytes)))
        );

        assert_eq!(crate::execution::output_return_bytes(None), b"null");
        assert_eq!(crate::execution::output_return_bytes(Some(&StoredOutput::Json(vec![]))), b"null");
        assert_eq!(
            crate::execution::output_return_bytes(Some(&StoredOutput::Text(vec![0xff, 0xfe]))),
            tree(serde_json::Value::String("[invalid UTF-8]".to_string()))
        );
    }
}
