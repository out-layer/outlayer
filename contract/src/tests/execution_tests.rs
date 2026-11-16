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

    /// The bulk cancel returns the stablecoin as the single one does.
    #[test]
    fn test_cancel_pending_requests_returns_the_stablecoin_too() {
        let mut contract = setup_contract();
        let owner = accounts(0);
        let sender = accounts(3);

        for id in 0..2u64 {
            let mut r = test_execution_request(id, sender.clone(), env::block_timestamp());
            r.attached_usd = 12_000;
            contract.pending_requests.insert(&id, &r);
        }
        contract.user_stablecoin_balances.insert(&sender, &976_000);

        testing_env!(get_context(owner, NearToken::from_near(0)).build());
        assert_eq!(contract.cancel_pending_requests(vec![0, 1, 7]), 2);

        assert_eq!(contract.user_stablecoin_balances.get(&sender).unwrap(), 1_000_000);
        assert!(contract.get_request(0).is_none() && contract.get_request(1).is_none());
    }

    fn with_pending(ids: &[u64], next_request_id: u64) -> Contract {
        let mut contract = setup_contract();
        for &id in ids {
            contract.pending_requests.insert(&id, &test_execution_request(id, accounts(3), 0));
        }
        contract.next_request_id = next_request_id;
        contract
    }

    #[test]
    fn pending_ids_come_newest_first_and_page_by_limit() {
        let contract = with_pending(&[2, 5, 9], 10);
        let page = contract.get_pending_request_ids(None, Some(2));
        assert_eq!(page.ids, vec![9, 5]);
        assert_eq!(page.next_from_id, Some(4));
        let page = contract.get_pending_request_ids(page.next_from_id, Some(2));
        assert_eq!(page.ids, vec![2]);
        assert_eq!(page.next_from_id, None, "id 0 was looked at");
    }

    #[test]
    fn one_call_looks_at_one_window_of_ids_however_many_there_are() {
        let newest = 3 * crate::views::PENDING_SCAN_WINDOW;
        let contract = with_pending(&[newest - 1, 7], newest);
        testing_env!(get_context(accounts(1), NearToken::from_near(0)).build());
        let page = contract.get_pending_request_ids(None, None);
        println!("one window of {} ids: {:?}", crate::views::PENDING_SCAN_WINDOW, env::used_gas());
        assert_eq!(page.ids, vec![newest - 1]);
        assert_eq!(page.next_from_id, Some(newest - 1 - crate::views::PENDING_SCAN_WINDOW));

        let mut from = page.next_from_id;
        let mut found = Vec::new();
        while let Some(f) = from {
            // A fresh call each page, as an RPC view is; each must fit well inside its gas.
            testing_env!(get_context(accounts(1), NearToken::from_near(0)).build());
            let p = contract.get_pending_request_ids(Some(f), None);
            assert!(env::used_gas() < near_sdk::Gas::from_tgas(200), "a page used {:?}", env::used_gas());
            found.extend(p.ids);
            from = p.next_from_id;
        }
        assert_eq!(found, vec![7], "paging reaches the oldest");
    }

    #[test]
    fn no_requests_no_pending_ids() {
        let contract = with_pending(&[], 0);
        let page = contract.get_pending_request_ids(None, None);
        assert!(page.ids.is_empty() && page.next_from_id.is_none());
    }

    #[test]
    #[should_panic(expected = "limit must be at least 1")]
    fn a_zero_limit_is_refused() {
        let contract = with_pending(&[1], 2);
        contract.get_pending_request_ids(None, Some(0));
    }

    #[test]
    #[should_panic(expected = "limit must be at least 1")]
    fn a_zero_limit_clears_nothing() {
        let mut contract = with_pending(&[1], 2);
        testing_env!(get_context(accounts(0), NearToken::from_near(0)).build());
        contract.clear_all_pending_requests(None, Some(0));
    }

    #[test]
    fn a_request_status_carries_sizes_not_bytes_and_staleness_by_block_time() {
        let mut contract = setup_contract();
        let mut r = test_execution_request(4, accounts(3), 1_000);
        r.input_data = Some("i".repeat(300));
        r.pending_output = Some(StoredOutput::Text(vec![b'o'; 2_000]));
        r.output_submitted = true;
        contract.pending_requests.insert(&4, &r);

        let mut ctx = get_context(accounts(1), NearToken::from_near(0));
        ctx.block_timestamp(1_000 + EXECUTION_TIMEOUT);
        testing_env!(ctx.build());
        let s = contract.get_request_status(4).unwrap();
        assert_eq!((s.input_bytes, s.output_bytes, s.output_submitted, s.stale), (300, 2_000, true, false));
        assert_eq!(s.payer_account_id, accounts(3));

        let mut ctx = get_context(accounts(1), NearToken::from_near(0));
        ctx.block_timestamp(1_000 + EXECUTION_TIMEOUT + 1);
        testing_env!(ctx.build());
        assert!(contract.get_request_status(4).unwrap().stale);
        assert!(contract.get_request_status(5).is_none());
    }

    #[test]
    fn the_owner_clears_the_newest_window() {
        let mut contract = with_pending(&[1, 3, 4], 5);
        testing_env!(get_context(accounts(0), NearToken::from_near(0)).build());
        assert_eq!(contract.clear_all_pending_requests(None, Some(2)), 2);
        assert!(contract.get_request(4).is_none() && contract.get_request(3).is_none());
        assert!(contract.get_request(1).is_some());
    }

    #[test]
    #[should_panic(expected = "Execution is not yet stale")]
    fn a_stranger_cannot_cancel_before_the_timeout() {
        let mut contract = setup_contract();
        let sender = accounts(3);
        let initial_timestamp = env::block_timestamp();
        let execution_request = test_execution_request(0, sender, initial_timestamp);
        contract.pending_requests.insert(&0, &execution_request);

        let mut context = get_context(accounts(4), NearToken::from_near(0));
        context.block_timestamp(initial_timestamp + EXECUTION_TIMEOUT);
        testing_env!(context.build());
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
        contract.submit_execution_output_internal(0, StoredOutput::from(large_output.clone()));

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
        let estimate = c.estimate_execution_cost(None, None, None).0;
        assert_eq!(c.estimate_execution_cost(None, Some(INPUT_DATA_FREE_BYTES as u64), None).0, estimate);
        request_with(&mut c, estimate, Some("x".repeat(INPUT_DATA_FREE_BYTES)));
        assert!(c.get_request(0).is_some());
    }

    #[test]
    #[should_panic(expected = "Insufficient payment")]
    fn a_large_input_is_refused_at_the_compute_estimate() {
        let mut c = setup_contract();
        let estimate = c.estimate_execution_cost(None, None, None).0;
        request_with(&mut c, estimate, Some("x".repeat(INPUT_DATA_FREE_BYTES + 1)));
    }

    /// Beyond the allowance every byte is held at the storage price, the view
    /// quotes exactly that, and the cancel gives it back less the base fee.
    #[test]
    fn a_large_input_is_held_at_the_storage_price_and_returned() {
        let mut c = setup_contract();
        let len = INPUT_DATA_FREE_BYTES + 8_000;
        let estimate = c.estimate_execution_cost(None, None, None).0;
        let quoted = c.estimate_execution_cost(None, Some(len as u64), None).0;
        assert_eq!(quoted, estimate + 8_000 * STORAGE_PRICE_PER_BYTE);
        assert_eq!(quoted, estimate + input_storage_deposit(len));

        request_with(&mut c, quoted, Some("x".repeat(len)));
        let request = c.get_request(0).expect("admitted at the quote");
        assert_eq!(request.payment, quoted);

        let mut ctx = get_context(accounts(1), NearToken::from_yoctonear(0));
        ctx.block_timestamp(request.timestamp + EXECUTION_TIMEOUT + 1).block_height(STALE_AFTER_BLOCKS + 1);
        testing_env!(ctx.build());
        c.cancel_stale_execution(0);
        assert_eq!(
            transfers(),
            vec![(accounts(1), quoted - c.base_fee)],
            "everything above the base fee, the storage part included, comes back"
        );
        assert_eq!(c.total_fees_collected, c.base_fee);
    }

    /// Past the timeout anyone removes a request; the money goes where it would
    /// for the sender's own cancel: the NEAR to the payer, nothing to the caller.
    #[test]
    fn a_stranger_cancels_a_stale_request_and_the_payer_is_refunded() {
        let mut c = setup_contract();
        let estimate = c.estimate_execution_cost(None, None, None).0;
        request_with(&mut c, estimate * 2, None);
        let request = c.get_request(0).unwrap();

        let mut ctx = get_context(accounts(4), NearToken::from_yoctonear(0));
        ctx.block_timestamp(request.timestamp + EXECUTION_TIMEOUT + 1).block_height(STALE_AFTER_BLOCKS + 1);
        testing_env!(ctx.build());
        c.cancel_stale_execution(0);
        assert!(c.get_request(0).is_none());
        assert_eq!(transfers(), vec![(accounts(1), estimate * 2 - c.base_fee)]);
    }

    /// A price raised while the request waited takes from the compute part
    /// only: the storage part of a large input comes back whole.
    #[test]
    fn a_stale_cancel_returns_the_storage_part_after_a_price_raise() {
        let mut c = setup_contract();
        let len = INPUT_DATA_FREE_BYTES + 8_000;
        let quoted = c.estimate_execution_cost(None, Some(len as u64), None).0;
        request_with(&mut c, quoted, Some("x".repeat(len)));
        let request = c.get_request(0).unwrap();
        let storage = input_storage_deposit(len);

        c.base_fee = quoted * 1_000;
        let mut ctx = get_context(accounts(1), NearToken::from_yoctonear(0));
        ctx.block_timestamp(request.timestamp + EXECUTION_TIMEOUT + 1).block_height(STALE_AFTER_BLOCKS + 1);
        testing_env!(ctx.build());
        c.cancel_stale_execution(0);
        assert_eq!(transfers(), vec![(accounts(1), storage)]);
        assert_eq!(c.total_fees_collected, quoted - storage);
    }

    /// Every stored byte of output needs its storage in the payment, above the
    /// run's cost; what is attached beyond the estimate makes the room.
    #[test]
    fn every_stored_output_byte_needs_its_storage_in_the_payment() {
        let mut c = setup_contract();
        let estimate = c.estimate_execution_cost(None, None, None).0;
        let room = 2_000u128 * STORAGE_PRICE_PER_BYTE;
        request_with(&mut c, estimate + room, None);
        let cost = c.estimate_cost(&ResourceLimits::default());
        assert!(c.output_refusal(0, 2_000, cost).is_none());
        let reason = c
            .output_refusal(0, 2_001, cost)
            .expect("one byte more than the payment holds");
        assert!(reason.starts_with("output_storage_unpaid: "), "{}", reason);
        assert!(reason.contains(&(2_001u128 * STORAGE_PRICE_PER_BYTE).to_string()), "{}", reason);
        assert!(reason.len() < 300, "the reason travels in the 1024-byte yield payload: {}", reason.len());
    }

    /// An output above the stored maximum is refused whatever is attached.
    #[test]
    fn an_output_above_the_stored_maximum_is_refused() {
        let mut c = setup_contract();
        request_with(&mut c, 100 * 10u128.pow(24), None);
        let cost = c.estimate_cost(&ResourceLimits::default());
        assert!(c.output_refusal(0, MAX_STORED_OUTPUT_BYTES, cost).is_none());
        let reason = c.output_refusal(0, MAX_STORED_OUTPUT_BYTES + 1, cost).unwrap();
        assert!(reason.starts_with("output_too_large: "), "{}", reason);
    }

    /// The estimate with the output's length is what makes room for it.
    #[test]
    fn the_estimate_with_the_output_length_holds_that_output() {
        let mut c = setup_contract();
        let len = 40_000;
        let quoted = c.estimate_execution_cost(None, None, Some(len as u64)).0;
        assert_eq!(quoted, c.estimate_execution_cost(None, None, None).0 + 40_000 * STORAGE_PRICE_PER_BYTE);
        request_with(&mut c, quoted, None);
        let cost = c.estimate_cost(&ResourceLimits::default());
        assert!(c.output_refusal(0, len, cost).is_none());
        assert!(c.output_refusal(0, len + 1, cost).is_some());
    }

    /// The separate submit refuses outright what it cannot hold.
    #[test]
    #[should_panic(expected = "output_storage_unpaid: ")]
    fn the_separate_submit_refuses_an_output_the_payment_cannot_hold() {
        let mut c = setup_contract();
        let estimate = c.estimate_execution_cost(None, None, None).0;
        request_with(&mut c, estimate, None);
        let operator = c.get_config().1;
        testing_env!(get_context(operator, NearToken::from_near(0)).build());
        c.submit_execution_output(0, ExecutionOutput::Text("x".repeat(2_000)));
    }

    /// A stored output's deposit comes back whole on a stale cancel, after a
    /// price raise too.
    #[test]
    fn a_stale_cancel_returns_the_output_deposit() {
        let mut c = setup_contract();
        let len = 40_000;
        let quoted = c.estimate_execution_cost(None, None, Some(len as u64)).0;
        request_with(&mut c, quoted, None);
        let mut r = c.pending_requests.get(&0).unwrap();
        r.pending_output = Some(StoredOutput::Text(vec![b'x'; len]));
        r.output_submitted = true;
        c.pending_requests.insert(&0, &r);
        let held = output_storage_deposit(len);

        c.base_fee = quoted * 1_000;
        c.per_million_instructions_fee = quoted;
        let mut ctx = get_context(accounts(4), NearToken::from_yoctonear(0));
        ctx.block_timestamp(r.timestamp + EXECUTION_TIMEOUT + 1).block_height(STALE_AFTER_BLOCKS + 1);
        testing_env!(ctx.build());
        c.cancel_stale_execution(0);
        assert_eq!(transfers(), vec![(accounts(1), held)]);
        assert_eq!(c.total_fees_collected, quoted - held);
    }

    /// One call cancels the stale requests among many, skipping the live and
    /// the gone; the money goes as for one cancel.
    #[test]
    fn a_batch_cancels_the_stale_and_skips_the_rest() {
        let mut c = setup_contract();
        let estimate = c.estimate_execution_cost(None, None, None).0;
        for _ in 0..3 {
            request_with(&mut c, estimate * 2, None);
        }
        request_meta().insert(&2, &RequestMeta { admitted_height: 1, held_bytes: 0 });

        let mut ctx = get_context(accounts(4), NearToken::from_yoctonear(0));
        ctx.block_height(STALE_AFTER_BLOCKS + 1);
        testing_env!(ctx.build());
        assert_eq!(c.cancel_stale_executions(vec![0, 1, 2, 9]), 2);
        assert!(c.get_request(0).is_none() && c.get_request(1).is_none());
        assert!(c.get_request(2).is_some(), "not yet stale: skipped");
        let paid = transfers();
        assert_eq!(paid.len(), 2);
        assert!(paid.iter().all(|(to, amount)| *to == accounts(1) && *amount == estimate * 2 - c.base_fee));
        println!("batch of 2 small stale requests: {:?}", env::used_gas());
    }

    #[test]
    #[should_panic(expected = "At most 100 requests per call")]
    fn a_batch_is_bounded() {
        let mut c = setup_contract();
        c.cancel_stale_executions((0..101).collect());
    }

    fn request_at(c: &mut Contract, who: AccountId, deposit: u128, input: Option<String>, now: u64, gas_tgas: u64) {
        let mut ctx = get_context(who, NearToken::from_yoctonear(deposit));
        ctx.block_timestamp(now).block_height(now).prepaid_gas(near_sdk::Gas::from_tgas(gas_tgas));
        testing_env!(ctx.build());
        c.request_execution(source(), Some(ResourceLimits::default()), input, None, None, None, None);
    }

    /// A new request first removes the stuck ones before it: the spam is
    /// cleaned by whoever comes next, inside the same call, the money of each
    /// going to its own payer.
    #[test]
    fn a_new_request_sweeps_the_stale_ones_before_it() {
        let mut c = setup_contract();
        let estimate = c.estimate_execution_cost(None, None, None).0;
        for _ in 0..3 {
            request_at(&mut c, accounts(1), estimate * 2, None, 1_000, 300);
        }
        request_at(&mut c, accounts(2), estimate, None, 1_000 + STALE_AFTER_BLOCKS + 1, 300);
        assert!(c.get_request(0).is_none() && c.get_request(1).is_none(), "two per call");
        assert!(c.get_request(2).is_some(), "the third waits for the next call");
        assert!(c.get_request(3).is_some(), "the new request is stored");
        let refunds: Vec<_> = transfers().into_iter().filter(|(to, _)| *to == accounts(1)).collect();
        assert_eq!(refunds.len(), 2);

        request_at(&mut c, accounts(2), estimate, None, 1_000 + STALE_AFTER_BLOCKS + 2, 300);
        assert!(c.get_request(2).is_none(), "the next call takes the rest");
    }

    /// The sweep stops at the first live request: everything after it is newer.
    #[test]
    fn the_sweep_stops_at_a_live_request() {
        let mut c = setup_contract();
        let estimate = c.estimate_execution_cost(None, None, None).0;
        request_at(&mut c, accounts(1), estimate, None, 1_000, 300);
        request_at(&mut c, accounts(1), estimate, None, 1_000 + STALE_AFTER_BLOCKS, 300);
        request_at(&mut c, accounts(2), estimate, None, 1_000 + STALE_AFTER_BLOCKS + 1, 300);
        assert!(c.get_request(0).is_none());
        assert!(c.get_request(1).is_some(), "live: not touched");
    }

    /// A stale request holding more than the sweep's bound is passed, not
    /// settled: its removal would cost the next caller too much gas.
    #[test]
    fn the_sweep_passes_a_large_stuck_request() {
        let mut c = setup_contract();
        let len = SWEEP_MAX_HELD_BYTES + 1;
        let quoted = c.estimate_execution_cost(None, Some(len as u64), None).0;
        let estimate = c.estimate_execution_cost(None, None, None).0;
        request_at(&mut c, accounts(1), quoted, Some("x".repeat(len)), 1_000, 300);
        request_at(&mut c, accounts(1), estimate, None, 1_000, 300);
        request_at(&mut c, accounts(2), estimate, None, 1_000 + STALE_AFTER_BLOCKS + 1, 300);
        assert!(c.get_request(0).is_some(), "large: left to cancel_stale_executions");
        assert!(c.get_request(1).is_none(), "the small one behind it is settled");
    }

    #[test]
    #[should_panic(expected = "at most 1572864 (what one transaction can carry)")]
    fn an_input_larger_than_a_transaction_is_refused() {
        let mut c = setup_contract();
        let len = MAX_INPUT_DATA_BYTES + 1;
        let quoted = c.estimate_execution_cost(None, Some(len as u64), None).0;
        request_with(&mut c, quoted, Some("x".repeat(len)));
    }

    /// Staleness counts blocks from admission, not seconds: a request is
    /// live however long the blocks take, until 400 blocks have passed.
    #[test]
    fn a_request_goes_stale_by_blocks_not_by_time() {
        let mut c = setup_contract();
        let estimate = c.estimate_execution_cost(None, None, None).0;
        request_at(&mut c, accounts(1), estimate, None, 1_000, 300);
        let late = 1_000 + EXECUTION_TIMEOUT * 10;
        let mut ctx = get_context(accounts(4), NearToken::from_yoctonear(0));
        ctx.block_timestamp(late).block_height(1_000 + STALE_AFTER_BLOCKS);
        testing_env!(ctx.build());
        assert!(!c.get_request_status(0).unwrap().stale, "slow blocks: still live");
        let mut ctx = get_context(accounts(4), NearToken::from_yoctonear(0));
        ctx.block_timestamp(1_001).block_height(1_000 + STALE_AFTER_BLOCKS + 1);
        testing_env!(ctx.build());
        assert!(c.get_request_status(0).unwrap().stale, "400 blocks: stale");
    }

    /// The meta counts what the request holds, the stored output included,
    /// and the sweep drops the meta of a request settled elsewhere.
    #[test]
    fn the_meta_holds_the_bytes_and_goes_with_the_request() {
        let mut c = setup_contract();
        let len = 4_000;
        let quoted = c.estimate_execution_cost(None, Some(300), Some(len as u64)).0;
        request_at(&mut c, accounts(1), quoted, Some("i".repeat(300)), 1_000, 300);
        assert_eq!(request_meta().get(&0).unwrap().held_bytes, 300);
        c.submit_execution_output_internal(0, StoredOutput::Text(vec![b'o'; len]));
        assert_eq!(request_meta().get(&0).unwrap().held_bytes, 300 + len as u64);

        c.pending_requests.remove(&0); // settled by its callback
        c.sweep_stale();
        assert!(request_meta().get(&0).is_none(), "the cursor took its meta");
    }

    /// A caller without gas to spare is not made to clean anything.
    #[test]
    fn no_sweep_without_gas_to_spare() {
        let mut c = setup_contract();
        let estimate = c.estimate_execution_cost(None, None, None).0;
        request_at(&mut c, accounts(1), estimate, None, 1_000, 300);
        request_at(&mut c, accounts(2), estimate, None, 1_000 + STALE_AFTER_BLOCKS + 1, 80);
        assert!(c.get_request(0).is_some());
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
        let quoted = c.estimate_execution_cost(None, Some(len as u64), None).0;
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

    fn settle_with(c: &mut Contract, request_id: u64, response: Result<ExecutionResponse, PromiseError>) {
        let request = c.get_request(request_id).expect("pending");
        testing_env!(get_context(accounts(0), NearToken::from_near(0)).build());
        c.on_execution_response(
            request_id,
            request.sender_id.clone(),
            request.resolved_source.clone(),
            request.resource_limits.clone(),
            U128(request.payment),
            response,
        );
    }

    fn failed(resources: ResourceMetrics) -> Result<ExecutionResponse, PromiseError> {
        Ok(ExecutionResponse {
            success: false,
            output: None,
            error: Some("trap".to_string()),
            resources_used: resources,
            compilation_note: None,
            refund_usd: None,
        })
    }

    /// A failed run pays for what it burned, by the same formula as a success.
    #[test]
    fn a_failed_run_is_charged_what_it_burned() {
        let mut c = setup_contract();
        let quoted = c.estimate_execution_cost(None, None, None).0;
        request_with(&mut c, quoted, Some("{}".to_string()));
        let burned = ResourceMetrics { instructions: 500_000_000, time_ms: 20_000, compile_time_ms: None };
        let expected = c.calculate_cost(&burned);
        assert!(expected > c.base_fee && expected < quoted, "a meaningful middle: {expected}");

        settle_with(&mut c, 0, failed(burned));
        assert_eq!(transfers(), vec![(accounts(1), quoted - expected)]);
        assert_eq!(c.total_fees_collected, expected);
    }

    /// A failure before the guest ran arrives with nothing burned and costs
    /// the base fee, as it always did.
    #[test]
    fn a_platform_failure_costs_the_base_fee() {
        let mut c = setup_contract();
        let quoted = c.estimate_execution_cost(None, None, None).0;
        request_with(&mut c, quoted, Some("{}".to_string()));
        settle_with(&mut c, 0, failed(ResourceMetrics { instructions: 0, time_ms: 0, compile_time_ms: None }));
        assert_eq!(transfers(), vec![(accounts(1), quoted - c.base_fee)]);
        assert_eq!(c.total_fees_collected, c.base_fee);
    }

    /// A failed run that burned past its budget — the penalty case, the
    /// whole limit reported — pays the compute deposit and no more; the
    /// storage part comes back.
    #[test]
    fn a_failed_run_never_pays_past_the_compute_deposit() {
        let mut c = setup_contract();
        let len = INPUT_DATA_FREE_BYTES + 8_000;
        let storage_part = input_storage_deposit(len);
        let quoted = c.estimate_execution_cost(None, Some(len as u64), None).0;
        request_with(&mut c, quoted, Some("x".repeat(len)));
        settle_with(&mut c, 0, failed(ResourceMetrics { instructions: u64::MAX / 4, time_ms: u64::MAX / 4, compile_time_ms: Some(u64::MAX / 4) }));
        assert_eq!(transfers(), vec![(accounts(1), storage_part)]);
        assert_eq!(c.total_fees_collected, quoted - storage_part);
    }

    /// A run the yield window outlived costs the base fee: the window runs
    /// out on our side as often as on the caller's, and the two cannot be
    /// told apart here. The storage part and the stablecoin come back whole.
    #[test]
    fn a_timed_out_run_costs_the_base_fee() {
        let mut c = setup_contract();
        let len = INPUT_DATA_FREE_BYTES + 8_000;
        let quoted = c.estimate_execution_cost(None, Some(len as u64), None).0;
        request_with(&mut c, quoted, Some("x".repeat(len)));
        c.user_stablecoin_balances.insert(&accounts(1), &0);
        let mut request = c.get_request(0).unwrap();
        request.attached_usd = 7_000;
        c.pending_requests.insert(&0, &request);

        settle_with(&mut c, 0, Err(PromiseError::Failed));
        assert_eq!(transfers(), vec![(accounts(1), quoted - c.base_fee)]);
        assert_eq!(c.total_fees_collected, c.base_fee);
        assert_eq!(c.user_stablecoin_balances.get(&accounts(1)).unwrap(), 7_000);
    }

    /// A base fee raised after the request was made is never credited past what the request
    /// paid: the fees counter bounds the owner's NEAR withdrawal.
    #[test]
    fn a_timed_out_run_never_credits_more_than_was_paid() {
        let mut c = setup_contract();
        let quoted = c.estimate_execution_cost(None, None, None).0;
        request_with(&mut c, quoted, Some("{}".to_string()));
        c.base_fee = quoted * 1_000;

        settle_with(&mut c, 0, Err(PromiseError::Failed));
        assert_eq!(c.total_fees_collected, quoted, "kept the payment, not the new base fee");
        assert!(transfers().is_empty(), "nothing left to refund");
    }

    #[test]
    #[should_panic(expected = "exceeds hard limit of 4096 MB")]
    fn memory_above_the_cap_is_refused() {
        let mut c = setup_contract();
        let quoted = c.estimate_execution_cost(None, None, None).0;
        testing_env!(get_context(accounts(1), NearToken::from_yoctonear(quoted)).build());
        let limits = ResourceLimits { max_memory_mb: Some(MAX_MEMORY_MB + 1), ..Default::default() };
        c.request_execution(source(), Some(limits), None, None, None, None, None);
    }

    #[test]
    fn memory_at_the_cap_is_admitted() {
        let mut c = setup_contract();
        let quoted = c.estimate_execution_cost(None, None, None).0;
        testing_env!(get_context(accounts(1), NearToken::from_yoctonear(quoted)).build());
        let limits = ResourceLimits { max_memory_mb: Some(MAX_MEMORY_MB), ..Default::default() };
        c.request_execution(source(), Some(limits), None, None, None, None, None);
        assert!(c.get_request(0).is_some());
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
