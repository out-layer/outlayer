//! Payment host functions for WASM components
//!
//! Implements the `near:payment/api` WIT interface.
//! Allows WASI to call refund_usd() to return part of attached amount to caller.

use anyhow::Result;
use std::sync::{Arc, Mutex};
use tracing::debug;
use wasmtime::component::Linker;

// Generate bindings from WIT (payment is separate package near:payment)
// A published interface version never changes a type: a changed signature is
// a new package version, registered next to the old one (wit/README.md).
wasmtime::component::bindgen!({
    path: "wit",
    world: "near:payment/payment-host",
});

/// Shared payment state that can be read after execution
#[derive(Debug, Clone, Default)]
pub struct PaymentState {
    /// Attached USD amount (from env var)
    pub attached_usd: u64,
    /// Amount to refund (set by WASI via refund_usd)
    pub refund_usd: u64,
    /// Whether refund has been called already
    pub refund_called: bool,
}

/// Host state for payment functions
pub struct PaymentHostState {
    state: Arc<Mutex<PaymentState>>,
}

impl PaymentHostState {
    /// Create new payment host state
    pub fn new(attached_usd: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(PaymentState {
                attached_usd,
                refund_usd: 0,
                refund_called: false,
            })),
        }
    }

    /// Get the current refund amount (call after execution completes)
    pub fn get_refund_usd(&self) -> u64 {
        self.state.lock().unwrap().refund_usd
    }

    /// Get shared state reference (for passing to other contexts)
    #[allow(dead_code)]
    pub fn get_state(&self) -> Arc<Mutex<PaymentState>> {
        self.state.clone()
    }
}

impl near::payment::api::Host for PaymentHostState {
    fn refund_usd(&mut self, amount: u64) -> String {
        let mut state = self.state.lock().unwrap();

        debug!(
            "payment::refund_usd amount={}, attached={}, already_called={}",
            amount, state.attached_usd, state.refund_called
        );

        // Check if already called
        if state.refund_called {
            return "refund_usd can only be called once per execution".to_string();
        }

        // Check if amount exceeds attached
        if amount > state.attached_usd {
            return format!(
                "Refund amount {} exceeds attached USD {}",
                amount, state.attached_usd
            );
        }

        // Set refund
        state.refund_usd = amount;
        state.refund_called = true;

        debug!("payment::refund_usd success, refund={}", amount);
        String::new() // Empty string = success
    }
}

/// Add payment host functions to a wasmtime component linker
pub fn add_payment_to_linker<T: Send + 'static>(
    linker: &mut Linker<T>,
    get_state: impl Fn(&mut T) -> &mut PaymentHostState + Send + Sync + Copy + 'static,
) -> Result<()> {
    near::payment::api::add_to_linker(linker, get_state)
}
