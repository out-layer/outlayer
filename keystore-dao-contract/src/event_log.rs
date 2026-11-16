//! What a keystore's RTMR3 says about it: the dstack boot event log, replayed.
//!
//! RTMR3 of a dstack CVM is not a build hash. The guest OS extends it at boot with one event per
//! fact — the app id, the hash of the app's compose (image digests and all), the instance id of
//! this very CVM, the key provider (KMS) — so two instances of one release share a compose hash
//! and still differ in RTMR3. The register is opaque without its event log.
//!
//! A registration carries the RTMR3 events. Each event's digest is recomputed from its fields,
//! the digests are replayed into the register, and the result must equal the RTMR3 of the
//! verified TDX quote: only then are the fields facts about the quoted TD. Members vote on a
//! registration knowing WHICH compose runs there and WHICH instance it is, and a compose hash can
//! be rebuilt from the release.
//!
//! Only the events before `system-ready` count. Everything up to that marker is written by the
//! measured guest OS; after it the app itself may extend RTMR3 with events of any name.

use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use schemars::JsonSchema;
use sha2::{Digest, Sha384};

/// The register the dstack guest extends with app events.
const APP_IMR: u32 = 3;
/// The guest OS's last boot event.
const BOOT_END: &str = "system-ready";
/// More events than any boot writes; bounds the work a registration can ask for.
pub const MAX_EVENTS: usize = 64;
/// Bounds one event's payload (the key provider's JSON is the largest, about 150 bytes).
const MAX_PAYLOAD_HEX: usize = 1024;

/// One entry of dstack's event log, as its guest agent prints it. Other fields are ignored.
#[derive(Deserialize, Serialize, JsonSchema, Clone, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct EventLogEntry {
    pub imr: u32,
    pub event_type: u32,
    /// sha384 of the event, hex.
    pub digest: String,
    pub event: String,
    /// Hex.
    pub event_payload: String,
}

/// What the replayed boot events state about the keystore of a registration. All hex, as in the
/// event log.
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, JsonSchema, Clone, Debug, PartialEq)]
#[borsh(crate = "near_sdk::borsh")]
#[serde(crate = "near_sdk::serde")]
pub struct RegistrationFacts {
    /// sha256 of the app's compose: the release. The same for every instance of it.
    pub compose_hash: String,
    pub app_id: String,
    /// This CVM. A redeploy is a new one; a restart keeps it.
    pub instance_id: String,
    /// The key provider (KMS) as the guest recorded it: JSON, hex-encoded.
    pub key_provider: String,
    /// The guest OS image, when the guest records it.
    pub os_image_hash: Option<String>,
}

/// Replay the RTMR3 events of `log` and read the boot facts. `Ok((rtmr3_hex, facts))`; the
/// caller compares `rtmr3_hex` with the quote's.
pub fn replay(log: &[EventLogEntry]) -> Result<(String, RegistrationFacts), String> {
    if log.len() > MAX_EVENTS {
        return Err(format!("event log has {} entries, at most {}", log.len(), MAX_EVENTS));
    }
    let mut mr = [0u8; 48];
    let mut booted = false;
    let (mut compose_hash, mut app_id, mut instance_id, mut key_provider, mut os_image_hash) =
        (None, None, None, None, None);

    for e in log.iter().filter(|e| e.imr == APP_IMR) {
        if e.event_payload.len() > MAX_PAYLOAD_HEX {
            return Err(format!("event '{}': payload too long", e.event));
        }
        // The digest is over `type:name:payload`: a name with a colon would let one digest be
        // read as two different events.
        if e.event.contains(':') || e.event.len() > 64 {
            return Err(format!("event name '{}' is not one dstack writes", e.event));
        }
        let payload = hex::decode(&e.event_payload)
            .map_err(|_| format!("event '{}': payload is not hex", e.event))?;
        let mut h = Sha384::new();
        h.update(e.event_type.to_le_bytes());
        h.update(b":");
        h.update(e.event.as_bytes());
        h.update(b":");
        h.update(&payload);
        let digest = h.finalize();
        if !e.digest.eq_ignore_ascii_case(&hex::encode(digest)) {
            return Err(format!("event '{}': digest does not match its fields", e.event));
        }

        let mut ext = Sha384::new();
        ext.update(mr);
        ext.update(digest);
        mr.copy_from_slice(&ext.finalize());

        if booted {
            continue;
        }
        let slot = match e.event.as_str() {
            BOOT_END => {
                booted = true;
                continue;
            }
            "compose-hash" => &mut compose_hash,
            "app-id" => &mut app_id,
            "instance-id" => &mut instance_id,
            "key-provider" => &mut key_provider,
            "os-image-hash" => &mut os_image_hash,
            _ => continue,
        };
        if slot.is_some() {
            return Err(format!("event '{}' appears twice before {}", e.event, BOOT_END));
        }
        *slot = Some(e.event_payload.to_ascii_lowercase());
    }

    if !booted {
        return Err(format!("event log has no {} event", BOOT_END));
    }
    // Each fact has the size dstack writes it in: a sha256, or the 20 bytes of an id.
    let need = |v: Option<String>, name: &str, hex_len: Option<usize>| {
        let v = v.filter(|s| !s.is_empty()).ok_or_else(|| format!("event log has no {} before {}", name, BOOT_END))?;
        match hex_len {
            Some(n) if v.len() != n => Err(format!("{} is {} hex characters, not {}", name, v.len(), n)),
            _ => Ok(v),
        }
    };
    if let Some(h) = &os_image_hash {
        if h.len() != 64 {
            return Err(format!("os-image-hash is {} hex characters, not 64", h.len()));
        }
    }
    Ok((
        hex::encode(mr),
        RegistrationFacts {
            compose_hash: need(compose_hash, "compose-hash", Some(64))?,
            app_id: need(app_id, "app-id", Some(40))?,
            instance_id: need(instance_id, "instance-id", Some(40))?,
            key_provider: need(key_provider, "key-provider", None)?,
            os_image_hash,
        },
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A dstack event with the digest its fields give.
    pub(crate) fn ev(imr: u32, event: &str, payload_hex: &str) -> EventLogEntry {
        let event_type = 0x0800_0001u32;
        let mut h = Sha384::new();
        h.update(event_type.to_le_bytes());
        h.update(b":");
        h.update(event.as_bytes());
        h.update(b":");
        h.update(hex::decode(payload_hex).unwrap());
        EventLogEntry {
            imr,
            event_type,
            digest: hex::encode(h.finalize()),
            event: event.to_string(),
            event_payload: payload_hex.to_string(),
        }
    }

    /// The boot log of a keystore CVM: `compose` and `instance` vary, the rest is fixed.
    pub(crate) fn boot_log(compose: &str, instance: &str) -> Vec<EventLogEntry> {
        vec![
            ev(0, "firmware", "00"),
            ev(3, "system-preparing", ""),
            ev(3, "app-id", &compose[..40]),
            ev(3, "compose-hash", compose),
            ev(3, "instance-id", instance),
            ev(3, "boot-mr-done", ""),
            ev(3, "mr-kms", &"48".repeat(32)),
            ev(3, "os-image-hash", &"8d".repeat(32)),
            ev(3, "key-provider", "7b226e616d65223a226b6d73227d"),
            ev(3, "storage-fs", "7a6673"),
            ev(3, "system-ready", ""),
        ]
    }

    const COMPOSE: &str = "cfcba6acbf261f883b9f380c49c1401917f5f4e8c46007cf2cb027d1ddb010be";
    const INSTANCE: &str = "cf657a49d37e8cb5902c2d9b6dccb7f1a424e03d";

    /// The digest formula is dstack's: these four are the digests a live testnet keystore
    /// (2026-11-16, this compose and instance) carries in its event log.
    #[test]
    fn digests_are_the_ones_dstack_writes() {
        let log: Vec<EventLogEntry> = boot_log(COMPOSE, INSTANCE).into_iter().filter(|x| x.imr == 3).collect();
        assert!(log[0].digest.starts_with("f9974020ef507068"), "system-preparing");
        assert!(log[1].digest.starts_with("9789e469f4db9392"), "app-id");
        assert!(log[2].digest.starts_with("72f0d52df0deb306"), "compose-hash");
        assert!(log[3].digest.starts_with("faf9e73683ce4bb3"), "instance-id");
        let (_, facts) = replay(&log).unwrap();
        assert_eq!(facts.compose_hash, COMPOSE);
        assert_eq!(facts.app_id, &COMPOSE[..40]);
        assert_eq!(facts.instance_id, INSTANCE);
    }

    #[test]
    fn two_instances_of_one_compose_differ_in_rtmr3_only_by_instance() {
        let (a, fa) = replay(&boot_log(COMPOSE, INSTANCE)).unwrap();
        let (b, fb) = replay(&boot_log(COMPOSE, &"ab".repeat(20))).unwrap();
        assert_ne!(a, b);
        assert_eq!(fa.compose_hash, fb.compose_hash);
        assert_ne!(fa.instance_id, fb.instance_id);
    }

    #[test]
    fn a_changed_field_no_longer_matches_its_digest() {
        let mut log = boot_log(COMPOSE, INSTANCE);
        log[3].event_payload = "00".repeat(32);
        assert!(replay(&log).unwrap_err().contains("digest does not match"));
    }

    #[test]
    fn events_the_app_adds_after_boot_are_replayed_but_state_nothing() {
        let mut log = boot_log(COMPOSE, INSTANCE);
        let (boot_only, _) = replay(&log).unwrap();
        log.push(ev(3, "compose-hash", &"ee".repeat(32)));
        log.push(ev(3, "instance-id", &"ee".repeat(20)));
        let (with_app, facts) = replay(&log).unwrap();
        assert_ne!(boot_only, with_app, "the app's events are in the register");
        assert_eq!(facts.compose_hash, COMPOSE);
        assert_eq!(facts.instance_id, INSTANCE);
    }

    #[test]
    fn a_fact_stated_twice_before_boot_ends_is_refused() {
        let mut log = boot_log(COMPOSE, INSTANCE);
        log.insert(5, ev(3, "compose-hash", &"ee".repeat(32)));
        assert!(replay(&log).unwrap_err().contains("appears twice"));
    }

    #[test]
    fn a_log_without_a_boot_fact_or_the_boot_end_is_refused() {
        let mut no_instance = boot_log(COMPOSE, INSTANCE);
        no_instance.retain(|e| e.event != "instance-id");
        assert!(replay(&no_instance).unwrap_err().contains("no instance-id"));

        let mut no_end = boot_log(COMPOSE, INSTANCE);
        no_end.retain(|e| e.event != "system-ready");
        assert!(replay(&no_end).unwrap_err().contains("no system-ready"));
    }

    #[test]
    fn an_event_name_with_a_colon_is_refused() {
        // `type:a:b` + payload could otherwise be told as event "a" with a payload starting ":b".
        let mut log = boot_log(COMPOSE, INSTANCE);
        log.insert(7, ev(3, "os-image-hash:x", "00"));
        assert!(replay(&log).unwrap_err().contains("not one dstack writes"));
    }

    #[test]
    fn a_fact_of_the_wrong_size_is_refused() {
        let short = boot_log(COMPOSE, &"ab".repeat(19));
        assert!(replay(&short).unwrap_err().contains("instance-id is 38 hex characters"));
        let mut log = boot_log(COMPOSE, INSTANCE);
        let i = log.iter().position(|e| e.event == "os-image-hash").unwrap();
        log[i] = ev(3, "os-image-hash", "8d");
        assert!(replay(&log).unwrap_err().contains("os-image-hash is 2 hex characters"));
    }

    #[test]
    fn other_registers_are_ignored_and_a_long_log_is_refused() {
        let (a, _) = replay(&boot_log(COMPOSE, INSTANCE)).unwrap();
        let mut log = boot_log(COMPOSE, INSTANCE);
        log.push(ev(1, "compose-hash", &"ee".repeat(32)));
        assert_eq!(replay(&log).unwrap().0, a);

        let long: Vec<EventLogEntry> = (0..=MAX_EVENTS).map(|_| ev(0, "x", "")).collect();
        assert!(replay(&long).unwrap_err().contains("at most"));
    }
}
