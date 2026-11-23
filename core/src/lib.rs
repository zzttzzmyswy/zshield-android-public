//! ZShield Rust core.
//!
//! Layering (see `docs/DESIGN.md` §2/§3):
//! - [`config`] — the JSON contract with the Kotlin control plane,
//! - [`compile`] / [`compiled`] — turning filter lists into the serialized artifacts the tunnel
//!   loads at start,
//! - [`dns`] — wire format, filter engine, TTL cache, ECH stripping, request pipeline,
//! - [`http`] — plaintext HTTP request model, adblock decision, keep-alive relay and request log,
//! - [`upstream`] — DoH and plaintext UDP transports,
//! - [`tun`] — the userspace TCP/IP stack (smoltcp), packet parsing, policy, UDP NAT and the
//!   per-connection forwarding tasks,
//! - [`tunnel`] — the event-driven fd loop that ties the stack, the forwarder and the DNS engine
//!   together,
//! - [`jni_api`] — the single JNI entry class `top.zztweb.zshield.core.Native`,
//! - [`rules_identity`] — which rule content a start or swap actually installed, in one parseable
//!   log line (the observation `scripts/effectiveness/pss_idle.sh` binds a sample batch to).
//!
//! Since M2a there is one data path for both tunnel modes: `mode = "dns_only"` is the same stack
//! with a smaller route table, so a policy change cannot behave differently between modes.
//!
//! Since M2b the adblock engine is loaded at start and consulted for every plaintext HTTP request;
//! the TLS side of the same pipeline is M3, which reuses `http::decision` unchanged.

pub mod compile;
pub mod compiled;
pub mod config;
pub mod cosmetic;
pub mod dns;
pub mod http;
pub mod https;
pub mod jni_api;
pub mod mem;
pub mod rules_identity;
pub mod tun;
pub mod tunnel;
pub mod upstream;

/// Log one line to logcat (and stderr off-device).
///
/// The app ships no telemetry and no crash reporting; this only writes to the local log so a user
/// debugging with `adb logcat` can see what the core is doing.
pub fn log_msg(level: &str, message: &str) {
    #[cfg(target_os = "android")]
    {
        use std::ffi::CString;
        extern "C" {
            fn __android_log_write(prio: i32, tag: *const std::ffi::c_char, text: *const std::ffi::c_char) -> i32;
        }
        let prio = match level {
            "error" => 6,
            "warn" => 5,
            "info" => 4,
            "debug" => 3,
            _ => 4,
        };
        if let (Ok(text), Ok(tag)) = (
            CString::new(message.replace('\0', " ")),
            CString::new("ZShieldCore"),
        ) {
            // SAFETY: both pointers are valid NUL-terminated strings for the duration of the call.
            unsafe {
                __android_log_write(prio, tag.as_ptr(), text.as_ptr());
            }
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        eprintln!("[zshield:{level}] {message}");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn logging_does_not_panic() {
        crate::log_msg("info", "hello");
        crate::log_msg("error", "with\0nul");
    }
}
