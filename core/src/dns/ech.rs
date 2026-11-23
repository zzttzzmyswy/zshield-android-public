//! SvcParam rewriting for HTTPS (type 65) and SVCB (type 64) answers.
//!
//! # Why this exists
//!
//! Encrypted Client Hello moves the real SNI *inside* an encrypted blob, leaving only a decoy
//! `outer_name` on the wire. A client that learns an ECHConfig through DNS can therefore hide the
//! hostname from every SNI-based rule — including ours. Removing the `ech` SvcParam (key 5) from the
//! DNS answer makes the client fall back to a plaintext ClientHello, so the name we need is visible
//! again.
//!
//! The same mechanism removes `ipv6hint` (key 6) when the network underneath the tunnel has no
//! IPv6: a client that reads an IPv6 hint out of the HTTPS record connects to that address family
//! first, and a tunnel with no IPv6 route drops the connection instead of letting the client fall
//! back to IPv4 (MYS-2710).
//!
//! # What is rewritten
//!
//! Only the SvcParams list of a record whose RDATA already holds uncompressed names (see
//! `wire::read_record`, which expands target names while parsing). Rewriting in place would break
//! the record's length and every compression pointer that follows it, so the rewrite is done by
//! re-encoding the message through `wire::build_response` and *then* fixing the SvcParams inside the
//! re-encoded buffer — the buffer is fully uncompressed at that point, so no pointer can be
//! invalidated.
//!
//! The functions below therefore work on a complete, already-built message and return a new one.

use crate::dns::wire::{encode_name, Message, Record, TYPE_HTTPS};

/// `SVCB` record type (RFC 9460).
pub const TYPE_SVCB: u16 = 64;
/// SvcParamKey of `ech` (RFC 9460 §14.3.2; formerly `echconfig`).
pub const SVC_PARAM_ECH: u16 = 5;
/// SvcParamKey of `ipv6hint` (RFC 9460 §7.6).
pub const SVC_PARAM_IPV6HINT: u16 = 6;

/// True when this record type carries SvcParams.
pub fn is_svcb_type(rtype: u16) -> bool {
    rtype == TYPE_SVCB || rtype == TYPE_HTTPS
}

/// Remove the `ech` SvcParam from one record's RDATA.
///
/// Returns `Ok(true)` when something was removed, `Ok(false)` when the record had none, and `Err`
/// when the RDATA does not parse as SVCB/HTTPS — in which case the caller must leave the record
/// untouched rather than risk emitting a broken one.
pub fn strip_ech_from_rdata(rdata: &[u8]) -> Result<(Vec<u8>, bool), String> {
    strip_svc_params_from_rdata(rdata, &[SVC_PARAM_ECH])
}

/// Remove the listed SvcParam keys from one record's RDATA.
///
/// Same contract as [`strip_ech_from_rdata`]: `Err` means the RDATA does not parse, and the caller
/// must keep the original record.
pub fn strip_svc_params_from_rdata(rdata: &[u8], keys: &[u16]) -> Result<(Vec<u8>, bool), String> {
    // SvcPriority(2) + TargetName(uncompressed, as stored by `wire::read_record`)
    if rdata.len() < 3 {
        return Err("rdata too short for SVCB".to_string());
    }
    let target_len = svc_target_length(rdata, 2)?;
    let params_start = 2 + target_len;
    if params_start > rdata.len() {
        return Err("SVCB target name overruns rdata".to_string());
    }
    let mut out = Vec::with_capacity(rdata.len());
    out.extend_from_slice(&rdata[..params_start]);

    let mut cursor = params_start;
    let mut removed = false;
    while cursor < rdata.len() {
        if cursor + 4 > rdata.len() {
            return Err("truncated SvcParam header".to_string());
        }
        let key = u16::from_be_bytes([rdata[cursor], rdata[cursor + 1]]);
        let len = usize::from(u16::from_be_bytes([rdata[cursor + 2], rdata[cursor + 3]]));
        let value_start = cursor + 4;
        let end = value_start
            .checked_add(len)
            .ok_or_else(|| "SvcParam length overflows".to_string())?;
        if end > rdata.len() {
            return Err("truncated SvcParam value".to_string());
        }
        if keys.contains(&key) {
            removed = true;
        } else {
            out.extend_from_slice(&rdata[cursor..end]);
        }
        cursor = end;
    }
    if !removed {
        return Ok((rdata.to_vec(), false));
    }
    Ok((out, true))
}

/// Length of the uncompressed target name starting at `pos` (including the root label).
fn svc_target_length(rdata: &[u8], pos: usize) -> Result<usize, String> {
    let mut cursor = pos;
    loop {
        let Some(&len) = rdata.get(cursor) else {
            return Err("target name overruns rdata".to_string());
        };
        if len == 0 {
            return Ok(cursor + 1 - pos);
        }
        if len & 0xc0 != 0 {
            return Err("compressed name in SVCB target".to_string());
        }
        cursor += 1 + usize::from(len);
        if cursor > rdata.len() {
            return Err("target name overruns rdata".to_string());
        }
    }
}

/// Remove the `ech` SvcParam from every HTTPS/SVCB answer in an already-built DNS message.
///
/// Returns `None` when nothing needed changing (the caller can forward the original bytes), and
/// `Some(new_message)` otherwise. Record lengths and the answer count are re-emitted, so the result
/// parses back into exactly the same message minus the `ech` parameters.
pub fn strip_ech_from_response(response: &[u8]) -> Option<Vec<u8>> {
    strip_svc_params_from_response(response, &[SVC_PARAM_ECH])
}

/// Remove the listed SvcParam keys from every HTTPS/SVCB answer in an already-built DNS message.
///
/// `keys` must be sorted per RFC 9460 §2.2 ordering concerns to stay valid; the accepted sets here
/// are `[ech]`, `[ipv6hint]` and `[ech, ipv6hint]`, and removing parameters never reorders the ones
/// that remain.
pub fn strip_svc_params_from_response(response: &[u8], keys: &[u16]) -> Option<Vec<u8>> {
    let message = Message::parse(response).ok()?;
    let mut changed = false;
    let mut answers = Vec::with_capacity(message.answers.len());
    for record in &message.answers {
        if is_svcb_type(record.rtype) {
            if let Ok((rdata, removed)) = strip_svc_params_from_rdata(&record.rdata, keys) {
                if removed {
                    changed = true;
                    answers.push(Record {
                        rdata,
                        ..record.clone()
                    });
                    continue;
                }
            }
        }
        answers.push(record.clone());
    }
    if !changed {
        return None;
    }
    Some(rebuild(&message, &answers))
}

/// Re-emit a message with a replaced answer section, keeping the id, flags and question intact.
fn rebuild(message: &Message, answers: &[Record]) -> Vec<u8> {
    let mut out = Vec::with_capacity(response_capacity(answers));
    out.extend_from_slice(&message.id.to_be_bytes());
    // Keep every flag bit the upstream set (QR, AA, RD, RA, AD, CD, RCODE...).
    out.extend_from_slice(&message.flags.to_be_bytes());
    out.extend_from_slice(&(message.questions.len() as u16).to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&(message.authorities.len() as u16).to_be_bytes());
    // Additional records (including OPT) are preserved verbatim; they are position-independent
    // because parsing decompressed every name.
    out.extend_from_slice(&(message.additionals.len() as u16).to_be_bytes());

    for question in &message.questions {
        match encode_name(&question.name) {
            Ok(bytes) => out.extend_from_slice(&bytes),
            Err(_) => continue,
        }
        out.extend_from_slice(&question.qtype.to_be_bytes());
        out.extend_from_slice(&question.qclass.to_be_bytes());
    }
    for record in answers.iter().chain(message.authorities.iter()).chain(message.additionals.iter()) {
        match encode_name(&record.name) {
            Ok(bytes) => out.extend_from_slice(&bytes),
            Err(_) => continue,
        }
        out.extend_from_slice(&record.rtype.to_be_bytes());
        out.extend_from_slice(&record.rclass.to_be_bytes());
        out.extend_from_slice(&record.ttl.to_be_bytes());
        let len = record.rdata.len().min(u16::MAX as usize) as u16;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&record.rdata[..len as usize]);
    }
    out
}

fn response_capacity(answers: &[Record]) -> usize {
    64 + answers.iter().map(|record| record.rdata.len() + 32).sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire::{encode_name, CLASS_IN};

    /// Encode one SvcParam.
    fn param(key: u16, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&key.to_be_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        out
    }

    /// Encode an SVCB/HTTPS RDATA: priority, uncompressed target, params.
    fn rdata(priority: u16, target: &str, params: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&priority.to_be_bytes());
        out.extend_from_slice(&encode_name(target).unwrap());
        for param in params {
            out.extend_from_slice(param);
        }
        out
    }

    /// A plausible ECHConfigList: version 0xfe0d + length + opaque body.
    fn ech_value() -> Vec<u8> {
        let mut value = Vec::new();
        value.extend_from_slice(&[0xfe, 0x0d]);
        value.extend_from_slice(&20u16.to_be_bytes());
        value.extend_from_slice(&[0xab; 20]);
        value
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x4242u16.to_be_bytes());
        out.extend_from_slice(&0x8180u16.to_be_bytes()); // QR, RD, RA
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&encode_name(name).unwrap());
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out
    }

    /// Build a response by hand so the test does not depend on `wire::build_response`.
    fn response(name: &str, qtype: u16, answers: &[(u16, Vec<u8>)], ttl: u32) -> Vec<u8> {
        let mut out = query(name, qtype);
        out[6] = 0;
        out[7] = answers.len() as u8;
        for (rtype, body) in answers {
            out.extend_from_slice(&encode_name(name).unwrap());
            out.extend_from_slice(&rtype.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&(body.len() as u16).to_be_bytes());
            out.extend_from_slice(body);
        }
        out
    }

    #[test]
    fn removes_ech_and_keeps_the_other_params() {
        let body = rdata(
            1,
            "",
            &[
                param(1, &[0x02, 0x68, 0x32]),      // alpn=h2
                param(SVC_PARAM_ECH, &ech_value()), // to be removed
                param(3, &[0x00, 0x01, 0xbb]),      // port=443
                param(4, &[1, 2, 3, 4]),            // ipv4hint
            ],
        );
        let message = response("crypto.cloudflare.com", TYPE_HTTPS, &[(TYPE_HTTPS, body.clone())], 300);
        let stripped = strip_ech_from_response(&message).expect("ech must be removed");

        // The result must parse again, and be exactly the original minus the ech parameter.
        let parsed = Message::parse(&stripped).expect("the rewritten message must parse");
        let original = Message::parse(&message).expect("original parses");
        assert_eq!(parsed.id, original.id);
        assert_eq!(parsed.flags, original.flags);
        assert_eq!(parsed.questions, original.questions);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].rtype, TYPE_HTTPS);
        assert_eq!(parsed.answers[0].ttl, 300);

        let (rebuilt, removed) = strip_ech_from_rdata(&parsed.answers[0].rdata).expect("parses");
        assert!(!removed, "the ech parameter must be gone");
        assert_eq!(rebuilt, parsed.answers[0].rdata);

        // Every other parameter survives, in order, with its length field intact.
        let keys = svc_param_keys(&parsed.answers[0].rdata);
        assert_eq!(keys, vec![1, 3, 4]);
        assert_eq!(parsed.answers[0].rdata.len(), body.len() - param(SVC_PARAM_ECH, &ech_value()).len());
    }

    #[test]
    fn keeps_additional_records_and_authorities() {
        // An OPT record in the additional section must survive the rewrite (it carries the EDNS
        // buffer size and DO bit, and dropping it changes how the client behaves).
        let body = rdata(1, "", &[param(SVC_PARAM_ECH, &ech_value())]);
        let mut message = response("example.com", TYPE_HTTPS, &[(TYPE_HTTPS, body)], 60);
        // authority: one NS record
        message[8] = 0;
        message[9] = 1;
        message[10] = 0;
        message[11] = 1;
        message.extend_from_slice(&encode_name("example.com").unwrap());
        message.extend_from_slice(&2u16.to_be_bytes()); // NS
        message.extend_from_slice(&CLASS_IN.to_be_bytes());
        message.extend_from_slice(&60u32.to_be_bytes());
        let ns = encode_name("ns1.example.com").unwrap();
        message.extend_from_slice(&(ns.len() as u16).to_be_bytes());
        message.extend_from_slice(&ns);
        // additional: OPT with an empty body
        message.extend_from_slice(&[0u8]); // root name
        message.extend_from_slice(&41u16.to_be_bytes());
        message.extend_from_slice(&1232u16.to_be_bytes()); // class = UDP payload size
        message.extend_from_slice(&0u32.to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes());

        let stripped = strip_ech_from_response(&message).expect("ech removed");
        let parsed = Message::parse(&stripped).expect("parses");
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.authorities.len(), 1);
        assert_eq!(parsed.additionals.len(), 1);
        assert_eq!(parsed.additionals[0].rtype, 41);
        assert_eq!(parsed.authorities[0].cname_target(), None);
        assert!(strip_ech_from_rdata(&parsed.answers[0].rdata)
            .expect("parses")
            .1
            .eq(&false));
    }

    #[test]
    fn leaves_records_without_ech_alone() {
        let body = rdata(1, "", &[param(1, &[0x02, 0x68, 0x32])]);
        let message = response("example.com", TYPE_HTTPS, &[(TYPE_HTTPS, body)], 60);
        assert!(
            strip_ech_from_response(&message).is_none(),
            "a response with no ech must be forwarded byte for byte"
        );
    }

    #[test]
    fn non_svcb_answers_are_not_touched() {
        let message = response("example.com", 1, &[(1, vec![1, 2, 3, 4])], 60);
        assert!(strip_ech_from_response(&message).is_none());
    }

    #[test]
    fn malformed_svcb_rdata_is_left_alone() {
        // A length field that overruns the record: stripping must fail, and the caller then keeps
        // the original record rather than emitting something broken.
        let mut broken = rdata(1, "", &[]);
        broken.extend_from_slice(&[0x00, 0x01, 0xff, 0xff]); // key 1, len 65535, no value
        assert!(strip_ech_from_rdata(&broken).is_err());

        // A record with ech *after* the broken part still must not produce a truncated message.
        let message = response("example.com", TYPE_HTTPS, &[(TYPE_HTTPS, broken.clone())], 60);
        assert!(strip_ech_from_response(&message).is_none());
    }

    #[test]
    fn target_name_is_skipped_correctly() {
        // A non-root target ("svc.example.com") must be skipped before the params are read.
        let body = rdata(
            1,
            "svc.example.com",
            &[param(SVC_PARAM_ECH, &ech_value()), param(1, &[0x02, 0x68, 0x33])],
        );
        let (stripped, removed) = strip_ech_from_rdata(&body).expect("parses");
        assert!(removed);
        let keys = svc_param_keys(&stripped);
        assert_eq!(keys, vec![1]);
        assert_eq!(&stripped[..2], &[0, 1], "priority is preserved");
    }

    #[test]
    fn empty_response_and_junk_do_not_panic() {
        assert!(strip_ech_from_response(&[]).is_none());
        assert!(strip_ech_from_response(&[0u8; 5]).is_none());
        assert!(strip_ech_from_rdata(&[]).is_err());
        assert!(strip_ech_from_rdata(&[0, 1]).is_err());
    }

    // ---- ipv6hint (MYS-2710) ----

    /// 2001:db8::1, the canonical `ipv6hint` value in the RFC 9460 examples.
    fn ipv6_hint_value() -> Vec<u8> {
        vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]
    }

    #[test]
    fn removes_ipv6hint_and_keeps_the_other_params() {
        let body = rdata(
            1,
            "",
            &[
                param(1, &[0x02, 0x68, 0x32]),            // alpn=h2
                param(3, &[0x00, 0x01, 0xbb]),            // port=443
                param(4, &[1, 2, 3, 4]),                  // ipv4hint
                param(SVC_PARAM_IPV6HINT, &ipv6_hint_value()), // to be removed
            ],
        );
        let message = response("www.baidu.com", TYPE_HTTPS, &[(TYPE_HTTPS, body.clone())], 300);
        let stripped = strip_svc_params_from_response(&message, &[SVC_PARAM_IPV6HINT])
            .expect("ipv6hint must be removed");

        let parsed = Message::parse(&stripped).expect("the rewritten message must parse");
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(svc_param_keys(&parsed.answers[0].rdata), vec![1, 3, 4]);
        assert_eq!(
            parsed.answers[0].rdata.len(),
            body.len() - param(SVC_PARAM_IPV6HINT, &ipv6_hint_value()).len()
        );
        // Removing ipv6hint must not touch ech: the two keys are independent.
        assert!(strip_ech_from_response(&stripped).is_none());
    }

    #[test]
    fn both_keys_can_be_removed_in_one_pass() {
        let body = rdata(
            1,
            "svc.example.com",
            &[
                param(SVC_PARAM_ECH, &ech_value()),
                param(SVC_PARAM_IPV6HINT, &ipv6_hint_value()),
                param(1, &[0x02, 0x68, 0x33]),
            ],
        );
        let message = response("example.com", TYPE_HTTPS, &[(TYPE_HTTPS, body)], 60);
        let stripped =
            strip_svc_params_from_response(&message, &[SVC_PARAM_ECH, SVC_PARAM_IPV6HINT])
                .expect("both must be removed");
        let parsed = Message::parse(&stripped).expect("parses");
        assert_eq!(svc_param_keys(&parsed.answers[0].rdata), vec![1]);
        assert_eq!(&parsed.answers[0].rdata[..2], &[0, 1], "priority preserved");
    }

    #[test]
    fn a_record_without_ipv6hint_is_left_byte_for_byte() {
        // Only ipv4hint: the caller must get `None` so the original upstream bytes are forwarded.
        let body = rdata(1, "", &[param(4, &[1, 2, 3, 4]), param(1, &[0x02, 0x68, 0x32])]);
        let message = response("example.com", TYPE_HTTPS, &[(TYPE_HTTPS, body)], 60);
        assert!(strip_svc_params_from_response(&message, &[SVC_PARAM_IPV6HINT]).is_none());
    }

    #[test]
    fn malformed_rdata_is_not_rewritten_when_stripping_ipv6hint() {
        let mut broken = rdata(1, "", &[]);
        broken.extend_from_slice(&[0x00, 0x06, 0xff, 0xff]); // key 6, len 65535, no value
        assert!(strip_svc_params_from_rdata(&broken, &[SVC_PARAM_IPV6HINT]).is_err());
        let message = response("example.com", TYPE_HTTPS, &[(TYPE_HTTPS, broken)], 60);
        assert!(strip_svc_params_from_response(&message, &[SVC_PARAM_IPV6HINT]).is_none());
    }

    #[test]
    fn svc_param_key_values_match_rfc_9460() {
        // The wire numbers are the whole contract with the client; a typo would silently rewrite
        // the wrong parameter.
        assert_eq!(SVC_PARAM_ECH, 5);
        assert_eq!(SVC_PARAM_IPV6HINT, 6);
    }

    /// Keys of an SVCB RDATA's parameters, for assertions.
    fn svc_param_keys(rdata: &[u8]) -> Vec<u16> {
        let target_len = svc_target_length(rdata, 2).expect("target");
        let mut cursor = 2 + target_len;
        let mut keys = Vec::new();
        while cursor + 4 <= rdata.len() {
            let key = u16::from_be_bytes([rdata[cursor], rdata[cursor + 1]]);
            let len = usize::from(u16::from_be_bytes([rdata[cursor + 2], rdata[cursor + 3]]));
            keys.push(key);
            cursor += 4 + len;
        }
        keys
    }
}
