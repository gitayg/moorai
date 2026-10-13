//! Pins the wire format against test/fixtures/guardd/golden.json, the fixture the hook client
//! (test/guardd-client.test.mjs) and the console (RAISEME-server test/device-keys.test.js) check too.
//! Contract: docs/proposals/guardd-contract.md §11.1.

use moorai_guardd::alerts::AlertBatch;
use moorai_guardd::beat::Beat;
use moorai_guardd::canonical::{canonical_json, parse_canonical, sha256_hex, unhex};
use moorai_guardd::console::RegisterBody;
use moorai_guardd::ipc::frame::{encode, Decoder};
use moorai_guardd::ipc::{RequestFrame, ResponseFrame};
use moorai_guardd::keys::{device_id_of_machine_id, verify_b64, DeviceKey};
use moorai_guardd::signing::{command_input, devreq_signing_input, hello_proof_input, rotate_input, CommandFields, DevReq};
use serde_json::Value;

const FIXTURE: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../test/fixtures/guardd/golden.json"));
/// Same constant in test/guardd-client.test.mjs and RAISEME-server/test/device-keys.test.js.
const FIXTURE_SHA256: &str = "6371d6615f0b9d40bd48b1923b0fd2a5a8e16c7a0baca6bb82b2fa8f737589b6";

fn g() -> Value {
    serde_json::from_slice(FIXTURE).unwrap()
}
fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("fixture field {k}"))
}

#[test]
fn fixture_is_the_pinned_one() {
    assert_eq!(sha256_hex(FIXTURE), FIXTURE_SHA256);
}

#[test]
fn canonical_json_cases() {
    for c in g()["canonical"].as_array().unwrap() {
        assert_eq!(canonical_json(&c["value"]).unwrap(), s(c, "canonical"));
        assert!(parse_canonical(s(c, "canonical").as_bytes()).is_ok());
    }
}

#[test]
fn device_key_and_id_from_the_test_seed() {
    let g = g();
    let k = &g["keys"];
    let dev = DeviceKey::from_seed(&unhex(s(k, "deviceSeedHex")).unwrap()).unwrap();
    assert_eq!(dev.public_spki_b64(), s(k, "devicePublicKeySpkiB64"));
    assert_eq!(dev.key_id(), s(k, "deviceKeyId"));
    let con = DeviceKey::from_seed(&unhex(s(k, "consoleSeedHex")).unwrap()).unwrap();
    assert_eq!(con.public_spki_b64(), s(k, "consolePublicKeySpkiB64"));
    assert_eq!(con.key_id(), s(k, "consoleKeyId"));
    let machine = s(&g, "deviceIdInput").strip_prefix("moorai-device|v1|").unwrap();
    assert_eq!(device_id_of_machine_id(machine), s(&g, "deviceId"));
}

#[test]
fn every_frame_round_trips_through_the_typed_messages_byte_for_byte() {
    let g = g();
    for f in g["frames"].as_array().unwrap() {
        let name = s(f, "name");
        let bytes = unhex(s(f, "frameHex")).unwrap();
        let mut d = Decoder::new();
        d.push(&bytes);
        let v = d.next_value().unwrap().expect("one complete frame");
        assert_eq!(v, f["message"], "{name}: decoded value");
        let re = if name.ends_with("-request") {
            let m: RequestFrame = serde_json::from_value(v).unwrap_or_else(|e| panic!("{name}: {e}"));
            encode(&m).unwrap()
        } else {
            let m: ResponseFrame = serde_json::from_value(v).unwrap_or_else(|e| panic!("{name}: {e}"));
            encode(&m).unwrap()
        };
        assert_eq!(re, bytes, "{name}: re-encoded frame");
    }
}

#[test]
fn decoder_refuses_bad_frames() {
    let mut d = Decoder::new();
    d.push(&[0, 0, 0, 0]);
    assert!(d.next_value().is_err(), "empty frame");
    let mut d = Decoder::new();
    d.push(&(2 * 1024 * 1024u32).to_be_bytes());
    assert!(d.next_value().is_err(), "oversized length refused before buffering");
    let mut d = Decoder::new();
    let p = br#"{"v":1, "id":1}"#;
    d.push(&(p.len() as u32).to_be_bytes());
    d.push(p);
    assert!(d.next_value().is_err(), "non-canonical payload");
    let mut d = Decoder::new();
    d.push(&[0, 0]);
    assert_eq!(d.next_value().unwrap(), None, "partial header");
}

fn check_devreq(case: &Value, body_bytes: Vec<u8>, dev: &DeviceKey) {
    assert_eq!(String::from_utf8(body_bytes.clone()).unwrap(), s(case, "bodyCanonical"));
    assert_eq!(sha256_hex(&body_bytes), s(case, "bodySha256"));
    let input = devreq_signing_input(&DevReq {
        method: s(case, "method"),
        path: s(case, "path"),
        tenant: s(case, "tenant"),
        device_id: s(case, "deviceId"),
        key_id: s(case, "keyId"),
        ts: s(case, "ts"),
        nonce: s(case, "nonce"),
        body: &body_bytes,
    });
    assert_eq!(input, s(case, "signingInput"));
    assert_eq!(dev.sign_b64(input.as_bytes()), s(case, "signatureB64"));
    assert!(verify_b64(&dev.public_spki_b64(), input.as_bytes(), s(case, "signatureB64")).is_ok());
    assert!(verify_b64(&dev.public_spki_b64(), format!("{input}x").as_bytes(), s(case, "signatureB64")).is_err());
}

fn device_key(g: &Value) -> DeviceKey {
    DeviceKey::from_seed(&unhex(s(&g["keys"], "deviceSeedHex")).unwrap()).unwrap()
}

#[test]
fn signed_beat() {
    let g = g();
    let beat: Beat = serde_json::from_value(g["beat"]["body"].clone()).unwrap();
    check_devreq(&g["beat"], beat.body_bytes().unwrap(), &device_key(&g));
}

#[test]
fn signed_alert_batch() {
    let g = g();
    let batch: AlertBatch = serde_json::from_value(g["alertBatch"]["body"].clone()).unwrap();
    check_devreq(&g["alertBatch"], batch.body_bytes().unwrap(), &device_key(&g));
}

#[test]
fn signed_registration_and_rotation() {
    let g = g();
    let r = &g["register"];
    let body: RegisterBody = serde_json::from_value(r["body"].clone()).unwrap();
    let bytes = canonical_json(&serde_json::to_value(&body).unwrap()).unwrap().into_bytes();
    check_devreq(r, bytes, &device_key(&g));
    let k = &g["keys"];
    let rot = rotate_input(s(r, "tenant"), s(r, "deviceId"), s(k, "consoleKeyId"), s(k, "deviceKeyId"));
    assert_eq!(rot, s(r, "rotateInput"));
    assert!(verify_b64(s(k, "consolePublicKeySpkiB64"), rot.as_bytes(), s(r, "rotateSignatureB64ByConsoleSeedAsOldKey")).is_ok());
}

#[test]
fn signed_commands_poll_has_an_empty_body() {
    let g = g();
    assert!(g["commandsPoll"]["body"].is_null());
    check_devreq(&g["commandsPoll"], Vec::new(), &device_key(&g));
}

#[test]
fn hello_proof() {
    let g = g();
    let h = &g["helloProof"];
    let input = hello_proof_input(s(h, "nonce"), s(h, "keyId"), s(h, "helperVersion"));
    assert_eq!(input, s(h, "input"));
    assert_eq!(device_key(&g).sign_b64(input.as_bytes()), s(h, "signatureB64"));
    // The hello-response frame carries the same proof.
    let hello = g["frames"].as_array().unwrap().iter().find(|f| f["name"] == "hello-response").unwrap();
    assert_eq!(hello["message"]["proof"], h["signatureB64"]);
}

#[test]
fn console_command_signature() {
    let g = g();
    let c = &g["command"];
    let fields: CommandFields = serde_json::from_value(c["fields"].clone()).unwrap();
    let input = command_input(&fields);
    assert_eq!(input, s(c, "input"));
    assert!(verify_b64(s(&g["keys"], "consolePublicKeySpkiB64"), input.as_bytes(), s(c, "signatureB64")).is_ok());
}
