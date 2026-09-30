// macOS on-device text recognition — Vision.framework (VNRecognizeTextRequest). The recognition
// model ships with the OS, so nothing is bundled into the notarized DMG and no bytes leave the
// device: the image is handed to a local framework and only the recovered text comes back.
use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2::AnyThread;
use objc2_foundation::{NSArray, NSData, NSDictionary};
use objc2_vision::{
    VNImageOption, VNImageRequestHandler, VNRecognizeTextRequest, VNRecognizedText, VNRequest,
    VNRequestTextRecognitionLevel,
};

// Vision is always present on macOS 10.15+, which is below the app's deployment target.
pub fn engine() -> Option<&'static str> {
    Some("macos-vision")
}

fn text_request(level: VNRequestTextRecognitionLevel) -> Retained<VNRecognizeTextRequest> {
    let req = VNRecognizeTextRequest::new();
    req.setRecognitionLevel(level);
    // Language correction "fixes" secrets and identifiers into dictionary words, which is exactly
    // the content this feature exists to recover verbatim.
    req.setUsesLanguageCorrection(false);
    req
}

fn top_lines(req: &VNRecognizeTextRequest) -> Vec<String> {
    let mut lines: Vec<String> = vec![];
    if let Some(results) = req.results() {
        for obs in results.iter() {
            let candidates: Retained<NSArray<VNRecognizedText>> = obs.topCandidates(1);
            if let Some(c) = candidates.iter().next() {
                lines.push(c.string().to_string());
            }
        }
    }
    lines
}

// The accurate pass is the primary reading; the fast pass only contributes lines the accurate pass
// did not already produce, so a line both engines agree on appears once.
fn merge_passes(primary: Vec<String>, secondary: Vec<String>) -> Vec<String> {
    let mut lines = primary;
    for line in secondary {
        if !lines.contains(&line) {
            lines.push(line);
        }
    }
    lines
}

// Two passes over one image, both on-device. On macOS 27 the accurate recognizer reads the 7 in
// AKIAIOSFODNN7EXAMPLE as Z at confidence 1.0 (every revision, with or without language correction
// or customWords); the fast recognizer reads it correctly. Across a 224-secret render corpus the
// union recovered 219 secret shapes vs 212 for accurate alone, for ~20ms of extra warm time.
pub fn recognize(bytes: &[u8]) -> Result<String, String> {
    let data = NSData::with_bytes(bytes);
    let accurate = text_request(VNRequestTextRecognitionLevel::Accurate);
    let fast = text_request(VNRequestTextRecognitionLevel::Fast);
    let options: Retained<NSDictionary<VNImageOption, AnyObject>> = NSDictionary::new();
    let handler =
        VNImageRequestHandler::initWithData_options(VNImageRequestHandler::alloc(), &data, &options);
    let requests: Retained<NSArray<VNRequest>> =
        NSArray::from_slice(&[accurate.as_ref(), fast.as_ref()]);
    handler
        .performRequests_error(&requests)
        .map_err(|e| e.localizedDescription().to_string())?;
    Ok(merge_passes(top_lines(&accurate), top_lines(&fast)).join("\n"))
}

#[cfg(test)]
mod vision_smoke {
    // Runtime proof that the OS engine actually recovers the secret/PII shapes #23 exists to catch,
    // on this host, with no network. `cargo test vision -- --nocapture` prints what Vision returned.
    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/ocr-canary.png");

    #[test]
    fn vision_recovers_the_canary_from_a_real_png() {
        let text = recognize(FIXTURE).expect("Vision failed on the fixture");
        println!("\n===== Vision OCR output =====\n{text}\n=============================");
        for needle in [
            "MOORAI-CANARY-7Q4Z",
            "AKIAIOSFODNN7EXAMPLE",
            "123-45-6789",
            "alice@acme.com",
        ] {
            assert!(text.contains(needle), "Vision did not recover {needle}");
        }
    }

    #[test]
    fn merge_keeps_accurate_order_and_adds_only_new_fast_lines() {
        let accurate = vec!["AKIAIOSFODNNZEXAMPLE".to_string(), "alice@acme.com".to_string()];
        let fast = vec!["AKIAIOSFODNN7EXAMPLE".to_string(), "alice@acme.com".to_string()];
        assert_eq!(
            merge_passes(accurate, fast),
            vec!["AKIAIOSFODNNZEXAMPLE", "alice@acme.com", "AKIAIOSFODNN7EXAMPLE"]
        );
    }
}
