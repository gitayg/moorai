// Linux on-device text recognition — Tesseract via the leptess binding (system libtesseract +
// libleptonica). Linux ships no OS text-recognition engine, so unlike the macOS Vision and Windows
// OCR tiers this is an opportunistic, second-class tier: the recognition happens locally and no
// image or recovered text ever leaves the device, but quality and coverage are below the OS engines.
// The engine and its `eng` model come from the package dependency (tesseract-ocr / tesseract-ocr-eng
// declared in tauri.conf.json), not from a bundle baked into the app binary.
use leptess::{LepTess, Variable};

// Capability probe: can libtesseract initialise with the English model on this host? Constructing an
// engine is the honest check — it fails when eng.traineddata is missing — and a failure makes this
// device report no native engine, so the caller falls through to the same skip/provider ordering as
// any engine-less platform. No image, no recognition, no network here.
pub fn engine() -> Option<&'static str> {
    if LepTess::new(None, "eng").is_ok() {
        Some("linux-tesseract")
    } else {
        None
    }
}

pub fn recognize(bytes: &[u8]) -> Result<String, String> {
    let mut lt = LepTess::new(None, "eng")
        .map_err(|e| format!("no Tesseract engine available (no eng traineddata?): {e}"))?;
    // The counterpart of Vision's setUsesLanguageCorrection(false): disabling the word dictionaries
    // stops Tesseract "correcting" secrets and identifiers into dictionary words, which is exactly
    // the content this feature exists to recover verbatim.
    lt.set_variable(Variable::LoadSystemDawg, "0")
        .map_err(|e| format!("failed to disable Tesseract system dictionary: {e}"))?;
    lt.set_variable(Variable::LoadFreqDawg, "0")
        .map_err(|e| format!("failed to disable Tesseract frequent-word dictionary: {e}"))?;
    lt.set_image_from_mem(bytes).map_err(|e| format!("image decode failed: {e}"))?;
    let text = lt.get_utf8_text().map_err(|e| format!("OCR failed: {e}"))?;
    // Newline-joined lines, matching the macOS/Windows tiers: several detectors this feeds are
    // line-anchored, so the layout is load-bearing. `lines()` also drops Tesseract's trailing
    // newline/form-feed and normalises CRLF.
    Ok(text.lines().collect::<Vec<&str>>().join("\n"))
}
