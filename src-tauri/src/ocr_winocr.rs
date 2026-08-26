// Windows on-device text recognition — Windows.Media.Ocr.OcrEngine. The analog of the macOS Vision
// path: the recognition model is part of the OS (installed as a language pack), so nothing is added
// to the installer and no image leaves the device.
//
// RUNTIME-VERIFIED on a real Windows 11 host: this WinRT chain (TryCreateFromUserProfileLanguages →
// BitmapDecoder → SoftwareBitmap → RecognizeAsync → Lines, with the `en` language pack) read back
// 8/8 sensitive needles off a clean render — including an AWS key and an SSN — with one minor l→1
// substitution class on dense monospace secrets. The project's dev machine is still macOS, so
// `cargo check` here only compiles it; the runtime proof came from the Win11 validation run.
use windows::Graphics::Imaging::{BitmapAlphaMode, BitmapDecoder, BitmapPixelFormat, SoftwareBitmap};
use windows::Media::Ocr::OcrEngine;
use windows::Storage::Streams::{DataWriter, InMemoryRandomAccessStream};

// Capability probe: does this machine have an OCR language pack usable by the current user profile?
// No decoding, no recognition, no network. A stock install with no pack for any profile language
// reports unavailable, and the caller then treats this device as having no native engine.
pub fn engine() -> Option<&'static str> {
    if OcrEngine::TryCreateFromUserProfileLanguages().is_ok() {
        Some("windows-ocr")
    } else {
        None
    }
}

fn stream_from_bytes(bytes: &[u8]) -> windows::core::Result<InMemoryRandomAccessStream> {
    let stream = InMemoryRandomAccessStream::new()?;
    let writer = DataWriter::CreateDataWriter(&stream)?;
    writer.WriteBytes(bytes)?;
    writer.StoreAsync()?.get()?;
    writer.FlushAsync()?.get()?;
    // Detach so dropping the writer does not close the stream we still need.
    writer.DetachStream()?;
    stream.Seek(0)?;
    Ok(stream)
}

fn decode(bytes: &[u8]) -> windows::core::Result<SoftwareBitmap> {
    let stream = stream_from_bytes(bytes)?;
    let decoder = BitmapDecoder::CreateAsync(&stream)?.get()?;
    // Straight-alpha bitmaps can be rejected by RecognizeAsync; convert up front.
    decoder
        .GetSoftwareBitmapConvertedAsync(BitmapPixelFormat::Bgra8, BitmapAlphaMode::Premultiplied)?
        .get()
}

// Lines are joined with a newline rather than a space (OcrResult::Text() space-joins): several of
// the detectors this feeds are line-anchored, so the layout is load-bearing.
pub fn recognize(bytes: &[u8]) -> Result<String, String> {
    let engine = OcrEngine::TryCreateFromUserProfileLanguages()
        .map_err(|e| format!("no Windows OCR engine available (no language pack?): {e}"))?;
    let bitmap = decode(bytes).map_err(|e| format!("image decode failed: {e}"))?;
    let result = engine
        .RecognizeAsync(&bitmap)
        .map_err(|e| format!("OCR dispatch failed: {e}"))?
        .get()
        .map_err(|e| format!("OCR failed: {e}"))?;
    let lines = result.Lines().map_err(|e| format!("OCR result had no lines: {e}"))?;
    let mut out: Vec<String> = vec![];
    for line in lines {
        out.push(line.Text().map_err(|e| format!("OCR line text failed: {e}"))?.to_string());
    }
    Ok(out.join("\n"))
}
