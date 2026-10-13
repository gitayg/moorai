// macOS providers for the clipboard guard. The general pasteboard has no change notification, so the
// runner polls changeCount (an integer, no content) every 500 ms; the frontmost app comes from
// NSWorkspace. Text is read only when clip_guard.rs asks (an unapproved AI app is in front), and only
// when the pasteboard holds plain text and no file: a copied file also carries its name as text, and an
// image carries none. No accessibility API and no event tap is used.
//
// Pasteboard privacy (macOS 15.4 preview, enforced in later releases): a programmatic read of the general
// pasteboard that does not follow the user's paste can show the user an alert, and the user can then
// allow or deny this app in System Settings; accessBehavior reports that choice. changeCount and the
// type list are not reads of the contents.
use objc2_app_kit::{NSPasteboard, NSPasteboardTypeFileURL, NSPasteboardTypeString, NSWorkspace};
use objc2_foundation::NSString;

pub struct MacClipboard;

impl crate::clip_guard::Clipboard for MacClipboard {
    fn change_count(&self) -> i64 {
        NSPasteboard::generalPasteboard().changeCount() as i64
    }

    fn read_text(&self) -> Option<String> {
        let pb = NSPasteboard::generalPasteboard();
        let types = pb.types()?;
        let has = |t: &NSString| types.iter().any(|x| &*x == t);
        // SAFETY: AppKit's pasteboard type constants are immutable NSStrings that live for the process.
        let (string_t, file_t) = unsafe { (NSPasteboardTypeString, NSPasteboardTypeFileURL) };
        if !has(string_t) || has(file_t) { return None; }
        pb.stringForType(string_t).map(|s| s.to_string())
    }

    fn write_text(&self, text: &str) -> bool {
        let pb = NSPasteboard::generalPasteboard();
        pb.clearContents();
        // SAFETY: see read_text.
        pb.setString_forType(&NSString::from_str(text), unsafe { NSPasteboardTypeString })
    }
}

pub struct MacFrontmost;

impl crate::clip_guard::Frontmost for MacFrontmost {
    fn frontmost(&self) -> Option<String> {
        NSWorkspace::sharedWorkspace().frontmostApplication()?.bundleIdentifier().map(|s| s.to_string())
    }
}

// "always" / "never" / "ask" / "default": the user's per-app pasteboard choice, for the status line.
// accessBehavior exists from macOS 15.4; on an older system there is no pasteboard alert at all.
pub fn access_behavior() -> &'static str {
    use objc2::runtime::NSObjectProtocol;
    let pb = NSPasteboard::generalPasteboard();
    if !pb.respondsToSelector(objc2::sel!(accessBehavior)) { return "not-applicable"; }
    match pb.accessBehavior().0 { 1 => "ask", 2 => "always", 3 => "never", _ => "default" }
}

pub fn notify(title: &str, body: &str) {
    // osascript by absolute path; the strings are passed as arguments, never spliced into the script.
    let script = "on run argv\ndisplay notification (item 2 of argv) with title (item 1 of argv)\nend run";
    let _ = std::process::Command::new("/usr/bin/osascript").args(["-e", script, title, body]).spawn().map(|mut c| std::thread::spawn(move || c.wait()));
}
