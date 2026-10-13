// Windows providers for the clipboard guard. A message-only window registers AddClipboardFormatListener,
// so WM_CLIPBOARDUPDATE wakes the loop when the clipboard changes; a 500 ms timer on the same window
// re-reads the foreground window (GetForegroundWindow -> process image name), which catches an AI app
// coming to the front while sensitive text is already on the clipboard. No WinEvent hook, no keyboard
// hook, no UI Automation. Text is read only when clip_guard.rs asks, only as CF_UNICODETEXT, and never
// when the clipboard holds files (CF_HDROP).
use windows::core::{w, HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HGLOBAL, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::DataExchange::{AddClipboardFormatListener, CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber, IsClipboardFormatAvailable, OpenClipboard, SetClipboardData};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE};
use windows::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};
use windows::Win32::UI::WindowsAndMessaging::{CreateWindowExW, DefWindowProcW, DispatchMessageW, GetForegroundWindow, GetMessageW, GetWindowThreadProcessId, PostMessageW, RegisterClassW, SetTimer, HWND_MESSAGE, MSG, WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_CLIPBOARDUPDATE, WM_TIMER, WNDCLASSW};

const CF_UNICODETEXT: u32 = 13;
const CF_HDROP: u32 = 15;
const WM_WAKE: u32 = WM_APP + 1;

pub struct WinClipboard { pub hwnd: HWND }

fn open(hwnd: HWND) -> bool {
    // Another app may hold the clipboard open for a moment.
    for _ in 0..5 {
        if unsafe { OpenClipboard(Some(hwnd)) }.is_ok() { return true; }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}

impl crate::clip_guard::Clipboard for WinClipboard {
    fn change_count(&self) -> i64 { unsafe { GetClipboardSequenceNumber() as i64 } }

    fn read_text(&self) -> Option<String> {
        unsafe {
            if IsClipboardFormatAvailable(CF_UNICODETEXT).is_err() || IsClipboardFormatAvailable(CF_HDROP).is_ok() { return None; }
            if !open(self.hwnd) { return None; }
            let text = (|| {
                let h = GetClipboardData(CF_UNICODETEXT).ok()?;
                let g = HGLOBAL(h.0);
                let p = GlobalLock(g) as *const u16;
                if p.is_null() { return None; }
                let max = GlobalSize(g) / 2;
                let mut n = 0;
                while n < max && *p.add(n) != 0 { n += 1; }
                let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, n));
                let _ = GlobalUnlock(g);
                Some(s)
            })();
            let _ = CloseClipboard();
            text
        }
    }

    fn write_text(&self, text: &str) -> bool {
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            if !open(self.hwnd) { return false; }
            let ok = (|| {
                EmptyClipboard().ok()?;
                let g = GlobalAlloc(GMEM_MOVEABLE, wide.len() * 2).ok()?;
                let p = GlobalLock(g) as *mut u16;
                if p.is_null() { return None; }
                std::ptr::copy_nonoverlapping(wide.as_ptr(), p, wide.len());
                let _ = GlobalUnlock(g);
                // On success the clipboard owns the memory.
                SetClipboardData(CF_UNICODETEXT, Some(HANDLE(g.0))).ok()?;
                Some(())
            })().is_some();
            let _ = CloseClipboard();
            ok
        }
    }
}

pub struct WinFrontmost;

impl crate::clip_guard::Frontmost for WinFrontmost {
    fn frontmost(&self) -> Option<String> {
        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.0.is_null() { return None; }
            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            if pid == 0 { return None; }
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            let r = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len);
            let _ = CloseHandle(h);
            r.ok()?;
            Some(crate::clip_guard_apps::exe_id(&String::from_utf16_lossy(&buf[..len as usize])))
        }
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    if msg == WM_CLIPBOARDUPDATE {
        // A sent message: GetMessageW handles it internally and does not return, so post one that it does.
        let _ = PostMessageW(Some(hwnd), WM_WAKE, WPARAM(0), LPARAM(0));
        return LRESULT(0);
    }
    DefWindowProcW(hwnd, msg, wp, lp)
}

// Runs on the calling thread until the process ends: calls `tick` on every clipboard change and every
// 500 ms. Err when the listener window cannot be created.
pub fn run(mut tick: impl FnMut(HWND)) -> Result<(), String> {
    unsafe {
        let inst = GetModuleHandleW(PCWSTR::null()).map_err(|e| e.to_string())?;
        let class = w!("MoorAIClipboardGuard");
        let wc = WNDCLASSW { lpfnWndProc: Some(wndproc), hInstance: inst.into(), lpszClassName: class, ..Default::default() };
        RegisterClassW(&wc);
        let hwnd = CreateWindowExW(WINDOW_EX_STYLE(0), class, w!("MoorAI clipboard guard"), WINDOW_STYLE(0), 0, 0, 0, 0, Some(HWND_MESSAGE), None, Some(inst.into()), None).map_err(|e| e.to_string())?;
        AddClipboardFormatListener(hwnd).map_err(|e| e.to_string())?;
        SetTimer(Some(hwnd), 1, 500, None);
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            DispatchMessageW(&msg);
            if msg.message == WM_TIMER || msg.message == WM_WAKE { tick(hwnd); }
        }
    }
    Ok(())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

// A toast under the app's AppUserModelID (the installer's Start-menu shortcut carries it), else under
// PowerShell's, which every Windows install registers. The in-app banner is shown either way.
pub fn notify(title: &str, body: &str) {
    use windows::Data::Xml::Dom::XmlDocument;
    use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
    let show = |aumid: &str| -> windows::core::Result<()> {
        let xml = XmlDocument::new()?;
        xml.LoadXml(&HSTRING::from(format!("<toast><visual><binding template=\"ToastGeneric\"><text>{}</text><text>{}</text></binding></visual></toast>", xml_escape(title), xml_escape(body))))?;
        let toast = ToastNotification::CreateToastNotification(&xml)?;
        ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(aumid))?.Show(&toast)
    };
    if show("run.glick.moorai").is_err() {
        let _ = show("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe");
    }
}
