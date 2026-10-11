//! Finder integration: receive files opened via double-click, "Open With" or by dropping
//! them on the Dock icon.
//!
//! macOS delivers these through `-[NSApplicationDelegate application:openURLs:]`. winit
//! owns the application delegate (and panics if it is replaced), so instead we add that one
//! method to winit's delegate class at runtime. On a cold launch the URLs arrive before
//! eframe creates our app, so this happens from a will-finish-launching observer that is
//! registered before the event loop exists, and paths are parked in a queue until the UI
//! picks them up.

use std::path::PathBuf;
use std::ptr::NonNull;
use std::sync::{Mutex, OnceLock};

use eframe::egui;
use objc2::runtime::{AnyClass, AnyObject, Sel};
use objc2::{ffi, sel};
use objc2_app_kit::{NSApplication, NSApplicationWillFinishLaunchingNotification};
use objc2_foundation::{MainThreadMarker, NSArray, NSNotification, NSNotificationCenter, NSURL};

/// Must match the class name winit declares for its `NSApplicationDelegate`.
const WINIT_DELEGATE_CLASS: &str = "WinitApplicationDelegate";

static PENDING: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
static CTX: OnceLock<egui::Context> = OnceLock::new();

extern "C" fn application_open_urls(
    _this: &AnyObject,
    _cmd: Sel,
    _app: &AnyObject,
    urls: &NSArray<NSURL>,
) {
    let paths = urls
        .iter()
        .filter_map(|u| unsafe { u.path() })
        .map(|p| PathBuf::from(p.to_string()));
    if let Ok(mut pending) = PENDING.lock() {
        pending.extend(paths);
    }
    if let Some(ctx) = CTX.get() {
        ctx.request_repaint();
    }
}

fn add_open_urls_method(mtm: MainThreadMarker) {
    let Some(class) = AnyClass::get(WINIT_DELEGATE_CLASS) else {
        eprintln!("tidewatch: {WINIT_DELEGATE_CLASS} not found; Finder open-file support disabled");
        return;
    };
    let sel = sel!(application:openURLs:);
    if class.instance_method(sel).is_none() {
        type OpenUrls = extern "C" fn(&AnyObject, Sel, &AnyObject, &NSArray<NSURL>);
        // SAFETY: the signature matches `-application:openURLs:` ("v@:@@": void, self, _cmd,
        // NSApplication*, NSArray*), and the class is a registered, live Objective-C class.
        unsafe {
            let imp =
                std::mem::transmute::<OpenUrls, unsafe extern "C" fn()>(application_open_urls);
            ffi::class_addMethod(
                class as *const AnyClass as *mut ffi::objc_class,
                sel.as_ptr(),
                Some(imp),
                c"v@:@@".as_ptr(),
            );
        }
    }
    // AppKit caches which optional delegate methods exist when the delegate is assigned,
    // so assign it again now that it responds to `application:openURLs:`.
    let app = NSApplication::sharedApplication(mtm);
    unsafe {
        let delegate = app.delegate();
        app.setDelegate(delegate.as_deref());
    }
}

/// Call before the event loop is created (from eframe's event-loop builder hook).
pub fn install() {
    let block = block2::RcBlock::new(|_: NonNull<NSNotification>| {
        if let Some(mtm) = MainThreadMarker::new() {
            add_open_urls_method(mtm);
        }
    });
    unsafe {
        let observer = NSNotificationCenter::defaultCenter()
            .addObserverForName_object_queue_usingBlock(
                Some(NSApplicationWillFinishLaunchingNotification),
                None,
                None,
                &block,
            );
        // Keep the observer registered for the life of the process.
        std::mem::forget(observer);
    }
}

/// Lets the handler wake the UI when files arrive while the app is running.
pub fn set_context(ctx: &egui::Context) {
    let _ = CTX.set(ctx.clone());
}

/// Files opened from Finder since the last call.
pub fn take_opened() -> Vec<PathBuf> {
    PENDING
        .lock()
        .map(|mut p| std::mem::take(&mut *p))
        .unwrap_or_default()
}
