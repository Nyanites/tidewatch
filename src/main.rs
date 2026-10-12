#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod detect;
mod known;
mod loader;
#[cfg(target_os = "macos")]
mod macos;
mod model;
mod rules;
mod search;
mod sigma;
mod update;
mod workspace;

use std::path::PathBuf;

use eframe::egui;

fn main() -> eframe::Result {
    // Older macOS passes a `-psn_…` process serial number when launched from Finder.
    let path = std::env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .find(|p| !p.to_string_lossy().starts_with("-psn"));

    // The EVTX parser recurses on nested data; give worker threads room for hostile files.
    let _ = rayon::ThreadPoolBuilder::new()
        .stack_size(16 << 20)
        .build_global();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Tidewatch")
            .with_inner_size([1400.0, 860.0])
            .with_min_inner_size([800.0, 500.0])
            .with_drag_and_drop(true)
            // Without this eframe replaces the bundle's Dock icon with the egui logo.
            .with_icon(
                eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon-256.png"))
                    .expect("valid icon PNG"),
            ),
        #[cfg(target_os = "macos")]
        event_loop_builder: Some(Box::new(|_| macos::install())),
        ..Default::default()
    };

    eframe::run_native(
        "Tidewatch",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, path)))),
    )
}
