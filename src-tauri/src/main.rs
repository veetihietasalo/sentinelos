#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;
use sentinel_core::model::{Snapshot, VectorStatus};
use sentinel_core::monitor::Monitor;
use provider_macos::MacosProvider;
use tauri::{Emitter, Manager};
use tauri::tray::TrayIconBuilder;

pub struct AppState {
    pub monitor: Mutex<Monitor>,
}

/// Worst overall status for the menu-bar glyph. `Unavailable` (a blocked or
/// errored check) is surfaced as "review" — it is never silently reported as
/// "secure". Mirrors the UI's `worst()` so tray and window agree.
fn overall_glyph(s: &Snapshot) -> &'static str {
    use VectorStatus::*;
    if s.reports.iter().any(|r| r.status == Threat) {
        "● threat"
    } else if s.reports.iter().any(|r| matches!(r.status, Review | Unavailable)) {
        "● review"
    } else {
        "● secure"
    }
}

#[tauri::command]
fn run_sweep(state: tauri::State<AppState>) -> Snapshot {
    let provider = MacosProvider::new();
    let mut mon = state.monitor.lock().unwrap();
    mon.tick(&provider);
    mon.current().cloned().unwrap_or(Snapshot { reports: vec![] })
}

#[tauri::command]
fn get_snapshot(state: tauri::State<AppState>) -> Option<Snapshot> {
    state.monitor.lock().unwrap().current().cloned()
}

fn main() {
    tauri::Builder::default()
        .manage(AppState { monitor: Mutex::new(Monitor::new()) })
        .invoke_handler(tauri::generate_handler![run_sweep, get_snapshot])
        .setup(|app| {
            let tray = TrayIconBuilder::with_id("sentinel-tray")
                .title("● secure")
                .build(app)?;
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let mut ticker =
                    tokio::time::interval(std::time::Duration::from_secs(300));
                loop {
                    ticker.tick().await;
                    let provider = MacosProvider::new();
                    let (events, snapshot) = {
                        let state = handle.state::<AppState>();
                        let mut mon = state.monitor.lock().unwrap();
                        let evs = mon.tick(&provider);
                        (evs, mon.current().cloned())
                    };
                    for ev in &events {
                        let _ = handle.emit("sentinel://event", ev);
                    }
                    if let Some(snap) = snapshot {
                        let _ = handle.emit("sentinel://snapshot", &snap);
                        let _ = tray.set_title(Some(overall_glyph(&snap)));
                    }
                }
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
