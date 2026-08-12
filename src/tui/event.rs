//! Terminal event polling (crossterm synchronous poll/read).

use std::time::Duration;

use crossterm::event::{self, Event, KeyEvent};

use crate::error::{Error, Result};

/// Outcome of feeding an event to the [`App`](super::App) state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventResult {
    Continue,
    Quit,
}

/// A polled terminal event. `Tick` fires every poll interval (100ms) and lets
/// the App do time-based work (e.g. clipboard auto-clear countdown) without
/// blocking on input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TuiEvent {
    Key(KeyEvent),
    Tick,
}

/// Poll for a terminal event with a short timeout (so the UI can refresh
/// reveal-on-hold state promptly). Returns `Ok(None)` on timeout.
pub fn poll() -> Result<Option<TuiEvent>> {
    if event::poll(Duration::from_millis(100))
        .map_err(|e| Error::Other(anyhow::anyhow!("event poll failed: {e}")))?
    {
        match event::read().map_err(|e| Error::Other(anyhow::anyhow!("event read failed: {e}")))? {
            Event::Key(k) => Ok(Some(TuiEvent::Key(k))),
            _ => Ok(None),
        }
    } else {
        // No input within the window — emit a Tick so the App can advance
        // time-based state (clipboard clear deadline, reveal timeout, ...).
        Ok(Some(TuiEvent::Tick))
    }
}
