use crate::app_event::AppEvent;
use crate::app_event_sender::AppEventSender;
use crate::bottom_pane::textarea::TextArea;
#[cfg(not(target_os = "linux"))]
use crate::voice::VoiceCapture;
#[cfg(target_os = "linux")]
struct VoiceCapture;
use crossterm::event::KeyCode;
use crossterm::event::KeyEvent;
use crossterm::event::KeyEventKind;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;
use uuid::Uuid;

pub(crate) struct VoiceHandleResult {
    pub(crate) consumed: bool,
    pub(crate) sync_popups: bool,
}

pub(crate) struct VoiceTimeoutResult {
    pub(crate) started: bool,
    pub(crate) sync_popups: bool,
}

#[derive(Default)]
pub(crate) struct VoiceInputState {
    voice: Option<VoiceCapture>,
    recording_placeholder_id: Option<String>,
    space_hold_started_at: Option<Instant>,
    space_hold_id: Option<String>,
    space_insert_pos: Option<usize>,
}

impl VoiceInputState {
    pub(crate) fn is_recording(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            false
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.voice.is_some()
        }
    }

    pub(crate) fn cancel_pending_hold_if_needed(&mut self, key_event: &KeyEvent) {
        #[cfg(target_os = "linux")]
        {
            let _ = key_event;
            return;
        }
        #[cfg(not(target_os = "linux"))]
        if self.space_hold_started_at.is_some() && !matches!(key_event.code, KeyCode::Char(' ')) {
            self.clear_space_hold();
        }
    }

    pub(crate) fn handle_recording_key_event(
        &mut self,
        key_event: &KeyEvent,
        textarea: &mut TextArea,
        app_event_tx: &AppEventSender,
    ) -> Option<VoiceHandleResult> {
        #[cfg(target_os = "linux")]
        {
            let _ = (key_event, textarea, app_event_tx);
            return None;
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.voice.as_ref()?;

            let should_stop = match key_event.kind {
                KeyEventKind::Release => matches!(key_event.code, KeyCode::Char(' ')),
                KeyEventKind::Press | KeyEventKind::Repeat => {
                    !matches!(key_event.code, KeyCode::Char(' '))
                }
            };

            if should_stop {
                if let Some(vc) = self.voice.take() {
                    match vc.stop() {
                        Ok(audio) => {
                            let id = self.recording_placeholder_id.take().unwrap_or_else(|| {
                                let id = Uuid::new_v4().to_string();
                                textarea.insert_named_element("transcribing", id.clone());
                                id
                            });
                            let _ = textarea.update_named_element_by_id(&id, "transcribing");
                            let tx = app_event_tx.clone();
                            crate::voice::transcribe_async(id, audio, tx);
                        }
                        Err(e) => {
                            tracing::error!("failed to stop voice capture: {e}");
                        }
                    }
                }

                return Some(VoiceHandleResult {
                    consumed: true,
                    sync_popups: true,
                });
            }

            Some(VoiceHandleResult {
                consumed: false,
                sync_popups: false,
            })
        }
    }

    pub(crate) fn handle_space_key_event(
        &mut self,
        key_event: &KeyEvent,
        paste_burst_active: bool,
        textarea: &mut TextArea,
        app_event_tx: &AppEventSender,
    ) -> Option<VoiceHandleResult> {
        #[cfg(target_os = "linux")]
        {
            let _ = (key_event, paste_burst_active, textarea, app_event_tx);
            return None;
        }
        #[cfg(not(target_os = "linux"))]
        {
            if !matches!(key_event.code, KeyCode::Char(' ')) {
                return None;
            }

            match key_event.kind {
                KeyEventKind::Press => {
                    if paste_burst_active {
                        return None;
                    }
                    if self.space_hold_started_at.is_some() {
                        return Some(VoiceHandleResult {
                            consumed: false,
                            sync_popups: true,
                        });
                    }

                    let insert_pos = textarea.cursor();
                    textarea.insert_str(" ");

                    let id = Uuid::new_v4().to_string();
                    self.space_hold_started_at = Some(Instant::now());
                    self.space_hold_id = Some(id.clone());
                    self.space_insert_pos = Some(insert_pos);

                    let tx = app_event_tx.clone();
                    if let Ok(handle) = tokio::runtime::Handle::try_current() {
                        handle.spawn(async move {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            tx.send(AppEvent::SpaceHoldTimeout { id });
                        });
                    } else {
                        std::thread::spawn(move || {
                            std::thread::sleep(Duration::from_millis(500));
                            tx.send(AppEvent::SpaceHoldTimeout { id });
                        });
                    }

                    Some(VoiceHandleResult {
                        consumed: true,
                        sync_popups: true,
                    })
                }
                KeyEventKind::Repeat => {
                    if self.space_hold_started_at.is_some() {
                        return Some(VoiceHandleResult {
                            consumed: false,
                            sync_popups: false,
                        });
                    }
                    None
                }
                KeyEventKind::Release => {
                    self.clear_space_hold();
                    Some(VoiceHandleResult {
                        consumed: true,
                        sync_popups: false,
                    })
                }
            }
        }
    }

    pub(crate) fn on_space_hold_timeout(
        &mut self,
        id: &str,
        textarea: &mut TextArea,
        app_event_tx: &AppEventSender,
    ) -> VoiceTimeoutResult {
        #[cfg(target_os = "linux")]
        {
            let _ = (id, textarea, app_event_tx);
            return VoiceTimeoutResult {
                started: false,
                sync_popups: false,
            };
        }
        #[cfg(not(target_os = "linux"))]
        {
            if self.voice.is_some() {
                return VoiceTimeoutResult {
                    started: false,
                    sync_popups: false,
                };
            }

            if self.space_hold_started_at.is_none() || self.space_hold_id.as_deref() != Some(id) {
                return VoiceTimeoutResult {
                    started: false,
                    sync_popups: false,
                };
            }

            let mut sync_popups = false;
            if let Some(pos) = self.space_insert_pos.take() {
                let text = textarea.text().to_string();
                if pos < text.len()
                    && let Some(ch) = text[pos..].chars().next()
                    && ch == ' '
                {
                    let next = pos + ch.len_utf8();
                    textarea.replace_range(pos..next, "");
                    sync_popups = true;
                }
            }

            self.clear_space_hold();

            match VoiceCapture::start() {
                Ok(vc) => {
                    self.voice = Some(vc);
                    let id = Uuid::new_v4().to_string();
                    textarea.insert_named_element("", id.clone());
                    self.recording_placeholder_id = Some(id.clone());
                    sync_popups = true;
                    if let Some(v) = &self.voice {
                        let data = v.data_arc();
                        let stop = v.stopped_flag();
                        let sr = v.sample_rate();
                        let ch = v.channels();
                        let peak = v.last_peak_arc();
                        self.spawn_recording_meter(id, sr, ch, data, peak, stop, app_event_tx);
                    }
                    VoiceTimeoutResult {
                        started: true,
                        sync_popups,
                    }
                }
                Err(e) => {
                    tracing::error!("failed to start voice capture: {e}");
                    VoiceTimeoutResult {
                        started: false,
                        sync_popups,
                    }
                }
            }
        }
    }

    pub(crate) fn recording_hint(&self) -> Option<Vec<(String, String)>> {
        #[cfg(target_os = "linux")]
        {
            None
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.voice.as_ref().map(|_| {
                vec![(
                    "Recording".to_string(),
                    "— release Space to transcribe".to_string(),
                )]
            })
        }
    }

    fn clear_space_hold(&mut self) {
        self.space_hold_started_at = None;
        self.space_hold_id = None;
        self.space_insert_pos = None;
    }

    fn spawn_recording_meter(
        &self,
        id: String,
        _sample_rate: u32,
        _channels: u16,
        _data: Arc<Mutex<Vec<i16>>>,
        last_peak: Arc<AtomicU16>,
        stop: Arc<AtomicBool>,
        app_event_tx: &AppEventSender,
    ) {
        let tx = app_event_tx.clone();
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        handle.spawn(async move {
            let width: usize = 12;
            // Bar glyphs low→high; single-line sparkline that scrolls left.
            // let symbols: Vec<char> = "·•●⬤".chars().collect();
            let symbols: Vec<char> = "⠤⠴⠶⠷⡷⡿⣿".chars().collect();
            let mut history: VecDeque<char> = VecDeque::with_capacity(width);
            // Prefill to fixed width so the meter is always exactly `width` chars.
            while history.len() < width {
                history.push_back(symbols[0]);
            }
            // Adaptive gain control: track a slow EMA of RMS as the noise/reference level.
            let mut noise_ema: f64 = 0.02; // bootstrap with small non-zero to avoid division by zero
            let alpha_noise: f64 = 0.05; // slightly faster adaptation for responsiveness
            // Envelope follower with separate attack/release for responsiveness
            let mut env: f64 = 0.0;
            let attack: f64 = 0.80; // faster rise for immediate peaks
            let release: f64 = 0.25; // quick fall but not too jumpy
            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                // Read latest peak value from VoiceCapture
                let latest_peak = last_peak.load(Ordering::Relaxed) as f64 / (i16::MAX as f64);
                // Envelope follower (attack/release) for responsive yet stable meter
                if latest_peak > env {
                    env = attack * latest_peak + (1.0 - attack) * env;
                } else {
                    env = release * latest_peak + (1.0 - release) * env;
                }
                // Use envelope as a proxy for RMS for noise tracking
                let rms_approx = env * 0.7;
                noise_ema = (1.0 - alpha_noise) * noise_ema + alpha_noise * rms_approx;
                let ref_level = noise_ema.max(0.01);
                // Mix instantaneous peak with envelope so the bar reacts faster to changes
                let fast_signal = 0.8 * latest_peak + 0.2 * env;
                let target = 2.0f64; // slightly hotter meter
                let raw = (fast_signal / (ref_level * target)).max(0.0);
                let k = 1.6f64; // lighter compression for more punch
                let compressed = (raw.ln_1p() / (k * 1.0).ln_1p()).min(1.0);
                // Map to single-line glyph proportional to level (bottom→top).
                let idx = (compressed * (symbols.len() as f64 - 1.0))
                    .round()
                    .clamp(0.0, symbols.len() as f64 - 1.0) as usize;
                let level_char = symbols[idx];

                if history.len() >= width {
                    history.pop_front();
                }
                history.push_back(level_char);

                let mut text = String::with_capacity(width);
                for ch in &history {
                    text.push(*ch);
                }
                tx.send(AppEvent::RecordingMeter {
                    id: id.clone(),
                    text,
                });

                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
    }
}
