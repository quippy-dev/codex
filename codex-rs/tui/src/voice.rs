use crate::app_event::AppEvent;
use crate::app_event_sender::AppEventSender;
use codex_core::auth::AuthCredentialsStoreMode;
use codex_core::config::find_codex_home;
use codex_core::default_client::get_codex_user_agent;
use codex_login::CodexAuth;
use cpal::traits::DeviceTrait;
use cpal::traits::HostTrait;
use cpal::traits::StreamTrait;
use hound::SampleFormat;
use hound::WavSpec;
use hound::WavWriter;
use std::io::Cursor;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;
use tracing::error;
use tracing::info;

pub struct RecordedAudio {
    pub data: Vec<i16>,
    pub sample_rate: u32,
    pub channels: u16,
}

pub struct VoiceCapture {
    stream: Option<cpal::Stream>,
    sample_rate: u32,
    channels: u16,
    data: Arc<Mutex<Vec<i16>>>,
    stopped: Arc<AtomicBool>,
    last_peak: Arc<AtomicU16>,
}

impl VoiceCapture {
    pub fn start() -> Result<Self, String> {
        let host = cpal::default_host();
        let device = host
            .default_input_device()
            .ok_or_else(|| "no input audio device available".to_string())?;
        let config = device
            .default_input_config()
            .map_err(|e| format!("failed to get default input config: {e}"))?;

        let sample_rate = config.sample_rate().0;
        let channels = config.channels();
        let data: Arc<Mutex<Vec<i16>>> = Arc::new(Mutex::new(Vec::new()));
        let data_cb = data.clone();
        let stopped = Arc::new(AtomicBool::new(false));
        let last_peak = Arc::new(AtomicU16::new(0));
        let last_peak_cb = last_peak.clone();

        let stream = match config.sample_format() {
            cpal::SampleFormat::F32 => device
                .build_input_stream(
                    &config.into(),
                    move |input: &[f32], _| {
                        // Compute peak first to avoid holding the lock longer
                        let mut peak: f32 = 0.0;
                        for &s in input {
                            let a = s.abs();
                            if a > peak {
                                peak = a;
                            }
                        }
                        let peak_u = (peak.min(1.0) * i16::MAX as f32) as i32;
                        last_peak_cb.store(peak_u.max(0) as u16, Ordering::Relaxed);
                        if let Ok(mut buf) = data_cb.lock() {
                            // Convert f32 in [-1.0, 1.0] to i16
                            for &s in input {
                                let v = (s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16;
                                buf.push(v);
                            }
                        }
                    },
                    move |err| {
                        error!("audio input error: {err}");
                    },
                    None,
                )
                .map_err(|e| format!("failed to build input stream: {e}"))?,
            cpal::SampleFormat::I16 => device
                .build_input_stream(
                    &config.into(),
                    move |input: &[i16], _| {
                        // Update peak from this buffer
                        let mut peak: i32 = 0;
                        for &s in input {
                            let a = (s as i32).unsigned_abs() as i32; // absolute in i32
                            if a > peak {
                                peak = a;
                            }
                        }
                        last_peak_cb.store(peak as u16, Ordering::Relaxed);
                        if let Ok(mut buf) = data_cb.lock() {
                            buf.extend_from_slice(input);
                        }
                    },
                    move |err| {
                        error!("audio input error: {err}");
                    },
                    None,
                )
                .map_err(|e| format!("failed to build input stream: {e}"))?,
            cpal::SampleFormat::U16 => device
                .build_input_stream(
                    &config.into(),
                    move |input: &[u16], _| {
                        // Update peak then convert and push
                        let mut peak: i32 = 0;
                        if let Ok(mut buf) = data_cb.lock() {
                            for &s in input {
                                let v_i16 = (s as i32 - 32768) as i16;
                                let a = (v_i16 as i32).unsigned_abs() as i32;
                                if a > peak {
                                    peak = a;
                                }
                                buf.push(v_i16);
                            }
                        }
                        last_peak_cb.store(peak as u16, Ordering::Relaxed);
                    },
                    move |err| {
                        error!("audio input error: {err}");
                    },
                    None,
                )
                .map_err(|e| format!("failed to build input stream: {e}"))?,
            _ => {
                return Err("unsupported input sample format".to_string());
            }
        };

        stream
            .play()
            .map_err(|e| format!("failed to start input stream: {e}"))?;

        Ok(Self {
            stream: Some(stream),
            sample_rate,
            channels,
            data,
            stopped,
            last_peak,
        })
    }

    pub fn stop(mut self) -> Result<RecordedAudio, String> {
        // Mark stopped so any metering task can exit cleanly.
        self.stopped.store(true, Ordering::SeqCst);
        // Dropping the stream stops capture.
        self.stream.take();
        let data = self
            .data
            .lock()
            .map_err(|_| "failed to lock audio buffer".to_string())?
            .clone();
        Ok(RecordedAudio {
            data,
            sample_rate: self.sample_rate,
            channels: self.channels,
        })
    }

    pub fn data_arc(&self) -> Arc<Mutex<Vec<i16>>> {
        self.data.clone()
    }

    pub fn stopped_flag(&self) -> Arc<AtomicBool> {
        self.stopped.clone()
    }

    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    pub fn channels(&self) -> u16 {
        self.channels
    }

    pub fn last_peak_arc(&self) -> Arc<AtomicU16> {
        self.last_peak.clone()
    }
}

pub fn transcribe_async(id: String, audio: RecordedAudio, tx: AppEventSender) {
    std::thread::spawn(move || {
        // Require a minimum duration before attempting transcription to avoid
        // spurious garbage text from extremely short recordings.
        let total_samples = audio.data.len() as f32;
        let samples_per_second = (audio.sample_rate as f32) * (audio.channels as f32);
        let duration_seconds = if samples_per_second > 0.0 {
            total_samples / samples_per_second
        } else {
            0.0
        };
        const MIN_DURATION_SECONDS: f32 = 1.0;
        if duration_seconds < MIN_DURATION_SECONDS {
            let msg = format!(
                "recording too short ({duration_seconds:.2}s); minimum is {MIN_DURATION_SECONDS:.2}s"
            );
            info!("{msg}");
            tx.send(AppEvent::TranscriptionFailed { id, error: msg });
            return;
        }

        // Always send the full clip without trimming or rejecting.
        let (start_sample, end_sample) = (0, audio.data.len());

        // Serialize WAV (trimmed segment) to memory
        let mut wav_bytes: Vec<u8> = Vec::new();
        let spec = WavSpec {
            channels: audio.channels,
            sample_rate: audio.sample_rate,
            bits_per_sample: 16,
            sample_format: SampleFormat::Int,
        };
        let mut cursor = Cursor::new(&mut wav_bytes);
        if let Ok(mut writer) = WavWriter::new(&mut cursor, spec) {
            // Simple peak normalization with headroom to improve audibility on quiet inputs.
            let segment = &audio.data[start_sample..end_sample];
            let mut peak: i16 = 0;
            for &s in segment {
                let a = s.unsigned_abs();
                if a > peak.unsigned_abs() {
                    peak = s;
                }
            }
            let peak_abs = (peak as i32).unsigned_abs() as i32;
            let target = (i16::MAX as f32) * 0.9; // leave some headroom
            let gain: f32 = if peak_abs > 0 {
                target / (peak_abs as f32)
            } else {
                1.0
            };
            for &s in segment {
                let v = ((s as f32) * gain)
                    .round()
                    .clamp(i16::MIN as f32, i16::MAX as f32) as i16;
                if writer.write_sample(v).is_err() {
                    error!("failed writing wav sample");
                    break;
                }
            }
            let _ = writer.finalize();
        } else {
            error!("failed to create wav writer");
            return;
        }

        // Run reqwest + auth lookup on a dedicated runtime
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                error!("failed to create tokio runtime: {e}");
                return;
            }
        };
        let tx2 = tx.clone();
        let id2 = id.clone();
        let res: Result<(), String> = rt.block_on(async move {
            // Resolve API key using existing Codex auth logic (do not read env).
            let codex_home =
                find_codex_home().map_err(|e| format!("failed to find codex home: {e}"))?;
            let auth_opt =
                CodexAuth::from_auth_storage(&codex_home, AuthCredentialsStoreMode::Auto)
                    .map_err(|e| format!("failed to read auth.json: {e}"))?;
            let auth = match auth_opt {
                Some(auth) => auth,
                None => {
                    return Err("No Codex auth is configured; please run `codex login`".to_string());
                }
            };
            let bearer_token = auth
                .get_token()
                .map_err(|e| format!("failed to get auth token: {e}"))?;
            let chatgpt_account_id = auth.get_account_id();

            let client = reqwest::Client::new();

            let part = reqwest::multipart::Part::bytes(wav_bytes)
                .file_name("audio.wav")
                .mime_str("audio/wav")
                .map_err(|e| format!("failed to set mime: {e}"))?;
            let form = reqwest::multipart::Form::new()
                .text("model", "gpt-4o-transcribe")
                .part("file", part);

            let mut req = client
                .post("https://api.openai.com/v1/audio/transcriptions")
                .bearer_auth(bearer_token)
                .multipart(form)
                .header("User-Agent", get_codex_user_agent());

            if let Some(acc) = chatgpt_account_id {
                req = req.header("chatgpt-account-id", acc);
            }

            let resp = req
                .send()
                .await
                .map_err(|e| format!("transcription request failed: {e}"))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp
                    .text()
                    .await
                    .unwrap_or_else(|_| "<failed to read body>".to_string());
                return Err(format!("transcription failed: {status} {body}"));
            }

            let v: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| format!("failed to parse json: {e}"))?;
            let text = v
                .get("text")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            if text.is_empty() {
                return Err("empty transcription result".to_string());
            }
            tx2.send(AppEvent::TranscriptionComplete { id: id2, text });
            Ok(())
        });

        if let Err(e) = res {
            error!("voice transcription error: {e}");
            tx.send(AppEvent::TranscriptionFailed { id, error: e });
        } else {
            info!("voice transcription succeeded");
        }
    });
}
