use crate::app_event::AppEvent;
use crate::app_event_sender::AppEventSender;
use codex_core::config::find_codex_home;
use codex_login::AuthMode;
use codex_login::CodexAuth;
use codex_login::get_auth_file;
use codex_login::try_read_auth_json;
use cpal::traits::DeviceTrait;
use cpal::traits::HostTrait;
use cpal::traits::StreamTrait;
use hound::SampleFormat;
use hound::WavSpec;
use hound::WavWriter;
use std::io::Cursor;
use std::sync::Arc;
use std::sync::Mutex;
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

        let stream = match config.sample_format() {
            cpal::SampleFormat::F32 => device
                .build_input_stream(
                    &config.into(),
                    move |input: &[f32], _| {
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
                        if let Ok(mut buf) = data_cb.lock() {
                            for &s in input {
                                let v = (s as i32 - 32768) as i16;
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
        })
    }

    pub fn stop(mut self) -> Result<RecordedAudio, String> {
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
}

pub fn transcribe_async(audio: RecordedAudio, tx: AppEventSender) {
    std::thread::spawn(move || {
        // Serialize WAV to memory
        let mut wav_bytes: Vec<u8> = Vec::new();
        let spec = WavSpec {
            channels: audio.channels,
            sample_rate: audio.sample_rate,
            bits_per_sample: 16,
            sample_format: SampleFormat::Int,
        };
        let mut cursor = Cursor::new(&mut wav_bytes);
        if let Ok(mut writer) = WavWriter::new(&mut cursor, spec) {
            for s in &audio.data {
                if writer.write_sample(*s).is_err() {
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
        let res: Result<(), String> = rt.block_on(async move {
            // Resolve API key using existing Codex auth logic (do not read env).
            let codex_home =
                find_codex_home().map_err(|e| format!("failed to find codex home: {e}"))?;
            let auth_opt = CodexAuth::from_codex_home(&codex_home)
                .map_err(|e| format!("failed to read auth.json: {e}"))?;
            let api_key = match auth_opt {
                Some(auth) => match auth.mode {
                    AuthMode::ApiKey => auth
                        .get_token()
                        .await
                        .map_err(|e| format!("failed to get API key token: {e}"))?,
                    AuthMode::ChatGPT => {
                        // Attempt to read a persisted OPENAI_API_KEY from auth.json
                        let auth_file = get_auth_file(&codex_home);
                        let dot = try_read_auth_json(&auth_file)
                            .map_err(|e| format!("failed to read auth.json: {e}"))?;
                        dot.openai_api_key.ok_or_else(|| {
                            "OPENAI_API_KEY not available in auth.json; cannot transcribe audio"
                                .to_string()
                        })?
                    }
                },
                None => {
                    return Err("No Codex auth is configured; please run `codex login`".to_string());
                }
            };

            let client = reqwest::Client::new();

            let part = reqwest::multipart::Part::bytes(wav_bytes)
                .file_name("audio.wav")
                .mime_str("audio/wav")
                .map_err(|e| format!("failed to set mime: {e}"))?;
            let form = reqwest::multipart::Form::new()
                .text("model", "whisper-1")
                .part("file", part);

            let resp = client
                .post("https://api.openai.com/v1/audio/transcriptions")
                .bearer_auth(api_key)
                .multipart(form)
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
            tx.send(AppEvent::InsertComposerText(text));
            Ok(())
        });

        if let Err(e) = res {
            error!("voice transcription error: {e}");
        } else {
            info!("voice transcription succeeded");
        }
    });
}
