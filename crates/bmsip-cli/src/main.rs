#![forbid(unsafe_code)]

//! MODULE_CONTRACT: Linux CLI SIP endpoint (`bmsip-cli`) built on `bmsip-engine` supporting `call` and `listen` with WAV or live PipeWire/ALSA audio.
//! INVARIANTS: `#![forbid(unsafe_code)]`; uses only `bmsip-engine` public API; zero `.unwrap()`/`.expect()` outside tests; explicit exit codes (`0` success, `1` failure).
//! RFC_REFS: RFC 3261, RFC 3550, RFC 4733.

mod analyzer;
mod live_audio;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use bmsip_engine::bmsip_core::dialog::{RegistrationState, UaConfig};
use bmsip_engine::bmsip_core::sdp::RtpCodec;
use bmsip_engine::bmsip_core::sip::SipUri;
use bmsip_engine::bmsip_media::{DtmfDigit, WavPcm16};
use bmsip_engine::{
    AudioPort, EngineCommand, EngineConfig, EngineEvent, SipEngine, WavAudioHandle, WavAudioPort,
};
use live_audio::{LiveAudioHandle, LiveLinuxAudioPort};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodecChoice {
    Opus,
    Pcmu,
    Pcma,
}

impl CodecChoice {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.to_ascii_lowercase().as_str() {
            "opus" => Ok(Self::Opus),
            "pcmu" => Ok(Self::Pcmu),
            "pcma" => Ok(Self::Pcma),
            _ => Err(format!(
                "unsupported --codec '{raw}' (expected opus, pcmu, or pcma)"
            )),
        }
    }

    fn supported_codecs(self) -> Vec<RtpCodec> {
        match self {
            Self::Opus => vec![
                RtpCodec::opus(),
                RtpCodec::pcmu(),
                RtpCodec::pcma(),
                RtpCodec::telephone_event(101),
            ],
            Self::Pcmu => vec![
                RtpCodec::pcmu(),
                RtpCodec::pcma(),
                RtpCodec::telephone_event(101),
            ],
            Self::Pcma => vec![
                RtpCodec::pcma(),
                RtpCodec::pcmu(),
                RtpCodec::telephone_event(101),
            ],
        }
    }
}

#[derive(Debug, PartialEq)]
struct CallCliArgs {
    server: String,
    user: String,
    password: String,
    target: String,
    duration_ms: u64,
    tone_hz: u32,
    codec: CodecChoice,
    mic_gain: f32,
    live_audio: bool,
    dtmf: Option<String>,
    wav_in: Option<String>,
    wav_out: Option<String>,
    json_report: Option<String>,
}

#[derive(Debug, PartialEq)]
struct ListenCliArgs {
    server: String,
    user: String,
    password: String,
    duration_ms: u64,
    codec: CodecChoice,
    mic_gain: f32,
    live_audio: bool,
    wav_out: Option<String>,
    json_report: Option<String>,
}

#[derive(Debug, PartialEq)]
struct AnalyzeCliArgs {
    wav_path: String,
    tone_hz: Option<u32>,
}

#[derive(Debug, PartialEq, Eq)]
struct SelftestCliArgs {
    server: String,
    user: String,
    password: String,
    duration_ms: u64,
}

enum AudioInspector {
    Wav(WavAudioHandle),
    Live(LiveAudioHandle),
}

impl AudioInspector {
    fn recorded_wav(&self) -> WavPcm16 {
        match self {
            Self::Wav(h) => h.recorded_wav(),
            Self::Live(h) => h.recorded_wav(),
        }
    }
}

fn print_usage() {
    println!(
        "bmsip-cli v{}\n\n\
         USAGE:\n  \
           bmsip-cli --version\n  \
           bmsip-cli --help\n  \
           bmsip-cli call --server <host:port> --user <user> --password <pass> --target <sip_uri> [OPTIONS]\n  \
           bmsip-cli listen --server <host:port> --user <user> --password <pass> [OPTIONS]\n  \
           bmsip-cli analyze --wav <path> [--tone-hz <hz>]\n  \
           bmsip-cli selftest --server <host:port> --user <user> --password <pass> [--duration-ms <ms>]\n\n\
         OPTIONS:\n  \
           --duration-ms <ms>     Active call duration in milliseconds (default: 1000 / 10000 for listen / 800 for selftest)\n  \
           --tone-hz <hz>         Generated sine tone frequency or expected tone for analyze/call (default: 440)\n  \
           --codec <name>         Preferred audio codec: opus (default, 48 kHz), pcmu, or pcma\n  \
           --mic-gain <mult>      Live microphone gain multiplier (default: 4.0)\n  \
           --live-audio           Use 48 kHz live Linux microphone/speaker via PipeWire/PulseAudio/ALSA\n  \
           --wav <path>           Input 16-bit mono WAV file for analyze subcommand\n  \
           --dtmf <digits>        Optional RFC 4733 DTMF digits to transmit after connect (call)\n  \
           --wav-in <path>        Optional 16-bit mono WAV file to transmit (call)\n  \
           --wav-out <path>       Optional path to write received RX audio WAV\n  \
           --json-report <path>   Optional path to write per-call black-box JSON telemetry",
        env!("CARGO_PKG_VERSION")
    );
}

fn next_arg_value(args: &[String], idx: &mut usize, name: &str) -> Result<String, String> {
    *idx += 1;
    args.get(*idx)
        .cloned()
        .ok_or_else(|| format!("missing value for {name}"))
}

fn parse_mic_gain(raw: &str) -> Result<f32, String> {
    let val = raw
        .parse::<f32>()
        .map_err(|_| format!("invalid --mic-gain '{raw}'"))?;
    if !val.is_finite() || val <= 0.0 {
        return Err(format!("--mic-gain must be > 0, got '{raw}'"));
    }
    Ok(val)
}

fn parse_call_args(args: &[String]) -> Result<CallCliArgs, String> {
    let mut server: Option<String> = None;
    let mut user: Option<String> = None;
    let mut password: Option<String> = None;
    let mut target: Option<String> = None;
    let mut duration_ms: u64 = 1000;
    let mut tone_hz: u32 = 440;
    let mut codec = CodecChoice::Opus;
    let mut mic_gain: f32 = 4.0;
    let mut live_audio = false;
    let mut dtmf: Option<String> = None;
    let mut wav_in: Option<String> = None;
    let mut wav_out: Option<String> = None;
    let mut json_report: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        match flag {
            "--server" => server = Some(next_arg_value(args, &mut i, "--server")?),
            "--user" => user = Some(next_arg_value(args, &mut i, "--user")?),
            "--password" => password = Some(next_arg_value(args, &mut i, "--password")?),
            "--target" => target = Some(next_arg_value(args, &mut i, "--target")?),
            "--duration-ms" => {
                let raw = next_arg_value(args, &mut i, "--duration-ms")?;
                duration_ms = raw
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --duration-ms '{raw}'"))?;
            }
            "--tone-hz" => {
                let raw = next_arg_value(args, &mut i, "--tone-hz")?;
                tone_hz = raw
                    .parse::<u32>()
                    .map_err(|_| format!("invalid --tone-hz '{raw}'"))?;
            }
            "--codec" => codec = CodecChoice::parse(&next_arg_value(args, &mut i, "--codec")?)?,
            "--mic-gain" => {
                mic_gain = parse_mic_gain(&next_arg_value(args, &mut i, "--mic-gain")?)?
            }
            "--live-audio" => live_audio = true,
            "--dtmf" => dtmf = Some(next_arg_value(args, &mut i, "--dtmf")?),
            "--wav-in" => wav_in = Some(next_arg_value(args, &mut i, "--wav-in")?),
            "--wav-out" => wav_out = Some(next_arg_value(args, &mut i, "--wav-out")?),
            "--json-report" => json_report = Some(next_arg_value(args, &mut i, "--json-report")?),
            other => return Err(format!("unknown argument '{other}'")),
        }
        i += 1;
    }

    Ok(CallCliArgs {
        server: server.ok_or_else(|| "missing --server".to_string())?,
        user: user.ok_or_else(|| "missing --user".to_string())?,
        password: password.ok_or_else(|| "missing --password".to_string())?,
        target: target.ok_or_else(|| "missing --target".to_string())?,
        duration_ms,
        tone_hz,
        codec,
        mic_gain,
        live_audio,
        dtmf,
        wav_in,
        wav_out,
        json_report,
    })
}

fn parse_listen_args(args: &[String]) -> Result<ListenCliArgs, String> {
    let mut server: Option<String> = None;
    let mut user: Option<String> = None;
    let mut password: Option<String> = None;
    let mut duration_ms: u64 = 10_000;
    let mut codec = CodecChoice::Opus;
    let mut mic_gain: f32 = 4.0;
    let mut live_audio = false;
    let mut wav_out: Option<String> = None;
    let mut json_report: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        match flag {
            "--server" => server = Some(next_arg_value(args, &mut i, "--server")?),
            "--user" => user = Some(next_arg_value(args, &mut i, "--user")?),
            "--password" => password = Some(next_arg_value(args, &mut i, "--password")?),
            "--duration-ms" => {
                let raw = next_arg_value(args, &mut i, "--duration-ms")?;
                duration_ms = raw
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --duration-ms '{raw}'"))?;
            }
            "--codec" => codec = CodecChoice::parse(&next_arg_value(args, &mut i, "--codec")?)?,
            "--mic-gain" => {
                mic_gain = parse_mic_gain(&next_arg_value(args, &mut i, "--mic-gain")?)?
            }
            "--live-audio" => live_audio = true,
            "--wav-out" => wav_out = Some(next_arg_value(args, &mut i, "--wav-out")?),
            "--json-report" => json_report = Some(next_arg_value(args, &mut i, "--json-report")?),
            other => return Err(format!("unknown argument '{other}'")),
        }
        i += 1;
    }

    Ok(ListenCliArgs {
        server: server.ok_or_else(|| "missing --server".to_string())?,
        user: user.ok_or_else(|| "missing --user".to_string())?,
        password: password.ok_or_else(|| "missing --password".to_string())?,
        duration_ms,
        codec,
        mic_gain,
        live_audio,
        wav_out,
        json_report,
    })
}

fn parse_analyze_args(args: &[String]) -> Result<AnalyzeCliArgs, String> {
    let mut wav_path: Option<String> = None;
    let mut tone_hz: Option<u32> = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--wav" => wav_path = Some(next_arg_value(args, &mut i, "--wav")?),
            "--tone-hz" => {
                let raw = next_arg_value(args, &mut i, "--tone-hz")?;
                tone_hz = Some(
                    raw.parse::<u32>()
                        .map_err(|_| format!("invalid --tone-hz '{raw}'"))?,
                );
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
        i += 1;
    }

    Ok(AnalyzeCliArgs {
        wav_path: wav_path.ok_or_else(|| "missing --wav".to_string())?,
        tone_hz,
    })
}

fn parse_selftest_args(args: &[String]) -> Result<SelftestCliArgs, String> {
    let mut server: Option<String> = None;
    let mut user: Option<String> = None;
    let mut password: Option<String> = None;
    let mut duration_ms: u64 = 800;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--server" => server = Some(next_arg_value(args, &mut i, "--server")?),
            "--user" => user = Some(next_arg_value(args, &mut i, "--user")?),
            "--password" => password = Some(next_arg_value(args, &mut i, "--password")?),
            "--duration-ms" => {
                let raw = next_arg_value(args, &mut i, "--duration-ms")?;
                duration_ms = raw
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --duration-ms '{raw}'"))?;
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
        i += 1;
    }

    Ok(SelftestCliArgs {
        server: server.ok_or_else(|| "missing --server".to_string())?,
        user: user.ok_or_else(|| "missing --user".to_string())?,
        password: password.ok_or_else(|| "missing --password".to_string())?,
        duration_ms,
    })
}

fn resolve_server_addr(server: &str) -> Result<SocketAddr, String> {
    let target = if server.contains(':') {
        server.to_string()
    } else {
        format!("{server}:5060")
    };
    target
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve '{target}': {e}"))?
        .next()
        .ok_or_else(|| format!("no socket addresses resolved for '{target}'"))
}

fn build_audio_port(
    live_audio: bool,
    mic_gain: f32,
    tx_wav: WavPcm16,
) -> (Box<dyn AudioPort>, AudioInspector) {
    if live_audio {
        let (port, handle) = LiveLinuxAudioPort::spawn_with_gain(mic_gain);
        (Box::new(port), AudioInspector::Live(handle))
    } else {
        let (port, handle) = WavAudioPort::new(tx_wav, true);
        (Box::new(port), AudioInspector::Wav(handle))
    }
}

fn register_and_wait(engine: &SipEngine) -> Result<(), String> {
    engine
        .send_command(EngineCommand::Register)
        .map_err(|e| e.to_string())?;

    let reg_deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < reg_deadline {
        if let Some(ev) = engine.recv_event_timeout(Duration::from_millis(100)) {
            match ev {
                EngineEvent::RegistrationChanged(RegistrationState::Registered { .. }) => {
                    return Ok(());
                }
                EngineEvent::RegistrationChanged(RegistrationState::Failed { reason, .. }) => {
                    return Err(format!("SIP registration failed: {reason}"));
                }
                _ => {}
            }
        }
    }
    Err("SIP registration timed out".to_string())
}

fn unregister_and_shutdown(
    engine: SipEngine,
    inspector: &AudioInspector,
    wav_out: Option<&str>,
    json_report: Option<&str>,
    black_box_json: Option<&str>,
    target_tone_hz: Option<u32>,
    quiet: bool,
) -> Result<WavPcm16, String> {
    let _ = engine.send_command(EngineCommand::Unregister);
    let unreg_deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < unreg_deadline {
        if let Some(EngineEvent::RegistrationChanged(RegistrationState::Unregistered)) =
            engine.recv_event_timeout(Duration::from_millis(100))
        {
            break;
        }
    }

    let _ = engine.shutdown();

    let rx_wav = inspector.recorded_wav();
    if !quiet {
        println!(
            "Recorded RX samples: {} (RMS energy: {})",
            rx_wav.samples.len(),
            rx_wav.rms_energy()
        );
        let report = analyzer::analyze_wav(&rx_wav, target_tone_hz);
        println!("{}", report.format_oneliner());
    }

    if let Some(path) = wav_out {
        std::fs::write(path, rx_wav.encode())
            .map_err(|e| format!("failed to write WAV '{path}': {e}"))?;
    }
    if let (Some(path), Some(json)) = (json_report, black_box_json) {
        std::fs::write(path, json)
            .map_err(|e| format!("failed to write JSON report '{path}': {e}"))?;
    }
    Ok(rx_wav)
}

#[allow(clippy::too_many_arguments)]
fn execute_outbound_session(
    server: &str,
    user: &str,
    password: &str,
    target: &str,
    duration_ms: u64,
    codec: CodecChoice,
    mic_gain: f32,
    live_audio: bool,
    dtmf_digits: &[DtmfDigit],
    tx_wav: WavPcm16,
    wav_out: Option<&str>,
    json_report: Option<&str>,
    target_tone_hz: Option<u32>,
    quiet: bool,
) -> Result<(String, WavPcm16), String> {
    let registrar_addr = resolve_server_addr(server)?;
    let server_host = server.split(':').next().unwrap_or(server);
    let registrar_uri = SipUri::parse(&format!("sip:{server}")).map_err(|e| e.to_string())?;
    let target_uri = SipUri::parse(target).map_err(|e| e.to_string())?;

    let mut ua_cfg = UaConfig::new(user, password, server_host, registrar_uri, "0.0.0.0", 0);
    ua_cfg.supported_codecs = codec.supported_codecs();
    let eng_cfg = EngineConfig::new(ua_cfg, registrar_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

    let (audio_port, inspector) = build_audio_port(live_audio, mic_gain, tx_wav);
    let engine = SipEngine::spawn(eng_cfg, audio_port).map_err(|e| e.to_string())?;
    register_and_wait(&engine)?;

    engine
        .send_command(EngineCommand::Dial { target_uri })
        .map_err(|e| e.to_string())?;

    let mut active_call_id: Option<String> = None;
    let mut established_codec: Option<String> = None;
    let call_deadline = Instant::now() + Duration::from_secs(12);

    while Instant::now() < call_deadline {
        if let Some(ev) = engine.recv_event_timeout(Duration::from_millis(100)) {
            match ev {
                EngineEvent::OutboundCallStarted { call_id } => {
                    active_call_id = Some(call_id);
                }
                EngineEvent::CallEstablished {
                    codec: neg_codec,
                    remote_rtp,
                    ..
                } => {
                    if !quiet {
                        println!("Call established: codec={neg_codec}, remote_rtp={remote_rtp}");
                    }
                    established_codec = Some(neg_codec);
                    break;
                }
                EngineEvent::CallTerminated { reason, .. } => {
                    return Err(format!("call terminated before answer: {reason}"));
                }
                _ => {}
            }
        }
    }
    let negotiated_codec =
        established_codec.ok_or_else(|| "outbound call setup timed out".to_string())?;

    let call_id = active_call_id.ok_or_else(|| "missing call_id".to_string())?;
    for &digit in dtmf_digits {
        let _ = engine.send_command(EngineCommand::SendDtmf {
            call_id: call_id.clone(),
            digit,
        });
    }

    thread::sleep(Duration::from_millis(duration_ms));
    let _ = engine.send_command(EngineCommand::Hangup {
        call_id: call_id.clone(),
    });

    let mut black_box_json: Option<String> = None;
    let bye_deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < bye_deadline {
        if let Some(EngineEvent::CallTerminated {
            call_id: cid,
            black_box_json: json,
            reason,
            ..
        }) = engine.recv_event_timeout(Duration::from_millis(100))
        {
            if cid == call_id {
                if !quiet {
                    println!("Call terminated: {reason}");
                }
                black_box_json = Some(json);
                break;
            }
        }
    }

    let rx_wav = unregister_and_shutdown(
        engine,
        &inspector,
        wav_out,
        json_report,
        black_box_json.as_deref(),
        target_tone_hz,
        quiet,
    )?;
    Ok((negotiated_codec, rx_wav))
}

fn run_call(cli: CallCliArgs) -> Result<(), String> {
    let dtmf_digits: Vec<DtmfDigit> = match &cli.dtmf {
        Some(s) => s
            .chars()
            .map(DtmfDigit::from_char)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?,
        None => Vec::new(),
    };

    let (tx_wav, target_tone) = match &cli.wav_in {
        Some(path) => {
            let bytes = std::fs::read(path).map_err(|e| format!("read '{path}': {e}"))?;
            (WavPcm16::decode(&bytes).map_err(|e| e.to_string())?, None)
        }
        None => {
            let sample_rate = if cli.codec == CodecChoice::Opus || cli.live_audio {
                48_000
            } else {
                8_000
            };
            let wav = WavPcm16::generate_sine_wave(
                sample_rate,
                cli.tone_hz,
                (cli.duration_ms + 500) as u32,
                12000,
            );
            let tone = if cli.live_audio {
                None
            } else {
                Some(cli.tone_hz)
            };
            (wav, tone)
        }
    };

    execute_outbound_session(
        &cli.server,
        &cli.user,
        &cli.password,
        &cli.target,
        cli.duration_ms,
        cli.codec,
        cli.mic_gain,
        cli.live_audio,
        &dtmf_digits,
        tx_wav,
        cli.wav_out.as_deref(),
        cli.json_report.as_deref(),
        target_tone,
        false,
    )?;
    Ok(())
}

fn run_listen(cli: ListenCliArgs) -> Result<(), String> {
    let registrar_addr = resolve_server_addr(&cli.server)?;
    let server_host = cli.server.split(':').next().unwrap_or(&cli.server);
    let registrar_uri = SipUri::parse(&format!("sip:{}", cli.server)).map_err(|e| e.to_string())?;

    let mut ua_cfg = UaConfig::new(
        cli.user,
        cli.password,
        server_host,
        registrar_uri,
        "0.0.0.0",
        0,
    );
    ua_cfg.supported_codecs = cli.codec.supported_codecs();
    let eng_cfg = EngineConfig::new(ua_cfg, registrar_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

    let (silence_rate, silence_len) = if cli.codec == CodecChoice::Opus || cli.live_audio {
        (48_000, 960)
    } else {
        (8_000, 160)
    };
    let (audio_port, inspector) = build_audio_port(
        cli.live_audio,
        cli.mic_gain,
        WavPcm16::new(silence_rate, vec![0; silence_len]),
    );
    let engine = SipEngine::spawn(eng_cfg, audio_port).map_err(|e| e.to_string())?;
    register_and_wait(&engine)?;
    println!(
        "Listening for incoming calls on {}...",
        engine.local_sip_addr()
    );

    let mut active_call_id: Option<String> = None;
    let mut hangup_at: Option<Instant> = None;
    let mut black_box_json: Option<String> = None;
    let overall_deadline = Instant::now() + Duration::from_secs(60);

    while Instant::now() < overall_deadline {
        if let Some(deadline) = hangup_at {
            if Instant::now() >= deadline {
                if let Some(cid) = active_call_id.clone() {
                    let _ = engine.send_command(EngineCommand::Hangup { call_id: cid });
                    hangup_at = None;
                }
            }
        }

        if let Some(ev) = engine.recv_event_timeout(Duration::from_millis(100)) {
            match ev {
                EngineEvent::IncomingCall { call_id, from, .. } if active_call_id.is_none() => {
                    println!("Incoming call from {from} (call_id={call_id}), answering...");
                    active_call_id = Some(call_id.clone());
                    let _ = engine.send_command(EngineCommand::Ring {
                        call_id: call_id.clone(),
                    });
                    let _ = engine.send_command(EngineCommand::Answer { call_id });
                }
                EngineEvent::CallEstablished {
                    codec, remote_rtp, ..
                } => {
                    println!("Call answered: codec={codec}, remote_rtp={remote_rtp}");
                    hangup_at = Some(Instant::now() + Duration::from_millis(cli.duration_ms));
                }
                EngineEvent::DtmfReceived { digit, .. } => {
                    println!("DTMF received: '{}'", digit.to_char());
                }
                EngineEvent::CallTerminated {
                    reason,
                    black_box_json: json,
                    ..
                } => {
                    println!("Call terminated: {reason}");
                    black_box_json = Some(json);
                    break;
                }
                _ => {}
            }
        }
    }

    unregister_and_shutdown(
        engine,
        &inspector,
        cli.wav_out.as_deref(),
        cli.json_report.as_deref(),
        black_box_json.as_deref(),
        None,
        false,
    )?;
    Ok(())
}

fn run_analyze(cli: AnalyzeCliArgs) -> Result<(), String> {
    let bytes = std::fs::read(&cli.wav_path)
        .map_err(|e| format!("failed to read '{}': {e}", cli.wav_path))?;
    let wav =
        WavPcm16::decode(&bytes).map_err(|e| format!("invalid WAV '{}': {e}", cli.wav_path))?;
    let report = analyzer::analyze_wav(&wav, cli.tone_hz);
    println!("{}", report.format_multiline());
    Ok(())
}

struct SelftestCase {
    name: &'static str,
    codec: CodecChoice,
    sample_rate_hz: u32,
    tone_hz: u32,
    amplitude: i16,
}

fn run_selftest(cli: SelftestCliArgs) -> Result<(), String> {
    const CASES: [SelftestCase; 5] = [
        SelftestCase {
            name: "PCMU-8k-440Hz",
            codec: CodecChoice::Pcmu,
            sample_rate_hz: 8_000,
            tone_hz: 440,
            amplitude: 12_000,
        },
        SelftestCase {
            name: "PCMA-8k-1000Hz",
            codec: CodecChoice::Pcma,
            sample_rate_hz: 8_000,
            tone_hz: 1_000,
            amplitude: 12_000,
        },
        SelftestCase {
            name: "OPUS-48k-440Hz",
            codec: CodecChoice::Opus,
            sample_rate_hz: 48_000,
            tone_hz: 440,
            amplitude: 12_000,
        },
        SelftestCase {
            name: "OPUS-48k-6000Hz-HD",
            codec: CodecChoice::Opus,
            sample_rate_hz: 48_000,
            tone_hz: 6_000,
            amplitude: 12_000,
        },
        SelftestCase {
            name: "OPUS-48k-Quiet",
            codec: CodecChoice::Opus,
            sample_rate_hz: 48_000,
            tone_hz: 440,
            amplitude: 1_200,
        },
    ];

    let target = format!("sip:601@{}", cli.server);
    println!(
        "{:<20} {:<6} {:<7} {:<8} {:<9} {:<9} {:<8} {:<8} {:<7} STATUS",
        "Scenario",
        "Codec",
        "Rate",
        "Latency",
        "RMS dBFS",
        "Freq Hz",
        "SNR dB",
        "Dropouts",
        "Clicks"
    );
    println!("{}", "-".repeat(102));

    let mut failed_cases = 0usize;
    for case in &CASES {
        let tx_wav = WavPcm16::generate_sine_wave(
            case.sample_rate_hz,
            case.tone_hz,
            (cli.duration_ms + 500) as u32,
            case.amplitude,
        );
        let (neg_codec, rx_wav) = execute_outbound_session(
            &cli.server,
            &cli.user,
            &cli.password,
            &target,
            cli.duration_ms,
            case.codec,
            4.0,
            false,
            &[],
            tx_wav,
            None,
            None,
            Some(case.tone_hz),
            true,
        )?;
        let report = analyzer::analyze_wav(&rx_wav, Some(case.tone_hz));
        let snr = report.snr_db.unwrap_or(0.0);
        let freq_tol = f64::from(case.tone_hz) * 0.10;
        let pass = report.active_frames > 0
            && report.mid_stream_dropouts == 0
            && (report.detected_freq_hz - f64::from(case.tone_hz)).abs() <= freq_tol
            && snr >= 12.0;
        if !pass {
            failed_cases += 1;
        }
        println!(
            "{:<20} {:<6} {:<7} {:>5} ms {:>6.1} dB {:>7.1}   {:>5.1} dB {:>8} {:>7} {}",
            case.name,
            neg_codec,
            report.sample_rate_hz,
            report.initial_latency_ms,
            report.rms_dbfs,
            report.detected_freq_hz,
            snr,
            report.mid_stream_dropouts,
            report.boundary_clicks,
            if pass { "PASS" } else { "FAIL" }
        );
    }

    if failed_cases > 0 {
        return Err(format!("{failed_cases} audio selftest scenario(s) failed"));
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h") {
        print_usage();
        return ExitCode::SUCCESS;
    }
    if matches!(args[0].as_str(), "--version" | "-V") {
        println!("bmsip-cli {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }

    let res = match args[0].as_str() {
        "call" => parse_call_args(&args[1..]).and_then(run_call),
        "listen" => parse_listen_args(&args[1..]).and_then(run_listen),
        "analyze" => parse_analyze_args(&args[1..]).and_then(run_analyze),
        "selftest" => parse_selftest_args(&args[1..]).and_then(run_selftest),
        other => {
            eprintln!("unknown subcommand '{other}'\n");
            print_usage();
            return ExitCode::FAILURE;
        }
    };

    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vec_str(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn parses_call_args_including_live_audio_codec_and_gain() {
        let args = vec_str(&[
            "--server",
            "asterisk:5060",
            "--user",
            "1001",
            "--password",
            "secret1001",
            "--target",
            "sip:601@asterisk:5060",
            "--duration-ms",
            "500",
            "--codec",
            "pcmu",
            "--mic-gain",
            "2.5",
            "--live-audio",
        ]);
        let parsed = parse_call_args(&args).unwrap();
        assert_eq!(parsed.server, "asterisk:5060");
        assert_eq!(parsed.user, "1001");
        assert_eq!(parsed.duration_ms, 500);
        assert_eq!(parsed.codec, CodecChoice::Pcmu);
        assert_eq!(parsed.mic_gain, 2.5);
        assert!(parsed.live_audio);
    }

    #[test]
    fn parses_listen_args() {
        let args = vec_str(&[
            "--server",
            "asterisk:5060",
            "--user",
            "1002",
            "--password",
            "secret1002",
            "--live-audio",
            "--wav-out",
            "/tmp/rx.wav",
        ]);
        let parsed = parse_listen_args(&args).unwrap();
        assert_eq!(parsed.user, "1002");
        assert_eq!(parsed.duration_ms, 10_000);
        assert_eq!(parsed.codec, CodecChoice::Opus);
        assert_eq!(parsed.mic_gain, 4.0);
        assert!(parsed.live_audio);
        assert_eq!(parsed.wav_out.as_deref(), Some("/tmp/rx.wav"));
    }

    #[test]
    fn parses_analyze_and_selftest_args() {
        let a =
            parse_analyze_args(&vec_str(&["--wav", "/tmp/rx.wav", "--tone-hz", "440"])).unwrap();
        assert_eq!(a.wav_path, "/tmp/rx.wav");
        assert_eq!(a.tone_hz, Some(440));

        let s = parse_selftest_args(&vec_str(&[
            "--server",
            "asterisk:5060",
            "--user",
            "1001",
            "--password",
            "secret1001",
            "--duration-ms",
            "600",
        ]))
        .unwrap();
        assert_eq!(s.server, "asterisk:5060");
        assert_eq!(s.duration_ms, 600);
    }
}
