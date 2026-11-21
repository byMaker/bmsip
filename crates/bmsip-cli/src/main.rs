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
use bmsip_engine::bmsip_core::sip::{SipTransport, SipUri};
use bmsip_engine::bmsip_media::{DtmfDigit, WavPcm16};
use bmsip_engine::{
    AudioPort, EngineCommand, EngineConfig, EngineEvent, SipEngine, TlsConfig, WavAudioHandle,
    WavAudioPort,
};
use live_audio::{LiveAudioHandle, LiveLinuxAudioPort};

fn parse_transport_arg(raw: &str) -> Result<SipTransport, String> {
    match raw.to_ascii_lowercase().as_str() {
        "udp" => Ok(SipTransport::Udp),
        "tcp" => Ok(SipTransport::Tcp),
        "tls" => Ok(SipTransport::Tls),
        _ => Err(format!(
            "unsupported --transport '{raw}' (expected udp, tcp, or tls)"
        )),
    }
}

fn build_tls_config(
    tls_ca: Option<&str>,
    tls_server_name: Option<&str>,
    tls_insecure: bool,
) -> Result<TlsConfig, String> {
    let ca_cert_pem = match tls_ca {
        Some(path) => Some(
            std::fs::read_to_string(path)
                .map_err(|e| format!("failed to read --tls-ca '{path}': {e}"))?,
        ),
        None => None,
    };
    Ok(TlsConfig {
        ca_cert_pem,
        server_name: tls_server_name.map(str::to_string),
        accept_invalid_certs: tls_insecure,
        ..TlsConfig::default()
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DtmfMode {
    Rfc4733,
    Info,
}

impl DtmfMode {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.to_ascii_lowercase().as_str() {
            "rfc4733" => Ok(Self::Rfc4733),
            "info" => Ok(Self::Info),
            _ => Err(format!(
                "unsupported --dtmf-mode '{raw}' (expected rfc4733 or info)"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CodecChoice {
    Opus,
    G722,
    Pcmu,
    Pcma,
}

impl CodecChoice {
    fn parse(raw: &str) -> Result<Self, String> {
        match raw.to_ascii_lowercase().as_str() {
            "opus" => Ok(Self::Opus),
            "g722" => Ok(Self::G722),
            "pcmu" => Ok(Self::Pcmu),
            "pcma" => Ok(Self::Pcma),
            _ => Err(format!(
                "unsupported --codec '{raw}' (expected opus, g722, pcmu, or pcma)"
            )),
        }
    }

    fn default_wav_sample_rate_hz(self) -> u32 {
        match self {
            Self::Opus => 48_000,
            Self::G722 => 16_000,
            Self::Pcmu | Self::Pcma => 8_000,
        }
    }

    fn supported_codecs(self) -> Vec<RtpCodec> {
        match self {
            Self::Opus => vec![
                RtpCodec::opus(),
                RtpCodec::g722(),
                RtpCodec::pcmu(),
                RtpCodec::pcma(),
                RtpCodec::cn(),
                RtpCodec::telephone_event_48k(102),
                RtpCodec::telephone_event(101),
            ],
            Self::G722 => vec![
                RtpCodec::g722(),
                RtpCodec::pcmu(),
                RtpCodec::pcma(),
                RtpCodec::cn(),
                RtpCodec::telephone_event(101),
            ],
            Self::Pcmu => vec![
                RtpCodec::pcmu(),
                RtpCodec::pcma(),
                RtpCodec::cn(),
                RtpCodec::telephone_event(101),
            ],
            Self::Pcma => vec![
                RtpCodec::pcma(),
                RtpCodec::pcmu(),
                RtpCodec::cn(),
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
    transport: SipTransport,
    tls_ca: Option<String>,
    tls_server_name: Option<String>,
    tls_insecure: bool,
    duration_ms: u64,
    tone_hz: u32,
    codec: CodecChoice,
    mic_gain: f32,
    live_audio: bool,
    dtmf: Option<String>,
    dtmf_mode: DtmfMode,
    hold_ms: Option<u64>,
    transfer: Option<String>,
    wav_in: Option<String>,
    wav_out: Option<String>,
    json_report: Option<String>,
}

#[derive(Debug, PartialEq)]
struct ListenCliArgs {
    server: String,
    user: String,
    password: String,
    transport: SipTransport,
    tls_ca: Option<String>,
    tls_server_name: Option<String>,
    tls_insecure: bool,
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

#[derive(Debug, PartialEq, Eq)]
struct InteropCliArgs {
    asterisk: String,
    freeswitch: String,
    kamailio: String,
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
           bmsip-cli selftest --server <host:port> --user <user> --password <pass> [--duration-ms <ms>]\n  \
           bmsip-cli interop [--asterisk <host:port>] [--freeswitch <host:port>] [--kamailio <host:port>] [--duration-ms <ms>]\n\n\
         OPTIONS:\n  \
           --transport <proto>    SIP signaling transport: udp (default), tcp, or tls\n  \
           --tls-ca <path>        PEM CA certificate bundle for TLS server verification\n  \
           --tls-server-name <hn> Explicit TLS SNI / certificate hostname override\n  \
           --tls-insecure         Disable TLS certificate verification (lab/self-signed servers only)\n  \
           --duration-ms <ms>     Active call duration in milliseconds (default: 1000 / 10000 listen / 800 selftest / 500 interop)\n  \
           --tone-hz <hz>         Generated sine tone frequency or expected tone for analyze/call (default: 440)\n  \
           --codec <name>         Preferred audio codec: opus (default, 48 kHz), g722 (16 kHz HD), pcmu, or pcma\n  \
           --mic-gain <mult>      Live microphone gain multiplier (default: 4.0)\n  \
           --live-audio           Use 48 kHz live Linux microphone/speaker via PipeWire/PulseAudio/ALSA\n  \
           --wav <path>           Input 16-bit mono WAV file for analyze subcommand\n  \
           --dtmf <digits>        Optional DTMF digits to transmit after connect (call)\n  \
           --dtmf-mode <mode>     DTMF transport mode: rfc4733 (default) or info (SIP INFO)\n  \
           --hold-ms <ms>         Optional mid-call hold duration before resuming (call)\n  \
           --transfer <sip_uri>   Optional blind REFER transfer target prior to hangup (call)\n  \
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
    let mut transport = SipTransport::Udp;
    let mut tls_ca: Option<String> = None;
    let mut tls_server_name: Option<String> = None;
    let mut tls_insecure = false;
    let mut duration_ms: u64 = 1000;
    let mut tone_hz: u32 = 440;
    let mut codec = CodecChoice::Opus;
    let mut mic_gain: f32 = 4.0;
    let mut live_audio = false;
    let mut dtmf: Option<String> = None;
    let mut dtmf_mode = DtmfMode::Rfc4733;
    let mut hold_ms: Option<u64> = None;
    let mut transfer: Option<String> = None;
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
            "--transport" => {
                transport = parse_transport_arg(&next_arg_value(args, &mut i, "--transport")?)?
            }
            "--tls-ca" => tls_ca = Some(next_arg_value(args, &mut i, "--tls-ca")?),
            "--tls-server-name" => {
                tls_server_name = Some(next_arg_value(args, &mut i, "--tls-server-name")?)
            }
            "--tls-insecure" => tls_insecure = true,
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
            "--dtmf-mode" => {
                dtmf_mode = DtmfMode::parse(&next_arg_value(args, &mut i, "--dtmf-mode")?)?
            }
            "--hold-ms" => {
                let raw = next_arg_value(args, &mut i, "--hold-ms")?;
                hold_ms = Some(
                    raw.parse::<u64>()
                        .map_err(|_| format!("invalid --hold-ms '{raw}'"))?,
                );
            }
            "--transfer" => transfer = Some(next_arg_value(args, &mut i, "--transfer")?),
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
        transport,
        tls_ca,
        tls_server_name,
        tls_insecure,
        duration_ms,
        tone_hz,
        codec,
        mic_gain,
        live_audio,
        dtmf,
        dtmf_mode,
        hold_ms,
        transfer,
        wav_in,
        wav_out,
        json_report,
    })
}

fn parse_listen_args(args: &[String]) -> Result<ListenCliArgs, String> {
    let mut server: Option<String> = None;
    let mut user: Option<String> = None;
    let mut password: Option<String> = None;
    let mut transport = SipTransport::Udp;
    let mut tls_ca: Option<String> = None;
    let mut tls_server_name: Option<String> = None;
    let mut tls_insecure = false;
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
            "--transport" => {
                transport = parse_transport_arg(&next_arg_value(args, &mut i, "--transport")?)?
            }
            "--tls-ca" => tls_ca = Some(next_arg_value(args, &mut i, "--tls-ca")?),
            "--tls-server-name" => {
                tls_server_name = Some(next_arg_value(args, &mut i, "--tls-server-name")?)
            }
            "--tls-insecure" => tls_insecure = true,
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
        transport,
        tls_ca,
        tls_server_name,
        tls_insecure,
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

fn parse_interop_args(args: &[String]) -> Result<InteropCliArgs, String> {
    let mut asterisk = "asterisk:5060".to_string();
    let mut freeswitch = "freeswitch:5060".to_string();
    let mut kamailio = "kamailio:5060".to_string();
    let mut duration_ms: u64 = 500;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--asterisk" => asterisk = next_arg_value(args, &mut i, "--asterisk")?,
            "--freeswitch" => freeswitch = next_arg_value(args, &mut i, "--freeswitch")?,
            "--kamailio" => kamailio = next_arg_value(args, &mut i, "--kamailio")?,
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

    Ok(InteropCliArgs {
        asterisk,
        freeswitch,
        kamailio,
        duration_ms,
    })
}

fn resolve_server_addr(server: &str, transport: SipTransport) -> Result<SocketAddr, String> {
    let target = if server.contains(':') {
        server.to_string()
    } else {
        format!("{server}:{}", transport.default_port())
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
    record_rx: bool,
) -> (Box<dyn AudioPort>, AudioInspector) {
    if live_audio {
        let (port, handle) = LiveLinuxAudioPort::spawn_with_options(mic_gain, record_rx);
        (Box::new(port), AudioInspector::Live(handle))
    } else {
        let (port, handle) = WavAudioPort::new_with_recording(tx_wav, true, record_rx);
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
        if rx_wav.samples.is_empty() && wav_out.is_none() {
            println!("RX WAV recording disabled for live audio (pass --wav-out to record)");
        } else {
            println!(
                "Recorded RX samples: {} (RMS energy: {})",
                rx_wav.samples.len(),
                rx_wav.rms_energy()
            );
            let report = analyzer::analyze_wav(&rx_wav, target_tone_hz);
            println!("{}", report.format_oneliner());
        }
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
    transport: SipTransport,
    tls_config: TlsConfig,
    duration_ms: u64,
    codec: CodecChoice,
    mic_gain: f32,
    live_audio: bool,
    dtmf_digits: &[DtmfDigit],
    dtmf_mode: DtmfMode,
    hold_ms: Option<u64>,
    transfer_target: Option<&SipUri>,
    tx_wav: WavPcm16,
    wav_out: Option<&str>,
    json_report: Option<&str>,
    target_tone_hz: Option<u32>,
    quiet: bool,
) -> Result<(String, WavPcm16), String> {
    let registrar_addr = resolve_server_addr(server, transport)?;
    let server_host = server.split(':').next().unwrap_or(server);
    let registrar_uri = SipUri::parse(&format!("sip:{server}")).map_err(|e| e.to_string())?;
    let target_uri = SipUri::parse(target).map_err(|e| e.to_string())?;

    let mut ua_cfg = UaConfig::new(user, password, server_host, registrar_uri, "0.0.0.0", 0)
        .with_transport(transport);
    ua_cfg.supported_codecs = codec.supported_codecs();
    let eng_cfg = EngineConfig::new(ua_cfg, registrar_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        .with_tls_config(tls_config);

    let record_rx = !live_audio || wav_out.is_some();
    let (audio_port, inspector) = build_audio_port(live_audio, mic_gain, tx_wav, record_rx);
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
                EngineEvent::EarlyMediaStarted {
                    codec: neg_codec,
                    remote_rtp,
                    ..
                } => {
                    if !quiet {
                        println!("Early media started: codec={neg_codec}, remote_rtp={remote_rtp}");
                    }
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
        let cmd = match dtmf_mode {
            DtmfMode::Rfc4733 => EngineCommand::SendDtmf {
                call_id: call_id.clone(),
                digit,
            },
            DtmfMode::Info => EngineCommand::SendInfoDtmf {
                call_id: call_id.clone(),
                digit,
                duration_ms: 160,
            },
        };
        let _ = engine.send_command(cmd);
    }

    if let Some(hms) = hold_ms {
        let pre_ms = (duration_ms / 2).max(100);
        thread::sleep(Duration::from_millis(pre_ms));
        let _ = engine.send_command(EngineCommand::Hold {
            call_id: call_id.clone(),
        });
        thread::sleep(Duration::from_millis(hms));
        let _ = engine.send_command(EngineCommand::ResumeCall {
            call_id: call_id.clone(),
        });
        let rem_ms = duration_ms.saturating_sub(pre_ms);
        if rem_ms > 0 {
            thread::sleep(Duration::from_millis(rem_ms));
        }
    } else {
        thread::sleep(Duration::from_millis(duration_ms));
    }

    if let Some(target_uri) = transfer_target {
        let _ = engine.send_command(EngineCommand::Transfer {
            call_id: call_id.clone(),
            target_uri: target_uri.clone(),
        });
        thread::sleep(Duration::from_millis(150));
    }
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
            let sample_rate = if cli.live_audio {
                48_000
            } else {
                cli.codec.default_wav_sample_rate_hz()
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

    let transfer_uri = match &cli.transfer {
        Some(raw) => {
            Some(SipUri::parse(raw).map_err(|e| format!("invalid --transfer '{raw}': {e}"))?)
        }
        None => None,
    };

    let tls_config = build_tls_config(
        cli.tls_ca.as_deref(),
        cli.tls_server_name.as_deref(),
        cli.tls_insecure,
    )?;

    execute_outbound_session(
        &cli.server,
        &cli.user,
        &cli.password,
        &cli.target,
        cli.transport,
        tls_config,
        cli.duration_ms,
        cli.codec,
        cli.mic_gain,
        cli.live_audio,
        &dtmf_digits,
        cli.dtmf_mode,
        cli.hold_ms,
        transfer_uri.as_ref(),
        tx_wav,
        cli.wav_out.as_deref(),
        cli.json_report.as_deref(),
        target_tone,
        false,
    )?;
    Ok(())
}

fn run_listen(cli: ListenCliArgs) -> Result<(), String> {
    let tls_config = build_tls_config(
        cli.tls_ca.as_deref(),
        cli.tls_server_name.as_deref(),
        cli.tls_insecure,
    )?;
    let registrar_addr = resolve_server_addr(&cli.server, cli.transport)?;
    let server_host = cli.server.split(':').next().unwrap_or(&cli.server);
    let registrar_uri = SipUri::parse(&format!("sip:{}", cli.server)).map_err(|e| e.to_string())?;

    let mut ua_cfg = UaConfig::new(
        cli.user,
        cli.password,
        server_host,
        registrar_uri,
        "0.0.0.0",
        0,
    )
    .with_transport(cli.transport);
    ua_cfg.supported_codecs = cli.codec.supported_codecs();
    let eng_cfg = EngineConfig::new(ua_cfg, registrar_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        .with_tls_config(tls_config);

    let silence_rate = if cli.live_audio {
        48_000
    } else {
        cli.codec.default_wav_sample_rate_hz()
    };
    let silence_len = (silence_rate / 50) as usize;
    let record_rx = !cli.live_audio || cli.wav_out.is_some();
    let (audio_port, inspector) = build_audio_port(
        cli.live_audio,
        cli.mic_gain,
        WavPcm16::new(silence_rate, vec![0; silence_len]),
        record_rx,
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
    const CASES: [SelftestCase; 7] = [
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
            name: "G722-16k-440Hz",
            codec: CodecChoice::G722,
            sample_rate_hz: 16_000,
            tone_hz: 440,
            amplitude: 12_000,
        },
        SelftestCase {
            name: "G722-16k-3000Hz-WB",
            codec: CodecChoice::G722,
            sample_rate_hz: 16_000,
            tone_hz: 3_000,
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
            SipTransport::Udp,
            TlsConfig::default(),
            cli.duration_ms,
            case.codec,
            4.0,
            false,
            &[],
            DtmfMode::Rfc4733,
            None,
            None,
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

fn execute_two_party_session(
    server: &str,
    codec: CodecChoice,
    duration_ms: u64,
    tone_hz: u32,
) -> Result<(String, Option<DtmfDigit>, WavPcm16), String> {
    let registrar_addr = resolve_server_addr(server, SipTransport::Udp)?;
    let server_host = server.split(':').next().unwrap_or(server);
    let registrar_uri = SipUri::parse(&format!("sip:{server}")).map_err(|e| e.to_string())?;
    let rate = codec.default_wav_sample_rate_hz();
    let frame_len = (rate / 50) as usize;

    let mut cfg_1001 = UaConfig::new(
        "1001",
        "secret1001",
        server_host,
        registrar_uri.clone(),
        "0.0.0.0",
        0,
    );
    cfg_1001.supported_codecs = codec.supported_codecs();
    let tone = WavPcm16::generate_sine_wave(rate, tone_hz, (duration_ms + 800) as u32, 12_000);
    let (port_1001, _) = WavAudioPort::new(tone, true);
    let eng_1001 = SipEngine::spawn(
        EngineConfig::new(
            cfg_1001,
            registrar_addr,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
        ),
        Box::new(port_1001),
    )
    .map_err(|e| e.to_string())?;

    let mut cfg_1002 = UaConfig::new(
        "1002",
        "secret1002",
        server_host,
        registrar_uri,
        "0.0.0.0",
        0,
    );
    cfg_1002.supported_codecs = codec.supported_codecs();
    let (port_1002, handle_1002) = WavAudioPort::new(WavPcm16::new(rate, vec![0; frame_len]), true);
    let eng_1002 = SipEngine::spawn(
        EngineConfig::new(
            cfg_1002,
            registrar_addr,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
        ),
        Box::new(port_1002),
    )
    .map_err(|e| e.to_string())?;

    register_and_wait(&eng_1001)?;
    register_and_wait(&eng_1002)?;

    let target_uri = SipUri::parse(&format!("sip:1002@{server}")).map_err(|e| e.to_string())?;
    eng_1001
        .send_command(EngineCommand::Dial { target_uri })
        .map_err(|e| e.to_string())?;

    let mut cid_1001: Option<String> = None;
    let mut cid_1002: Option<String> = None;
    let mut neg_codec: Option<String> = None;
    let mut est_1002 = false;
    let deadline = Instant::now() + Duration::from_secs(12);

    while Instant::now() < deadline && (neg_codec.is_none() || !est_1002) {
        if let Some(ev) = eng_1001.recv_event_timeout(Duration::from_millis(20)) {
            match ev {
                EngineEvent::OutboundCallStarted { call_id } => cid_1001 = Some(call_id),
                EngineEvent::CallEstablished { codec, .. } => neg_codec = Some(codec),
                EngineEvent::CallTerminated { reason, .. } => {
                    return Err(format!("1001 call failed early: {reason}"));
                }
                _ => {}
            }
        }
        if let Some(ev) = eng_1002.recv_event_timeout(Duration::from_millis(20)) {
            match ev {
                EngineEvent::IncomingCall { call_id, .. } if cid_1002.is_none() => {
                    cid_1002 = Some(call_id.clone());
                    let _ = eng_1002.send_command(EngineCommand::Ring {
                        call_id: call_id.clone(),
                    });
                    let _ = eng_1002.send_command(EngineCommand::Answer { call_id });
                }
                EngineEvent::CallEstablished { .. } => est_1002 = true,
                _ => {}
            }
        }
    }

    let established_codec =
        neg_codec.ok_or_else(|| "two-party call setup timed out on caller".to_string())?;
    if !est_1002 {
        return Err("two-party call setup timed out on callee".to_string());
    }
    let call_1001 = cid_1001.ok_or_else(|| "missing caller call_id".to_string())?;

    let mut received_dtmf: Option<DtmfDigit> = None;
    let warmup_until = Instant::now() + Duration::from_millis(100);
    while Instant::now() < warmup_until {
        if let Some(EngineEvent::DtmfReceived { digit, .. }) =
            eng_1002.recv_event_timeout(Duration::from_millis(20))
        {
            received_dtmf = Some(digit);
        }
    }

    let _ = eng_1001.send_command(EngineCommand::SendDtmf {
        call_id: call_1001.clone(),
        digit: DtmfDigit::D5,
    });

    let talk_until = Instant::now() + Duration::from_millis(duration_ms);
    while Instant::now() < talk_until {
        if let Some(EngineEvent::DtmfReceived { digit, .. }) =
            eng_1002.recv_event_timeout(Duration::from_millis(25))
        {
            received_dtmf = Some(digit);
        }
    }

    let _ = eng_1001.send_command(EngineCommand::Hangup { call_id: call_1001 });
    let mut term_1 = false;
    let mut term_2 = false;
    let bye_dl = Instant::now() + Duration::from_secs(6);
    while Instant::now() < bye_dl && !(term_1 && term_2) {
        if let Some(ev) = eng_1001.recv_event_timeout(Duration::from_millis(25)) {
            if matches!(ev, EngineEvent::CallTerminated { .. }) {
                term_1 = true;
            }
        }
        if let Some(ev) = eng_1002.recv_event_timeout(Duration::from_millis(25)) {
            match ev {
                EngineEvent::DtmfReceived { digit, .. } => received_dtmf = Some(digit),
                EngineEvent::CallTerminated { .. } => term_2 = true,
                _ => {}
            }
        }
    }

    for eng in [&eng_1001, &eng_1002] {
        let _ = eng.send_command(EngineCommand::Unregister);
        let unreg_dl = Instant::now() + Duration::from_secs(3);
        while Instant::now() < unreg_dl {
            if let Some(EngineEvent::RegistrationChanged(RegistrationState::Unregistered)) =
                eng.recv_event_timeout(Duration::from_millis(50))
            {
                break;
            }
        }
    }
    let _ = eng_1001.shutdown();
    let _ = eng_1002.shutdown();

    Ok((established_codec, received_dtmf, handle_1002.recorded_wav()))
}

enum InteropKind {
    Echo {
        codec: CodecChoice,
        rate: u32,
        tone_hz: u32,
    },
    TwoParty {
        codec: CodecChoice,
        tone_hz: u32,
    },
}

struct InteropSpec<'a> {
    server_label: &'a str,
    engine_label: &'a str,
    scenario: &'a str,
    server_addr: &'a str,
    kind: InteropKind,
}

fn evaluate_interop_pass(
    report: &analyzer::AudioQualityReport,
    target_hz: u32,
    dtmf: Option<DtmfDigit>,
    expect_dtmf: bool,
) -> bool {
    let freq_ok =
        (report.detected_freq_hz - f64::from(target_hz)).abs() <= f64::from(target_hz) * 0.12;
    let min_snr = if target_hz >= 4_000 { 9.5 } else { 12.0 };
    let snr_ok = report.snr_db.unwrap_or(0.0) >= min_snr;
    let audio_ok = report.active_frames > 0 && report.mid_stream_dropouts == 0 && freq_ok && snr_ok;
    let dtmf_ok = !expect_dtmf || dtmf == Some(DtmfDigit::D5);
    audio_ok && dtmf_ok
}

fn run_interop(cli: InteropCliArgs) -> Result<(), String> {
    let specs = [
        InteropSpec {
            server_label: "Asterisk",
            engine_label: "PJSIP",
            scenario: "Echo-PCMU-8k-440Hz",
            server_addr: &cli.asterisk,
            kind: InteropKind::Echo {
                codec: CodecChoice::Pcmu,
                rate: 8_000,
                tone_hz: 440,
            },
        },
        InteropSpec {
            server_label: "Asterisk",
            engine_label: "PJSIP",
            scenario: "Echo-G722-16k-3000Hz",
            server_addr: &cli.asterisk,
            kind: InteropKind::Echo {
                codec: CodecChoice::G722,
                rate: 16_000,
                tone_hz: 3_000,
            },
        },
        InteropSpec {
            server_label: "Asterisk",
            engine_label: "PJSIP",
            scenario: "Echo-OPUS-48k-440Hz",
            server_addr: &cli.asterisk,
            kind: InteropKind::Echo {
                codec: CodecChoice::Opus,
                rate: 48_000,
                tone_hz: 440,
            },
        },
        InteropSpec {
            server_label: "Asterisk",
            engine_label: "PJSIP",
            scenario: "Echo-OPUS-48k-6000Hz",
            server_addr: &cli.asterisk,
            kind: InteropKind::Echo {
                codec: CodecChoice::Opus,
                rate: 48_000,
                tone_hz: 6_000,
            },
        },
        InteropSpec {
            server_label: "Asterisk",
            engine_label: "PJSIP",
            scenario: "Call-1001->1002-DTMF",
            server_addr: &cli.asterisk,
            kind: InteropKind::TwoParty {
                codec: CodecChoice::Opus,
                tone_hz: 440,
            },
        },
        InteropSpec {
            server_label: "FreeSWITCH",
            engine_label: "Sofia-SIP",
            scenario: "Echo-PCMU-8k-440Hz",
            server_addr: &cli.freeswitch,
            kind: InteropKind::Echo {
                codec: CodecChoice::Pcmu,
                rate: 8_000,
                tone_hz: 440,
            },
        },
        InteropSpec {
            server_label: "FreeSWITCH",
            engine_label: "Sofia-SIP",
            scenario: "Echo-G722-16k-3000Hz",
            server_addr: &cli.freeswitch,
            kind: InteropKind::Echo {
                codec: CodecChoice::G722,
                rate: 16_000,
                tone_hz: 3_000,
            },
        },
        InteropSpec {
            server_label: "FreeSWITCH",
            engine_label: "Sofia-SIP",
            scenario: "Echo-OPUS-48k-440Hz",
            server_addr: &cli.freeswitch,
            kind: InteropKind::Echo {
                codec: CodecChoice::Opus,
                rate: 48_000,
                tone_hz: 440,
            },
        },
        InteropSpec {
            server_label: "FreeSWITCH",
            engine_label: "Sofia-SIP",
            scenario: "Echo-OPUS-48k-6000Hz",
            server_addr: &cli.freeswitch,
            kind: InteropKind::Echo {
                codec: CodecChoice::Opus,
                rate: 48_000,
                tone_hz: 6_000,
            },
        },
        InteropSpec {
            server_label: "FreeSWITCH",
            engine_label: "Sofia-SIP",
            scenario: "Call-1001->1002-DTMF",
            server_addr: &cli.freeswitch,
            kind: InteropKind::TwoParty {
                codec: CodecChoice::Opus,
                tone_hz: 440,
            },
        },
        InteropSpec {
            server_label: "Kamailio",
            engine_label: "SIP-Proxy",
            scenario: "Proxy-G722-1001->1002",
            server_addr: &cli.kamailio,
            kind: InteropKind::TwoParty {
                codec: CodecChoice::G722,
                tone_hz: 440,
            },
        },
        InteropSpec {
            server_label: "Kamailio",
            engine_label: "SIP-Proxy",
            scenario: "Proxy-P2P-1001->1002",
            server_addr: &cli.kamailio,
            kind: InteropKind::TwoParty {
                codec: CodecChoice::Opus,
                tone_hz: 440,
            },
        },
    ];

    println!(
        "{:<11} {:<10} {:<21} {:<6} {:<6} {:<9} {:<8} {:<8} {:<5} STATUS",
        "Server", "Engine", "Scenario", "Codec", "Rate", "RMS dBFS", "Freq Hz", "SNR dB", "DTMF"
    );
    println!("{}", "-".repeat(100));

    let mut failed = 0usize;
    for spec in &specs {
        let (neg_codec, rx_wav, tone_hz, dtmf, expect_dtmf) = match spec.kind {
            InteropKind::Echo {
                codec,
                rate,
                tone_hz,
            } => {
                let target = format!("sip:601@{}", spec.server_addr);
                let tx_wav = WavPcm16::generate_sine_wave(
                    rate,
                    tone_hz,
                    (cli.duration_ms + 500) as u32,
                    12_000,
                );
                let (c, wav) = execute_outbound_session(
                    spec.server_addr,
                    "1001",
                    "secret1001",
                    &target,
                    SipTransport::Udp,
                    TlsConfig::default(),
                    cli.duration_ms,
                    codec,
                    4.0,
                    false,
                    &[],
                    DtmfMode::Rfc4733,
                    None,
                    None,
                    tx_wav,
                    None,
                    None,
                    Some(tone_hz),
                    true,
                )?;
                (c, wav, tone_hz, None, false)
            }
            InteropKind::TwoParty { codec, tone_hz } => {
                let (c, d, wav) =
                    execute_two_party_session(spec.server_addr, codec, cli.duration_ms, tone_hz)?;
                (c, wav, tone_hz, d, true)
            }
        };

        let report = analyzer::analyze_wav(&rx_wav, Some(tone_hz));
        let snr = report.snr_db.unwrap_or(0.0);
        let pass = evaluate_interop_pass(&report, tone_hz, dtmf, expect_dtmf);
        if !pass {
            failed += 1;
        }
        let dtmf_str = if !expect_dtmf {
            "-".to_string()
        } else {
            dtmf.map_or_else(|| "none".to_string(), |d| d.to_char().to_string())
        };
        println!(
            "{:<11} {:<10} {:<21} {:<6} {:<6} {:>6.1} dB {:>7.1}  {:>5.1} dB {:<5} {}",
            spec.server_label,
            spec.engine_label,
            spec.scenario,
            neg_codec,
            report.sample_rate_hz,
            report.rms_dbfs,
            report.detected_freq_hz,
            snr,
            dtmf_str,
            if pass { "PASS" } else { "FAIL" }
        );
    }

    if failed > 0 {
        return Err(format!("{failed} interop scenario(s) failed"));
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
        "interop" => parse_interop_args(&args[1..]).and_then(run_interop),
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
            "--hold-ms",
            "250",
            "--dtmf-mode",
            "info",
            "--transfer",
            "sip:1002@asterisk:5060",
            "--transport",
            "tls",
            "--tls-ca",
            "/etc/ssl/ca.pem",
            "--tls-server-name",
            "asterisk",
            "--tls-insecure",
        ]);
        let parsed = parse_call_args(&args).unwrap();
        assert_eq!(parsed.server, "asterisk:5060");
        assert_eq!(parsed.user, "1001");
        assert_eq!(parsed.transport, SipTransport::Tls);
        assert_eq!(parsed.tls_ca.as_deref(), Some("/etc/ssl/ca.pem"));
        assert_eq!(parsed.tls_server_name.as_deref(), Some("asterisk"));
        assert!(parsed.tls_insecure);
        assert_eq!(parsed.duration_ms, 500);
        assert_eq!(parsed.codec, CodecChoice::Pcmu);
        assert_eq!(CodecChoice::parse("g722").unwrap(), CodecChoice::G722);
        assert_eq!(CodecChoice::G722.default_wav_sample_rate_hz(), 16_000);
        assert_eq!(parsed.mic_gain, 2.5);
        assert!(parsed.live_audio);
        assert_eq!(parsed.dtmf_mode, DtmfMode::Info);
        assert_eq!(parsed.hold_ms, Some(250));
        assert_eq!(parsed.transfer.as_deref(), Some("sip:1002@asterisk:5060"));
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

        let interop = parse_interop_args(&vec_str(&[
            "--freeswitch",
            "fs.local:5060",
            "--duration-ms",
            "450",
        ]))
        .unwrap();
        assert_eq!(interop.asterisk, "asterisk:5060");
        assert_eq!(interop.freeswitch, "fs.local:5060");
        assert_eq!(interop.kamailio, "kamailio:5060");
        assert_eq!(interop.duration_ms, 450);
    }
}
