#![forbid(unsafe_code)]

//! MODULE_CONTRACT: Linux CLI SIP endpoint (`bmsip-cli`) built on `bmsip-engine` supporting `call` and `listen` with WAV or live PipeWire/ALSA audio.
//! INVARIANTS: `#![forbid(unsafe_code)]`; uses only `bmsip-engine` public API; zero `.unwrap()`/`.expect()` outside tests; explicit exit codes (`0` success, `1` failure).
//! RFC_REFS: RFC 3261, RFC 3550, RFC 4733.

mod live_audio;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use bmsip_engine::bmsip_core::dialog::{RegistrationState, UaConfig};
use bmsip_engine::bmsip_core::sip::SipUri;
use bmsip_engine::bmsip_media::{DtmfDigit, WavPcm16};
use bmsip_engine::{
    AudioPort, EngineCommand, EngineConfig, EngineEvent, SipEngine, WavAudioHandle, WavAudioPort,
};
use live_audio::{LiveAudioHandle, LiveLinuxAudioPort};

#[derive(Debug, PartialEq, Eq)]
struct CallCliArgs {
    server: String,
    user: String,
    password: String,
    target: String,
    duration_ms: u64,
    tone_hz: u32,
    live_audio: bool,
    dtmf: Option<String>,
    wav_in: Option<String>,
    wav_out: Option<String>,
    json_report: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
struct ListenCliArgs {
    server: String,
    user: String,
    password: String,
    duration_ms: u64,
    live_audio: bool,
    wav_out: Option<String>,
    json_report: Option<String>,
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
           bmsip-cli listen --server <host:port> --user <user> --password <pass> [OPTIONS]\n\n\
         OPTIONS:\n  \
           --duration-ms <ms>     Active call duration in milliseconds (default: 1000 / 10000 for listen)\n  \
           --tone-hz <hz>         Generated sine tone frequency if --wav-in/--live-audio omitted (default: 440)\n  \
           --live-audio           Use live Linux microphone/speaker via PipeWire/PulseAudio/ALSA\n  \
           --dtmf <digits>        Optional RFC 4733 DTMF digits to transmit after connect (call)\n  \
           --wav-in <path>        Optional 16-bit mono WAV file to transmit (call)\n  \
           --wav-out <path>       Optional path to write received RX audio WAV\n  \
           --json-report <path>   Optional path to write per-call black-box JSON telemetry",
        env!("CARGO_PKG_VERSION")
    );
}

fn parse_call_args(args: &[String]) -> Result<CallCliArgs, String> {
    let mut server: Option<String> = None;
    let mut user: Option<String> = None;
    let mut password: Option<String> = None;
    let mut target: Option<String> = None;
    let mut duration_ms: u64 = 1000;
    let mut tone_hz: u32 = 440;
    let mut live_audio = false;
    let mut dtmf: Option<String> = None;
    let mut wav_in: Option<String> = None;
    let mut wav_out: Option<String> = None;
    let mut json_report: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let next_val = |idx: &mut usize, name: &str| -> Result<String, String> {
            *idx += 1;
            args.get(*idx)
                .cloned()
                .ok_or_else(|| format!("missing value for {name}"))
        };
        match flag {
            "--server" => server = Some(next_val(&mut i, "--server")?),
            "--user" => user = Some(next_val(&mut i, "--user")?),
            "--password" => password = Some(next_val(&mut i, "--password")?),
            "--target" => target = Some(next_val(&mut i, "--target")?),
            "--duration-ms" => {
                let raw = next_val(&mut i, "--duration-ms")?;
                duration_ms = raw
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --duration-ms '{raw}'"))?;
            }
            "--tone-hz" => {
                let raw = next_val(&mut i, "--tone-hz")?;
                tone_hz = raw
                    .parse::<u32>()
                    .map_err(|_| format!("invalid --tone-hz '{raw}'"))?;
            }
            "--live-audio" => live_audio = true,
            "--dtmf" => dtmf = Some(next_val(&mut i, "--dtmf")?),
            "--wav-in" => wav_in = Some(next_val(&mut i, "--wav-in")?),
            "--wav-out" => wav_out = Some(next_val(&mut i, "--wav-out")?),
            "--json-report" => json_report = Some(next_val(&mut i, "--json-report")?),
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
    let mut live_audio = false;
    let mut wav_out: Option<String> = None;
    let mut json_report: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let next_val = |idx: &mut usize, name: &str| -> Result<String, String> {
            *idx += 1;
            args.get(*idx)
                .cloned()
                .ok_or_else(|| format!("missing value for {name}"))
        };
        match flag {
            "--server" => server = Some(next_val(&mut i, "--server")?),
            "--user" => user = Some(next_val(&mut i, "--user")?),
            "--password" => password = Some(next_val(&mut i, "--password")?),
            "--duration-ms" => {
                let raw = next_val(&mut i, "--duration-ms")?;
                duration_ms = raw
                    .parse::<u64>()
                    .map_err(|_| format!("invalid --duration-ms '{raw}'"))?;
            }
            "--live-audio" => live_audio = true,
            "--wav-out" => wav_out = Some(next_val(&mut i, "--wav-out")?),
            "--json-report" => json_report = Some(next_val(&mut i, "--json-report")?),
            other => return Err(format!("unknown argument '{other}'")),
        }
        i += 1;
    }

    Ok(ListenCliArgs {
        server: server.ok_or_else(|| "missing --server".to_string())?,
        user: user.ok_or_else(|| "missing --user".to_string())?,
        password: password.ok_or_else(|| "missing --password".to_string())?,
        duration_ms,
        live_audio,
        wav_out,
        json_report,
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

fn build_audio_port(live_audio: bool, tx_wav: WavPcm16) -> (Box<dyn AudioPort>, AudioInspector) {
    if live_audio {
        let (port, handle) = LiveLinuxAudioPort::spawn();
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
) -> Result<(), String> {
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
    println!(
        "Recorded RX samples: {} (RMS energy: {})",
        rx_wav.samples.len(),
        rx_wav.rms_energy()
    );

    if let Some(path) = wav_out {
        std::fs::write(path, rx_wav.encode())
            .map_err(|e| format!("failed to write WAV '{path}': {e}"))?;
    }
    if let (Some(path), Some(json)) = (json_report, black_box_json) {
        std::fs::write(path, json)
            .map_err(|e| format!("failed to write JSON report '{path}': {e}"))?;
    }
    Ok(())
}

fn run_call(cli: CallCliArgs) -> Result<(), String> {
    let registrar_addr = resolve_server_addr(&cli.server)?;
    let server_host = cli.server.split(':').next().unwrap_or(&cli.server);
    let registrar_uri = SipUri::parse(&format!("sip:{}", cli.server)).map_err(|e| e.to_string())?;
    let target_uri = SipUri::parse(&cli.target).map_err(|e| e.to_string())?;

    let dtmf_digits: Vec<DtmfDigit> = match &cli.dtmf {
        Some(s) => s
            .chars()
            .map(DtmfDigit::from_char)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?,
        None => Vec::new(),
    };

    let tx_wav = match &cli.wav_in {
        Some(path) => {
            let bytes = std::fs::read(path).map_err(|e| format!("read '{path}': {e}"))?;
            WavPcm16::decode(&bytes).map_err(|e| e.to_string())?
        }
        None => {
            WavPcm16::generate_sine_wave(8000, cli.tone_hz, (cli.duration_ms + 500) as u32, 12000)
        }
    };

    let ua_cfg = UaConfig::new(
        cli.user,
        cli.password,
        server_host,
        registrar_uri,
        "0.0.0.0",
        0,
    );
    let eng_cfg = EngineConfig::new(ua_cfg, registrar_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

    let (audio_port, inspector) = build_audio_port(cli.live_audio, tx_wav);
    let engine = SipEngine::spawn(eng_cfg, audio_port).map_err(|e| e.to_string())?;
    register_and_wait(&engine)?;

    engine
        .send_command(EngineCommand::Dial { target_uri })
        .map_err(|e| e.to_string())?;

    let mut active_call_id: Option<String> = None;
    let mut established = false;
    let call_deadline = Instant::now() + Duration::from_secs(12);

    while Instant::now() < call_deadline {
        if let Some(ev) = engine.recv_event_timeout(Duration::from_millis(100)) {
            match ev {
                EngineEvent::OutboundCallStarted { call_id } => {
                    active_call_id = Some(call_id);
                }
                EngineEvent::CallEstablished {
                    codec, remote_rtp, ..
                } => {
                    println!("Call established: codec={codec}, remote_rtp={remote_rtp}");
                    established = true;
                    break;
                }
                EngineEvent::CallTerminated { reason, .. } => {
                    return Err(format!("call terminated before answer: {reason}"));
                }
                _ => {}
            }
        }
    }
    if !established {
        return Err("outbound call setup timed out".to_string());
    }

    let call_id = active_call_id.ok_or_else(|| "missing call_id".to_string())?;
    for digit in dtmf_digits {
        let _ = engine.send_command(EngineCommand::SendDtmf {
            call_id: call_id.clone(),
            digit,
        });
    }

    thread::sleep(Duration::from_millis(cli.duration_ms));
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
                println!("Call terminated: {reason}");
                black_box_json = Some(json);
                break;
            }
        }
    }

    unregister_and_shutdown(
        engine,
        &inspector,
        cli.wav_out.as_deref(),
        cli.json_report.as_deref(),
        black_box_json.as_deref(),
    )
}

fn run_listen(cli: ListenCliArgs) -> Result<(), String> {
    let registrar_addr = resolve_server_addr(&cli.server)?;
    let server_host = cli.server.split(':').next().unwrap_or(&cli.server);
    let registrar_uri = SipUri::parse(&format!("sip:{}", cli.server)).map_err(|e| e.to_string())?;

    let ua_cfg = UaConfig::new(
        cli.user,
        cli.password,
        server_host,
        registrar_uri,
        "0.0.0.0",
        0,
    );
    let eng_cfg = EngineConfig::new(ua_cfg, registrar_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

    let (audio_port, inspector) =
        build_audio_port(cli.live_audio, WavPcm16::new(8000, vec![0; 160]));
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
    )
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
    fn parses_call_args_including_live_audio() {
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
            "--live-audio",
        ]);
        let parsed = parse_call_args(&args).unwrap();
        assert_eq!(parsed.server, "asterisk:5060");
        assert_eq!(parsed.user, "1001");
        assert_eq!(parsed.duration_ms, 500);
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
        assert!(parsed.live_audio);
        assert_eq!(parsed.wav_out.as_deref(), Some("/tmp/rx.wav"));
    }
}
