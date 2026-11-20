//! MODULE_CONTRACT: Linux CLI SIP endpoint (`bmsip-cli`) built on `bmsip-engine`.
//! INVARIANTS: Uses only `bmsip-engine` public API; zero `.unwrap()`/`.expect()` on user or network input; explicit exit codes (`0` success, `1` failure).
//! RFC_REFS: RFC 3261, RFC 3550, RFC 4733.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use bmsip_engine::bmsip_core::dialog::{RegistrationState, UaConfig};
use bmsip_engine::bmsip_core::sip::SipUri;
use bmsip_engine::bmsip_media::{DtmfDigit, WavPcm16};
use bmsip_engine::{EngineCommand, EngineConfig, EngineEvent, SipEngine, WavAudioPort};

struct CallCliArgs {
    server: String,
    user: String,
    password: String,
    target: String,
    duration_ms: u64,
    tone_hz: u32,
    dtmf: Option<String>,
    wav_in: Option<String>,
    wav_out: Option<String>,
    json_report: Option<String>,
}

fn print_usage() {
    println!(
        "bmsip-cli v{}\n\n\
         USAGE:\n  \
           bmsip-cli --version\n  \
           bmsip-cli --help\n  \
           bmsip-cli call --server <host:port> --user <user> --password <pass> --target <sip_uri> [OPTIONS]\n\n\
         OPTIONS:\n  \
           --duration-ms <ms>     Active media duration in milliseconds (default: 1000)\n  \
           --tone-hz <hz>         Generated sine tone frequency if --wav-in omitted (default: 440)\n  \
           --dtmf <digits>        Optional RFC 4733 DTMF digits to transmit after connect\n  \
           --wav-in <path>        Optional 16-bit mono WAV file to transmit\n  \
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
        dtmf,
        wav_in,
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

    let (audio_port, audio_handle) = WavAudioPort::new(tx_wav, true);
    let engine = SipEngine::spawn(eng_cfg, Box::new(audio_port)).map_err(|e| e.to_string())?;

    engine
        .send_command(EngineCommand::Register)
        .map_err(|e| e.to_string())?;

    let reg_deadline = Instant::now() + Duration::from_secs(10);
    let mut registered = false;
    while Instant::now() < reg_deadline {
        if let Some(ev) = engine.recv_event_timeout(Duration::from_millis(100)) {
            match ev {
                EngineEvent::RegistrationChanged(RegistrationState::Registered { .. }) => {
                    registered = true;
                    break;
                }
                EngineEvent::RegistrationChanged(RegistrationState::Failed { reason, .. }) => {
                    return Err(format!("SIP registration failed: {reason}"));
                }
                _ => {}
            }
        }
    }
    if !registered {
        return Err("SIP registration timed out".to_string());
    }

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

    let rx_wav = audio_handle.recorded_wav();
    println!(
        "Recorded RX samples: {} (RMS energy: {})",
        rx_wav.samples.len(),
        rx_wav.rms_energy()
    );

    if let Some(path) = &cli.wav_out {
        std::fs::write(path, rx_wav.encode())
            .map_err(|e| format!("failed to write WAV '{path}': {e}"))?;
    }
    if let (Some(path), Some(json)) = (&cli.json_report, &black_box_json) {
        std::fs::write(path, json)
            .map_err(|e| format!("failed to write JSON report '{path}': {e}"))?;
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

    if args[0] != "call" {
        eprintln!("unknown subcommand '{}'\n", args[0]);
        print_usage();
        return ExitCode::FAILURE;
    }

    match parse_call_args(&args[1..]).and_then(run_call) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
