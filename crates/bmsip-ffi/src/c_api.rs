//! MODULE_CONTRACT: C99/C++ ABI `extern "C"` wrapper matching `include/bmsip.h` and delegating to safe [`crate::client::BmsipClient`].
//! INVARIANTS: Every pointer parameter is null-checked prior to dereference; zero panics across `extern "C"` boundaries; caller owns allocated strings via `bmsip_string_free`.
//! RFC_REFS: RFC 3261, RFC 3550.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::slice;

use crate::client::{BmsipClient, FfiConfig};

/// Opaque C handle representing a [`BmsipClient`] instance.
pub struct BmsipClientHandle {
    inner: BmsipClient,
}

unsafe fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: Caller passes a valid null-terminated UTF-8 C string pointer.
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(str::to_string)
}

unsafe fn client_ref<'a>(handle: *const BmsipClientHandle) -> Option<&'a BmsipClient> {
    if handle.is_null() {
        return None;
    }
    // SAFETY: Caller passes a live handle allocated by `bmsip_client_new`.
    Some(&unsafe { &*handle }.inner)
}

/// Allocates and starts a new SIP client handle with an 8 kHz PCM bridge; returns null on invalid arguments or bind failure.
///
/// # Safety
/// All string pointers must be valid null-terminated UTF-8 C strings.
#[no_mangle]
pub unsafe extern "C" fn bmsip_client_new(
    username: *const c_char,
    password: *const c_char,
    domain: *const c_char,
    registrar_addr: *const c_char,
    bind_ip: *const c_char,
    sip_port: u16,
) -> *mut BmsipClientHandle {
    unsafe {
        bmsip_client_new_ex(
            username,
            password,
            domain,
            registrar_addr,
            bind_ip,
            sip_port,
            0,
            8_000,
        )
    }
}

/// Allocates and starts a new SIP client handle with explicit Opus toggle and PCM bridge sample rate (`8000`, `16000`, or `48000` Hz).
///
/// # Safety
/// All string pointers must be valid null-terminated UTF-8 C strings.
#[no_mangle]
pub unsafe extern "C" fn bmsip_client_new_ex(
    username: *const c_char,
    password: *const c_char,
    domain: *const c_char,
    registrar_addr: *const c_char,
    bind_ip: *const c_char,
    sip_port: u16,
    enable_opus: i32,
    sample_rate_hz: u32,
) -> *mut BmsipClientHandle {
    let (Some(u), Some(p), Some(d), Some(r), Some(b)) = (
        unsafe { cstr_to_string(username) },
        unsafe { cstr_to_string(password) },
        unsafe { cstr_to_string(domain) },
        unsafe { cstr_to_string(registrar_addr) },
        unsafe { cstr_to_string(bind_ip) },
    ) else {
        return ptr::null_mut();
    };

    let cfg = FfiConfig {
        username: u,
        password: p,
        domain: d,
        registrar_addr: r,
        bind_ip: b,
        sip_port,
        enable_opus: enable_opus != 0,
    };

    match BmsipClient::new_with_sample_rate(cfg, sample_rate_hz) {
        Ok(client) => Box::into_raw(Box::new(BmsipClientHandle { inner: client })),
        Err(_) => ptr::null_mut(),
    }
}

/// Returns the configured mono PCM bridge sample rate in Hz (`8000`, `16000`, or `48000`), or `0` if `client` is null.
///
/// # Safety
/// `client` must be null or a valid handle created by `bmsip_client_new` / `bmsip_client_new_ex`.
#[no_mangle]
pub unsafe extern "C" fn bmsip_client_audio_sample_rate_hz(
    client: *const BmsipClientHandle,
) -> u32 {
    let Some(c) = (unsafe { client_ref(client) }) else {
        return 0;
    };
    c.audio_sample_rate_hz()
}

/// Triggers account registration (`0` on success, `-1` on error).
///
/// # Safety
/// `client` must be a valid handle created by `bmsip_client_new`.
#[no_mangle]
pub unsafe extern "C" fn bmsip_client_register(client: *const BmsipClientHandle) -> i32 {
    let Some(c) = (unsafe { client_ref(client) }) else {
        return -1;
    };
    if c.register_account().is_ok() {
        0
    } else {
        -1
    }
}

/// Triggers account de-registration (`0` on success, `-1` on error).
///
/// # Safety
/// `client` must be a valid handle created by `bmsip_client_new`.
#[no_mangle]
pub unsafe extern "C" fn bmsip_client_unregister(client: *const BmsipClientHandle) -> i32 {
    let Some(c) = (unsafe { client_ref(client) }) else {
        return -1;
    };
    if c.unregister_account().is_ok() {
        0
    } else {
        -1
    }
}

/// Dials a target SIP URI (`0` on success, `-1` on error).
///
/// # Safety
/// `client` must be valid and `target_uri` must be a valid null-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn bmsip_client_dial(
    client: *const BmsipClientHandle,
    target_uri: *const c_char,
) -> i32 {
    let (Some(c), Some(uri)) = (unsafe { client_ref(client) }, unsafe {
        cstr_to_string(target_uri)
    }) else {
        return -1;
    };
    if c.dial(uri).is_ok() {
        0
    } else {
        -1
    }
}

/// Sends `180 Ringing` on an inbound call (`0` on success, `-1` on error).
///
/// # Safety
/// `client` and `call_id` must be valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn bmsip_client_ring(
    client: *const BmsipClientHandle,
    call_id: *const c_char,
) -> i32 {
    let (Some(c), Some(cid)) = (unsafe { client_ref(client) }, unsafe {
        cstr_to_string(call_id)
    }) else {
        return -1;
    };
    if c.ring(cid).is_ok() {
        0
    } else {
        -1
    }
}

/// Answers an inbound call (`0` on success, `-1` on error).
///
/// # Safety
/// `client` and `call_id` must be valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn bmsip_client_answer(
    client: *const BmsipClientHandle,
    call_id: *const c_char,
) -> i32 {
    let (Some(c), Some(cid)) = (unsafe { client_ref(client) }, unsafe {
        cstr_to_string(call_id)
    }) else {
        return -1;
    };
    if c.answer(cid).is_ok() {
        0
    } else {
        -1
    }
}

/// Rejects, cancels, or hangs up a call (`0` on success, `-1` on error).
///
/// # Safety
/// `client` and `call_id` must be valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn bmsip_client_hangup(
    client: *const BmsipClientHandle,
    call_id: *const c_char,
) -> i32 {
    let (Some(c), Some(cid)) = (unsafe { client_ref(client) }, unsafe {
        cstr_to_string(call_id)
    }) else {
        return -1;
    };
    if c.hangup(cid).is_ok() {
        0
    } else {
        -1
    }
}

/// Transmits an RFC 4733 DTMF digit (`'0'..'9'`, `'*'`, `'#'`, `'A'..'D'`).
///
/// # Safety
/// `client` and `call_id` must be valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn bmsip_client_send_dtmf(
    client: *const BmsipClientHandle,
    call_id: *const c_char,
    digit: c_char,
) -> i32 {
    let (Some(c), Some(cid)) = (unsafe { client_ref(client) }, unsafe {
        cstr_to_string(call_id)
    }) else {
        return -1;
    };
    let ch = (digit as u8) as char;
    if c.send_dtmf(cid, ch.to_string()).is_ok() {
        0
    } else {
        -1
    }
}

/// Notifies the engine of a local IP/port handover (`Wi-Fi <-> LTE`).
///
/// # Safety
/// `client` and `bind_ip` must be valid non-null pointers.
#[no_mangle]
pub unsafe extern "C" fn bmsip_client_notify_network_changed(
    client: *const BmsipClientHandle,
    bind_ip: *const c_char,
    sip_port: u16,
) -> i32 {
    let (Some(c), Some(ip)) = (unsafe { client_ref(client) }, unsafe {
        cstr_to_string(bind_ip)
    }) else {
        return -1;
    };
    if c.notify_network_changed(ip, sip_port).is_ok() {
        0
    } else {
        -1
    }
}

/// Suspends background media/refresh timers.
///
/// # Safety
/// `client` must be a valid handle created by `bmsip_client_new`.
#[no_mangle]
pub unsafe extern "C" fn bmsip_client_suspend(client: *const BmsipClientHandle) -> i32 {
    let Some(c) = (unsafe { client_ref(client) }) else {
        return -1;
    };
    if c.suspend().is_ok() {
        0
    } else {
        -1
    }
}

/// Resumes background timers and refreshes registration.
///
/// # Safety
/// `client` must be a valid handle created by `bmsip_client_new`.
#[no_mangle]
pub unsafe extern "C" fn bmsip_client_resume(client: *const BmsipClientHandle) -> i32 {
    let Some(c) = (unsafe { client_ref(client) }) else {
        return -1;
    };
    if c.resume().is_ok() {
        0
    } else {
        -1
    }
}

/// Pushes one 20 ms (160-sample) mono 16-bit PCM microphone frame.
///
/// # Safety
/// `client` must be valid and `samples` must point to at least `len` `int16_t` elements.
#[no_mangle]
pub unsafe extern "C" fn bmsip_client_push_pcm(
    client: *const BmsipClientHandle,
    samples: *const i16,
    len: usize,
) -> i32 {
    let Some(c) = (unsafe { client_ref(client) }) else {
        return -1;
    };
    if samples.is_null() {
        return -1;
    }
    // SAFETY: Caller guarantees `samples` points to `len` valid `i16` values.
    let pcm = unsafe { slice::from_raw_parts(samples, len) };
    if c.push_captured_pcm(pcm.to_vec()).is_ok() {
        0
    } else {
        -1
    }
}

/// Pops one 20 ms decoded mono PCM playout frame into `out_samples`.
///
/// Returns number of samples copied (`160`), `0` if empty, or `-1` on invalid arguments.
///
/// # Safety
/// `client` must be valid and `out_samples` must hold at least `capacity` `int16_t` elements.
#[no_mangle]
pub unsafe extern "C" fn bmsip_client_pop_pcm(
    client: *const BmsipClientHandle,
    out_samples: *mut i16,
    capacity: usize,
) -> i32 {
    let Some(c) = (unsafe { client_ref(client) }) else {
        return -1;
    };
    if out_samples.is_null() {
        return -1;
    }
    let Some(frame) = c.pop_playout_pcm() else {
        return 0;
    };
    if capacity < frame.len() {
        return -1;
    }
    // SAFETY: Caller guarantees `out_samples` points to writable buffer of size >= `capacity`.
    let dst = unsafe { slice::from_raw_parts_mut(out_samples, frame.len()) };
    dst.copy_from_slice(&frame);
    frame.len() as i32
}

/// Polls the next event as a heap-allocated JSON C string (`NULL` if no event).
///
/// Free non-null results with `bmsip_string_free`.
///
/// # Safety
/// `client` must be a valid handle created by `bmsip_client_new`.
#[no_mangle]
pub unsafe extern "C" fn bmsip_client_poll_event_json(
    client: *const BmsipClientHandle,
    timeout_ms: u32,
) -> *mut c_char {
    let Some(c) = (unsafe { client_ref(client) }) else {
        return ptr::null_mut();
    };
    let Some(ev) = c.poll_event(timeout_ms) else {
        return ptr::null_mut();
    };
    match CString::new(ev.to_json()) {
        Ok(cstr) => cstr.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Frees a C string previously returned by `bmsip_client_poll_event_json`.
///
/// # Safety
/// `s` must be null or a pointer returned by `bmsip_client_poll_event_json`.
#[no_mangle]
pub unsafe extern "C" fn bmsip_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: Pointer was allocated via `CString::into_raw`.
        drop(unsafe { CString::from_raw(s) });
    }
}

/// Shuts down and frees a [`BmsipClientHandle`].
///
/// # Safety
/// `client` must be null or a live handle returned by `bmsip_client_new`, freed at most once.
#[no_mangle]
pub unsafe extern "C" fn bmsip_client_free(client: *mut BmsipClientHandle) {
    if !client.is_null() {
        // SAFETY: Handle was allocated via `Box::into_raw`.
        let boxed = unsafe { Box::from_raw(client) };
        boxed.inner.shutdown();
    }
}
