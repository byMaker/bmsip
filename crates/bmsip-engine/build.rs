//! Build script locating `libopus` shared library so `bmsip-engine` and downstream crates link against it cleanly.

use std::env;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR must be set by Cargo"));
    let link_path = out_dir.join("libopus.so");

    if let Some(target_so) = find_libopus() {
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(&link_path);
            if std::os::unix::fs::symlink(&target_so, &link_path).is_ok() {
                println!("cargo:rustc-link-search=native={}", out_dir.display());
            }
        }
    }

    println!("cargo:rustc-link-lib=dylib=opus");
}

fn find_libopus() -> Option<PathBuf> {
    let dirs = [
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/usr/lib",
        "/usr/local/lib",
        "/lib/x86_64-linux-gnu",
        "/lib/aarch64-linux-gnu",
    ];
    let names = ["libopus.so", "libopus.so.0"];

    for name in names {
        for dir in dirs {
            let candidate = Path::new(dir).join(name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}
