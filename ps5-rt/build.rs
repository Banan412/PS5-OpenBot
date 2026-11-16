//! Build script for `ps5-rt` (PS5 FW 13.40 / FreeBSD 11 runtime glue).
//!
//! Active only when `CARGO_CFG_TARGET_VENDOR == "sie"`; no-op on host builds.
//!
//! 1. Creates empty stand-in archives in `OUT_DIR` ONLY for the 9 unused
//!    FreeBSD metadata libraries requested by Rust std/libc/unwind (`rt`,
//!    `util`, `execinfo`, `kvm`, `memstat`, `procstat`, `devstat`, `gcc_s`,
//!    `m`), while `--unresolved-symbols=report-all` continues to verify every
//!    real symbol reference.
//! 2. Copies `$PS5_PAYLOAD_SDK/target/lib/libc.a` to `OUT_DIR/libps5c.a`,
//!    redefines `mktemp.o`'s `stat`/`lstat` to `__ps5_stat11`/`__ps5_lstat11`,
//!    and deletes `syscalls.o` and `fts.o` via `llvm-ar`.
//! 3. Generates `__ps5_cerror`-checked FreeBSD syscall stubs in
//!    `OUT_DIR/syscalls.S` from the SDK's `syscalls.o`, assembles them with
//!    `clang` to `OUT_DIR/syscalls.o`, and archives them into `OUT_DIR/libps5c.a`.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const UNUSED_FREEBSD_LIBS: &[&str] = &[
    "rt", "util", "execinfo", "kvm", "memstat", "procstat", "devstat", "gcc_s", "m",
];

const RENAMES: &[(&str, &str)] = &[("stat", "__ps5_stat11"), ("lstat", "__ps5_lstat11")];

/// Syscalls overridden in `src/lib.rs` (must not also be emitted in `syscalls.S`).
const STUB_SKIP: &[&str] = &[
    "fstatat",
    "faccessat",
    "readlinkat",
    "clock_nanosleep",
    "accept",
];

fn exe_name(name: &str) -> String {
    format!("{name}{}", std::env::consts::EXE_SUFFIX)
}

fn sdk_tool(sdk: &Path, name: &str) -> PathBuf {
    let p = sdk.join("bin").join(exe_name(name));
    assert!(
        p.exists(),
        "PS5 Payload SDK tool {} not found at {}: check PS5_PAYLOAD_SDK",
        exe_name(name),
        p.display()
    );
    p
}

fn find_llvm_tool(sdk: &Path, env_override: Option<&str>, tool: &str) -> PathBuf {
    if let Some(var) = env_override {
        if let Ok(val) = env::var(var) {
            let p = PathBuf::from(&val);
            if p.exists() && !val.to_ascii_lowercase().contains("prospero-clang") {
                return p;
            }
        }
    }
    if let Ok(llvm_bin) = env::var("PS5_LLVM_BIN") {
        let p = Path::new(&llvm_bin).join(exe_name(tool));
        if p.exists() {
            return p;
        }
    }
    if let Some(parent) = sdk.parent() {
        let sibling = parent.join("llvm").join("LLVM").join("bin").join(exe_name(tool));
        if sibling.exists() {
            return sibling;
        }
    }
    let llvm_config = sdk.join("bin").join(exe_name("prospero-llvm-config"));
    if llvm_config.exists() {
        if let Ok(out) = Command::new(&llvm_config).arg("--bindir").output() {
            if out.status.success() {
                let bindir = String::from_utf8_lossy(&out.stdout).trim().to_owned();
                let candidate = Path::new(&bindir).join(exe_name(tool));
                if candidate.exists() {
                    return candidate;
                }
            }
        }
    }
    let sdk_candidate = sdk.join("bin").join(exe_name(tool));
    if sdk_candidate.exists() {
        return sdk_candidate;
    }
    PathBuf::from(exe_name(tool))
}

fn default_sdk_path() -> PathBuf {
    if let Ok(val) = env::var("PS5_PAYLOAD_SDK") {
        if !val.is_empty() {
            return PathBuf::from(val);
        }
    }
    let win_default = PathBuf::from(r"E:\.ps5-toolchain\ps5-payload-sdk");
    if win_default.exists() {
        return win_default;
    }
    PathBuf::from("/opt/ps5-payload-sdk")
}

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_VENDOR");
    if env::var("CARGO_CFG_TARGET_VENDOR").as_deref() != Ok("sie") {
        return;
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PS5_PAYLOAD_SDK");
    println!("cargo:rerun-if-env-changed=PS5_LLVM_BIN");
    println!("cargo:rerun-if-env-changed=CC_x86_64_sie_ps5_std");

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    // 1. Empty stand-in archives for unused FreeBSD metadata libs in OUT_DIR only.
    for lib in UNUSED_FREEBSD_LIBS {
        fs::write(out.join(format!("lib{lib}.a")), b"!<arch>\n").unwrap();
    }

    let sdk = default_sdk_path();
    assert!(
        sdk.exists(),
        "PS5 Payload SDK directory not found at {}: set PS5_PAYLOAD_SDK",
        sdk.display()
    );
    let libc = sdk.join("target").join("lib").join("libc.a");
    assert!(
        libc.exists(),
        "PS5 Payload SDK libc.a not found at {}",
        libc.display()
    );
    println!("cargo:rerun-if-changed={}", libc.display());

    let objcopy = sdk_tool(&sdk, "llvm-objcopy");
    let llvm_ar = sdk_tool(&sdk, "llvm-ar");
    let objdump = find_llvm_tool(&sdk, None, "llvm-objdump");
    let clang = find_llvm_tool(&sdk, Some("CC_x86_64_sie_ps5_std"), "clang");

    let work = out.join("ps5-rt-work");
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).unwrap_or_else(|e| panic!("creating {}: {e}", work.display()));

    // 2. Patch SDK libc.a -> OUT_DIR/libps5c.a
    let patched = out.join("libps5c.a");
    let bytes = fs::read(&libc).unwrap_or_else(|e| panic!("reading {}: {e}", libc.display()));
    fs::write(&patched, bytes).unwrap_or_else(|e| panic!("writing {}: {e}", patched.display()));

    let mut objcopy_cmd = Command::new(&objcopy);
    for (from, to) in RENAMES {
        objcopy_cmd.arg(format!("--redefine-sym={from}={to}"));
    }
    let status = objcopy_cmd
        .arg(&patched)
        .status()
        .unwrap_or_else(|e| panic!("running {}: {e}", objcopy.display()));
    assert!(status.success(), "llvm-objcopy failed on {}", patched.display());

    let status = Command::new(&llvm_ar)
        .arg("d")
        .arg(&patched)
        .args(["syscalls.o", "fts.o"])
        .status()
        .unwrap_or_else(|e| panic!("running {}: {e}", llvm_ar.display()));
    assert!(status.success(), "deleting syscalls.o and fts.o from {}", patched.display());

    // 3. Generate __ps5_cerror-checked syscall stubs in OUT_DIR/syscalls.S and assemble via clang.
    let syscalls_s = gen_syscall_stubs(&llvm_ar, &objdump, &libc, &work, &out);
    let syscalls_o = out.join("syscalls.o");
    let status = Command::new(&clang)
        .args(["-target", "x86_64-sie-ps5", "-fPIC", "-fno-plt", "-c"])
        .arg(&syscalls_s)
        .arg("-o")
        .arg(&syscalls_o)
        .status()
        .unwrap_or_else(|e| panic!("running {} to assemble syscalls.S: {e}", clang.display()));
    assert!(status.success(), "clang failed assembling {}", syscalls_s.display());

    let status = Command::new(&llvm_ar)
        .arg("rcs")
        .arg(&patched)
        .arg(&syscalls_o)
        .status()
        .unwrap_or_else(|e| panic!("running {} to add syscalls.o: {e}", llvm_ar.display()));
    assert!(status.success(), "llvm-ar rcs failed adding syscalls.o to {}", patched.display());

    let _ = fs::remove_dir_all(&work);

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=ps5c");
}

fn gen_syscall_stubs(
    llvm_ar: &Path,
    objdump: &Path,
    libc: &Path,
    work: &Path,
    out: &Path,
) -> PathBuf {
    let status = Command::new(llvm_ar)
        .current_dir(work)
        .arg("x")
        .arg(libc)
        .arg("syscalls.o")
        .status()
        .unwrap_or_else(|e| panic!("running {}: {e}", llvm_ar.display()));
    assert!(status.success(), "extracting syscalls.o from {}", libc.display());

    let dump = Command::new(objdump)
        .args(["-d", "--no-show-raw-insn", "--no-leading-addr"])
        .arg(work.join("syscalls.o"))
        .output()
        .unwrap_or_else(|e| panic!("running {}: {e}", objdump.display()));
    assert!(
        dump.status.success(),
        "llvm-objdump failed on syscalls.o: {}",
        String::from_utf8_lossy(&dump.stderr)
    );
    let text = String::from_utf8(dump.stdout).unwrap();

    let mut funcs: Vec<(String, Vec<String>)> = Vec::new();
    for line in text.lines() {
        if let Some(name) = line.strip_prefix('<').and_then(|l| l.strip_suffix(">:")) {
            funcs.push((name.to_owned(), Vec::new()));
        } else if let (Some(f), true) = (funcs.last_mut(), line.starts_with(' ') || line.starts_with('\t')) {
            let ins = line
                .split('#')
                .next()
                .unwrap()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            if !ins.is_empty() {
                f.1.push(ins);
            }
        }
    }

    const GENERIC: &[&str] = &[
        "movq %rdi, %rax",
        "movq %rsi, %rdi",
        "movq %rdx, %rsi",
        "movq %rcx, %rdx",
        "movq %r8, %r10",
        "movq %r9, %r8",
        "movq 0x8(%rsp), %r9",
        "syscall",
        "retq",
        "retq",
    ];

    let mut asm = String::from(
        "# Generated by ps5-rt/build.rs from the SDK's syscalls.o.\n\
         .section .text.__ps5_cerror,\"ax\",@progbits\n\
         .p2align 4\n\
         .hidden __ps5_cerror\n\
         __ps5_cerror:\n\
         \tpushq %rax\n\
         \tcallq *__error@GOTPCREL(%rip)\n\
         \tpopq %rcx\n\
         \tmovl %ecx, (%rax)\n\
         \tmovq $-1, %rax\n\
         \tmovq $-1, %rdx\n\
         \tretq\n",
    );

    let mut count = 0usize;
    for (name, ins) in &funcs {
        if STUB_SKIP.contains(&name.as_str()) {
            continue;
        }
        let body = if ins.iter().map(String::as_str).eq(GENERIC.iter().copied()) {
            GENERIC[..8].iter().map(|i| format!("\t{i}\n")).collect::<String>()
        } else {
            let n = match ins.as_slice() {
                [mov, r10, sc, r1, r2]
                    if r10 == "movq %rcx, %r10"
                        && sc == "syscall"
                        && r1 == "retq"
                        && r2 == "retq" =>
                {
                    mov.strip_prefix("movq $")
                        .and_then(|v| v.strip_suffix(", %rax"))
                        .and_then(|v| {
                            u32::from_str_radix(
                                v.trim_start_matches("0x"),
                                if v.starts_with("0x") { 16 } else { 10 },
                            )
                            .ok()
                        })
                }
                _ => None,
            };
            let n = n.unwrap_or_else(|| panic!("unexpected SDK syscall stub `{name}`: {ins:?}"));
            format!("\tmovq ${n}, %rax\n\tmovq %rcx, %r10\n\tsyscall\n")
        };

        asm.push_str(&format!(
            ".section .text.__ps5_sys.{name},\"ax\",@progbits\n\
             .p2align 4\n\
             .globl {name}\n\
             .type {name},@function\n\
             {name}:\n\
             {body}\
             \tjb __ps5_cerror\n\
             \tretq\n\
             .size {name}, .-{name}\n"
        ));
        count += 1;
    }
    assert!(count > 200, "only {count} syscall stubs found in SDK syscalls.o");

    let syscalls_s = out.join("syscalls.S");
    fs::write(&syscalls_s, asm).unwrap_or_else(|e| panic!("writing {}: {e}", syscalls_s.display()));
    syscalls_s
}
