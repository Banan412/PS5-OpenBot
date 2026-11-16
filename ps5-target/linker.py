"""PS5 FW 13.40 direct ld.lld linker wrapper for rustc (gnu-cc flavor).

Translates rustc's gnu-cc linker invocation into a direct ld.lld.exe call
against the patched PS5 Payload SDK main.script so PT_DYNAMIC only contains
.dynamic (zero warnings) and --unresolved-symbols=report-all verifies every
real symbol.
"""

import os
import pathlib
import subprocess
import sys
import tempfile


DEFAULT_SDK = r"E:\.ps5-toolchain\ps5-payload-sdk"
DEFAULT_LLVM_BIN = r"E:\.ps5-toolchain\llvm\LLVM\bin"

# Clang/GCC driver flags not accepted directly by ld.lld.
DRIVER_ONLY_FLAGS = {
    "-m64",
    "-nodefaultlibs",
    "-nostartfiles",
    "-nostdlib",
    "-nolibc",
    "-fno-stack-protector",
    "-fno-plt",
    "-femulated-tls",
    "-fPIC",
    "-fpic",
    "-pthread",
}

# Libraries we order explicitly at the end of the link line.
MANAGED_LIBS = {
    "-lps5c",
    "-lc",
    "-lkernel_web",
    "-lSceLibcInternal",
    "-lSceNet",
    "-lc_stub_weak",
    "-lkernel_stub_weak",
}


def unquote_rsp_line(line: str) -> str:
    s = line.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    return s


def expand_args(raw_args: list[str]) -> list[str]:
    expanded: list[str] = []
    for arg in raw_args:
        if arg.startswith("@") and len(arg) > 1:
            rsp_path = pathlib.Path(arg[1:])
            text = rsp_path.read_text(encoding="utf-8")
            for line in text.splitlines():
                val = unquote_rsp_line(line)
                if val:
                    if val.startswith("@") and len(val) > 1:
                        expanded.extend(expand_args([val]))
                    else:
                        expanded.append(val)
        else:
            expanded.append(arg)
    return expanded


def translate_args(args: list[str]) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in DRIVER_ONLY_FLAGS:
            i += 1
            continue
        if arg == "-static-pie":
            out.append("-pie")
            i += 1
            continue
        if arg.startswith("-Wl,"):
            parts = arg[4:].split(",")
            for part in parts:
                if not part or part in MANAGED_LIBS:
                    continue
                if part == "-static-pie":
                    out.append("-pie")
                else:
                    out.append(part)
            i += 1
            continue
        if arg in MANAGED_LIBS:
            i += 1
            continue
        if arg == "-l" and i + 1 < len(args) and f"-l{args[i + 1]}" in MANAGED_LIBS:
            i += 2
            continue
        if os.path.basename(arg).lower() == "crt1.o":
            i += 1
            continue
        out.append(arg)
        i += 1
    return out


def patch_main_script(sdk: pathlib.Path) -> str:
    script_path = sdk / "target" / "lib" / "main.script"
    if not script_path.is_file():
        raise FileNotFoundError(f"SDK linker script not found: {script_path}")
    script = script_path.read_text(encoding="utf-8")
    needle = "\t.dynamic : ALIGN(CONSTANT(MAXPAGESIZE)) {"
    if script.count(needle) != 1:
        raise RuntimeError(f"Unexpected SDK linker script format in {script_path}")
    sections = (
        "\t.dynsym : { *(.dynsym) } : ph_rodata\n"
        "\t.hash : { *(.hash) } : ph_rodata\n"
        "\t.dynstr : { *(.dynstr) } : ph_rodata\n"
        "\t.rela.dyn : { *(.rela.dyn) } : ph_rodata\n"
        "\t.note.gnu.build-id : { *(.note.gnu.build-id) } : ph_rodata\n\n"
    )
    return script.replace(needle, sections + needle, 1)


def quote_rsp_arg(arg: str) -> str:
    if not arg or any(c.isspace() or c in '"\\' for c in arg):
        escaped = arg.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return arg


def main() -> int:
    sdk = pathlib.Path(os.environ.get("PS5_PAYLOAD_SDK") or DEFAULT_SDK)
    llvm_bin = pathlib.Path(os.environ.get("PS5_LLVM_BIN") or DEFAULT_LLVM_BIN)
    ld_lld = pathlib.Path(os.environ.get("PS5_LD_LLD") or (llvm_bin / "ld.lld.exe"))
    if not ld_lld.is_file():
        raise FileNotFoundError(f"ld.lld.exe not found at {ld_lld}")

    crt1 = sdk / "target" / "lib" / "crt1.o"
    if not crt1.is_file():
        raise FileNotFoundError(f"crt1.o not found at {crt1}")

    patched_script = patch_main_script(sdk)
    rust_args = translate_args(expand_args(sys.argv[1:]))

    temp_files: list[pathlib.Path] = []
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", suffix=".script", delete=False
        ) as sf:
            sf.write(patched_script)
            script_tmp = pathlib.Path(sf.name)
        temp_files.append(script_tmp)

        lld_args = [
            "-m", "elf_x86_64_fbsd",
            "-pie",
            "--eh-frame-hdr",
            "--hash-style=sysv",
            "--build-id=uuid",
            "--unresolved-symbols=report-all",
            "-z", "now",
            "-z", "start-stop-visibility=hidden",
            "-z", "rodynamic",
            "-z", "common-page-size=0x4000",
            "-z", "max-page-size=0x4000",
            "--default-script", str(script_tmp),
            *rust_args,
            "-L", str(sdk / "target" / "lib"),
            "-L", str(sdk / "target" / "user" / "homebrew" / "lib"),
            "-Bdynamic",
            "-lps5c",
            "-lc",
            "-lkernel_web",
            "-lSceLibcInternal",
            "-lSceNet",
            "-lc_stub_weak",
            "-lkernel_stub_weak",
            str(crt1),
        ]

        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", suffix=".lld.rsp", delete=False
        ) as rf:
            for a in lld_args:
                rf.write(quote_rsp_arg(a) + "\n")
            rsp_tmp = pathlib.Path(rf.name)
        temp_files.append(rsp_tmp)

        return subprocess.call([str(ld_lld), f"@{rsp_tmp}"])
    finally:
        for p in temp_files:
            p.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
