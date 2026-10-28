"""adcheck setup: install or verify every backend tool dependency in one shot."""

import argparse
import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

from .core import Context, config_path, load_config, resolve_tools

DATA_DIR = Path.home() / ".local" / "share" / "adcheck"
SCCM_REPO = "https://github.com/garrettfoster13/sccmhunter"
SCCM_CLONE = DATA_DIR / "sccmhunter"
SCCM_VENV = DATA_DIR / "venv"
SCCM_WRAPPER = DATA_DIR / "bin" / "sccmhunter"

PY_DEPS = ("ldap3", "requests")
PIPX_PACKAGES = {
    "nxc": "netexec",
    "certipy": "certipy-ad",
    "bloodhound": "bloodhound-ce",
    "pre2k": "git+https://github.com/garrettfoster13/pre2k",
}
# apt package to try when the pipx install fails (netexec's aardwolf dependency
# needs Rust/cargo to build under Python 3.14; Kali ships a working apt package)
APT_FALLBACK = {
    "nxc": "netexec",
    "certipy": "certipy-ad",
    "bloodhound": "bloodhound-ce.py",
}
PIP_FAIL_HINTS = {
    "nxc": "pipx build on Python 3.14 needs Rust: sudo apt install rustc cargo, then re-run adcheck setup",
    "pre2k": "no apt fallback for pre2k; retry manually: pipx install git+https://github.com/garrettfoster13/pre2k",
}
# samba 2:4.24+ (Debian trixie / current Kali) moved rpcclient from samba-common-bin to smbclient
APT_PACKAGES = {"rpcclient": ("smbclient", "samba-common-bin")}
INSTALL_SOURCES = {
    "nxc": "pipx install netexec",
    "certipy": "pipx install certipy-ad",
    "bloodhound": "pipx install bloodhound-ce",
    "pre2k": "pipx install git+https://github.com/garrettfoster13/pre2k",
    "sccmhunter": f"git clone {SCCM_REPO} + venv wrapper under {DATA_DIR}",
    "rpcclient": "sudo apt install -y smbclient samba-common-bin",
}


class Step(NamedTuple):
    label: str
    argv: list | None = None  # subprocess step (None -> in-process func step)
    func: object = None  # callable returning bool
    capture: bool = False  # capture output instead of streaming (never for sudo steps)
    verify: str | None = None  # ctx.tools key that must resolve after the step
    apt_pkgs: tuple = ()  # apt packages installed by this step (for dpkg diagnostics)


def _run(argv, capture: bool = False) -> subprocess.CompletedProcess:
    argv = [str(a) for a in argv]
    print("+ " + shlex.join(argv))
    try:
        if capture:
            return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
        return subprocess.run(argv)
    except FileNotFoundError as e:
        print(f"  command not found: {argv[0]}")
        return subprocess.CompletedProcess(argv, 127, "", str(e))


def _tail(text: str, lines: int = 15) -> None:
    for ln in [ln for ln in (text or "").splitlines() if ln.strip()][-lines:]:
        print(f"    {ln}")


def _current_tools() -> dict:
    ctx = Context(domain="", dc_ip="")
    resolve_tools(ctx)
    return ctx.tools


def _verify_tool(key: str) -> bool:
    if key == "sccmhunter":
        return SCCM_WRAPPER.exists() and bool(_current_tools().get(key))
    return bool(_current_tools().get(key))


def _apt_diagnostic(pkgs: tuple, binary: str) -> None:
    for pkg in pkgs:
        cp = _run(["dpkg", "-L", pkg], capture=True)
        hits = [ln for ln in (cp.stdout or "").splitlines() if binary.lower() in ln.lower()][:10]
        if hits:
            print(f"  dpkg -L {pkg} entries matching '{binary}':")
            for ln in hits:
                print(f"    {ln}")
        else:
            print(f"  dpkg -L {pkg}: no files matching '{binary}'")


def _local_bin_on_path() -> None:
    local_bin = str(Path.home() / ".local" / "bin")
    if os.path.isdir(local_bin) and local_bin not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + local_bin


def _py_dep_status() -> dict:
    status = {}
    for mod in PY_DEPS:
        spec = importlib.util.find_spec(mod)
        status[mod] = spec.origin if spec else None
    return status


def _print_table(tools: dict) -> None:
    rows = [(key, tools.get(key) or "MISSING", INSTALL_SOURCES[key]) for key in INSTALL_SOURCES]
    rows += [(mod, origin or "MISSING", "python package (installed with adcheck)") for mod, origin in _py_dep_status().items()]
    w1 = max(len(r[0]) for r in rows + [("TOOL", "", "")])
    w2 = max(len(r[1]) for r in rows + [("", "STATUS", "")])
    print(f"{'TOOL':<{w1}}  {'STATUS':<{w2}}  INSTALL SOURCE")
    for tool, status, source in rows:
        print(f"{tool:<{w1}}  {status:<{w2}}  {source}")
    print(f"\nconfig file: {config_path()}")


def _register_tool(key: str, path: Path) -> bool:
    cfg = load_config()
    if not isinstance(cfg.get("tools"), dict):
        cfg["tools"] = {}
    cfg["tools"][key] = str(path)
    cfg_file = config_path()
    print(f"+ write {cfg_file} (tools.{key} = {path})")
    try:
        cfg_file.parent.mkdir(parents=True, exist_ok=True)
        cfg_file.write_text(json.dumps(cfg, indent=2) + "\n")
    except OSError as e:
        print(f"  could not write config: {e}")
        return False
    return True


def _write_sccm_wrapper() -> bool:
    content = f'#!/bin/sh\nexec "{SCCM_VENV}/bin/python" "{SCCM_CLONE}/sccmhunter.py" "$@"\n'
    print(f"+ write {SCCM_WRAPPER} (chmod +x)")
    try:
        SCCM_WRAPPER.parent.mkdir(parents=True, exist_ok=True)
        SCCM_WRAPPER.write_text(content)
        SCCM_WRAPPER.chmod(0o755)
    except OSError as e:
        print(f"  could not write wrapper: {e}")
        return False
    return True


def _build_plan(tools: dict, no_apt: bool) -> tuple[list[Step], list[str]]:
    steps: list[Step] = []
    notes = []

    missing_pipx = [key for key in PIPX_PACKAGES if not tools.get(key)]
    have_pipx = bool(shutil.which("pipx"))
    if missing_pipx and not have_pipx:
        if no_apt:
            notes.append(f"pipx missing and --no-apt given; cannot install: {', '.join(missing_pipx)}")
        else:
            steps.append(Step("install pipx (apt)", ["sudo", "apt", "install", "-y", "pipx"]))
            steps.append(Step("pipx ensurepath", ["pipx", "ensurepath"]))
            have_pipx = True
    if missing_pipx and have_pipx:
        for key in missing_pipx:
            steps.append(Step(
                f"install {key} via pipx ({PIPX_PACKAGES[key]})",
                ["pipx", "install", PIPX_PACKAGES[key]],
                capture=True,
                verify=key,
            ))

    if not tools.get("sccmhunter"):
        have_git = bool(shutil.which("git"))
        if not have_git:
            if no_apt:
                notes.append("git missing and --no-apt given; cannot install sccmhunter")
            else:
                steps.append(Step("install git (apt)", ["sudo", "apt", "install", "-y", "git"]))
                have_git = True
        if have_git:
            if not SCCM_CLONE.exists():
                steps.append(Step("clone sccmhunter", ["git", "clone", SCCM_REPO, str(SCCM_CLONE)]))
            if not (SCCM_VENV / "bin" / "pip").exists():
                steps.append(Step("create sccmhunter venv", [sys.executable, "-m", "venv", str(SCCM_VENV)]))
            steps.append(Step(
                "install sccmhunter requirements",
                [str(SCCM_VENV / "bin" / "pip"), "install", "-r", str(SCCM_CLONE / "requirements.txt")],
            ))
            steps.append(Step("write sccmhunter wrapper script", func=_write_sccm_wrapper))
            steps.append(Step(
                "register sccmhunter in adcheck config",
                func=lambda: _register_tool("sccmhunter", SCCM_WRAPPER),
                verify="sccmhunter",
            ))

    for key, pkgs in APT_PACKAGES.items():
        if not tools.get(key):
            joined = " ".join(pkgs)
            if no_apt:
                notes.append(f"{key} missing and --no-apt given; install manually: sudo apt install -y {joined}")
            else:
                steps.append(Step(
                    f"install {key} (apt: {joined})",
                    ["sudo", "apt", "install", "-y", *pkgs],
                    verify=key,
                    apt_pkgs=tuple(pkgs),
                ))

    return steps, notes


def _exec_step(step: Step, no_apt: bool) -> tuple[bool, str]:
    """Run one step (with pipx->apt fallback and post-install verification). Returns (ok, reason)."""
    rc, out = 0, ""
    if step.argv is not None:
        cp = _run(step.argv, capture=step.capture)
        rc, out = cp.returncode, cp.stdout or ""
        ok = cp.returncode == 0
    else:
        ok = bool(step.func())

    if not ok and step.argv and step.argv[0] == "pipx" and step.verify in APT_FALLBACK and not no_apt:
        pkg = APT_FALLBACK[step.verify]
        if _run(["apt-cache", "show", pkg], capture=True).returncode == 0:
            print(f"  pipx install failed; trying apt fallback package '{pkg}'")
            fallback = Step(
                label=f"apt fallback: install {step.verify} (sudo apt install -y {pkg})",
                argv=["sudo", "apt", "install", "-y", pkg],
                verify=step.verify,
                apt_pkgs=(pkg,),
            )
            fb_ok, fb_reason = _exec_step(fallback, no_apt)
            print(f"[{'OK' if fb_ok else 'FAIL'}] {fallback.label}")
            if fb_ok:
                return True, ""
            return False, f"pipx rc={rc}; apt fallback '{pkg}' failed: {fb_reason}"
        hint = PIP_FAIL_HINTS.get(step.verify, f"no apt package '{pkg}' available; install {step.verify} manually")
        print(f"  hint: {hint}")
        if out:
            _tail(out)
        return False, f"pipx install failed (rc={rc}); {hint}"

    if not ok:
        if step.argv and step.argv[0] == "pipx" and step.verify in PIP_FAIL_HINTS:
            print(f"  hint: {PIP_FAIL_HINTS[step.verify]}")
        if out:
            _tail(out)
        reason = f"command failed (rc={rc})" if step.argv is not None else "step action failed"
        return False, reason

    if step.verify and not _verify_tool(step.verify):
        reason = f"'{step.verify}' still not resolvable after install"
        print(f"  diagnostic: {reason}")
        if step.apt_pkgs:
            _apt_diagnostic(step.apt_pkgs, step.verify)
        if out:
            _tail(out)
        return False, reason
    return True, ""


def run_setup(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="adcheck setup",
        description="Install (or with --check, only verify) all adcheck backend tool dependencies",
    )
    parser.add_argument("--check", action="store_true", help="report status only; install nothing")
    parser.add_argument("--no-apt", action="store_true", help="skip all apt steps")
    parser.add_argument("-y", "--yes", action="store_true", help="do not prompt for confirmation")
    args = parser.parse_args(argv)

    _local_bin_on_path()

    if args.check:
        _print_table(_current_tools())
        return 0

    print("python dependencies (installed with the adcheck package):")
    for mod, origin in _py_dep_status().items():
        print(f"  {mod}: {'OK - ' + origin if origin else 'MISSING - reinstall the adcheck package'}")

    steps, notes = _build_plan(_current_tools(), args.no_apt)
    for note in notes:
        print(f"note: {note}")
    if not steps:
        if notes:
            print("\nNothing could be scheduled automatically (see notes above).")
        else:
            print("\nAll backend tools already resolve - nothing to do.")
        _print_table(_current_tools())
        return 0

    print(f"\nInstall plan ({len(steps)} step(s)):")
    for step in steps:
        print(f"  - {step.label}" + (f": {shlex.join(str(a) for a in step.argv)}" if step.argv else ""))
    if not args.yes:
        try:
            reply = input("\nProceed? [y/N] ")
        except EOFError:
            reply = ""
        if reply.strip().lower() not in ("y", "yes"):
            print("Aborted; nothing was installed.")
            return 0

    failed_steps: list[tuple[str, str]] = []
    for step in steps:
        ok, reason = _exec_step(step, args.no_apt)
        print(f"[{'OK' if ok else 'FAIL'}] {step.label}")
        if not ok:
            failed_steps.append((step.label, reason))

    print()
    if failed_steps:
        print("Failed steps:")
        for label, reason in failed_steps:
            print(f"  - {label}: {reason}")
        print()
    _print_table(_current_tools())
    if failed_steps:
        print(f"\n{len(failed_steps)} step(s) failed.")
        return 1
    return 0
