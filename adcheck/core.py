import json
import os
import shlex
import shutil
import ssl
import subprocess
import sys
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from pathlib import Path

SEVERITIES = ("OK", "INFO", "LOW", "MEDIUM", "HIGH")
SEV_COLORS = {"OK": "\033[32m", "INFO": "\033[90m", "LOW": "\033[34m", "MEDIUM": "\033[33m", "HIGH": "\033[31m"}


class ToolNotFound(Exception):
    pass


@dataclass
class Finding:
    check: str
    title: str
    severity: str = "INFO"  # one of SEVERITIES
    host: str = ""
    detail: str = ""
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "title": self.title,
            "severity": self.severity,
            "host": self.host,
            "detail": self.detail,
            "evidence": list(self.evidence),
        }


@dataclass
class Context:
    domain: str
    dc_ip: str
    dc_fqdn: str = ""
    username: str = ""
    password: str | None = None
    hashes: str = ""  # "LM:NT" or ":NT"
    kerberos: bool = False
    targets: str = ""  # nxc target spec: IP, CIDR, or path to file with one target per line
    output_dir: Path = Path(".")
    raw_dir: Path = Path(".")
    timeout: int = 300
    no_color: bool = False
    tools: dict[str, str | None] = field(default_factory=dict)  # keys: nxc, certipy, bloodhound, pre2k, sccmhunter, rpcclient

    @property
    def domain_dn(self) -> str:
        return ",".join(f"DC={part}" for part in self.domain.split(".") if part)

    @property
    def has_creds(self) -> bool:
        return bool(self.username) and (self.password is not None or bool(self.hashes) or self.kerberos)

    @property
    def has_password(self) -> bool:
        return self.password is not None


def config_path() -> Path:
    override = os.environ.get("ADCHECK_CONFIG")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".config" / "adcheck" / "config.json"


def load_config() -> dict:
    try:
        data = json.loads(config_path().read_text())
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def resolve_tools(ctx, sccmhunter_path=None, pre2k_path=None) -> None:
    ctx.tools["nxc"] = shutil.which("nxc") or shutil.which("netexec")
    ctx.tools["certipy"] = shutil.which("certipy-ad") or shutil.which("certipy")
    ctx.tools["bloodhound"] = shutil.which("bloodhound-ce-python") or shutil.which("bloodhound-python")
    ctx.tools["pre2k"] = pre2k_path or shutil.which("pre2k")
    ctx.tools["sccmhunter"] = sccmhunter_path or shutil.which("sccmhunter") or shutil.which("sccmhunter.py")
    ctx.tools["rpcclient"] = shutil.which("rpcclient")
    cfg_tools = load_config().get("tools")
    if isinstance(cfg_tools, dict):
        for key in ctx.tools:
            if ctx.tools[key] is None:
                path = cfg_tools.get(key)
                if isinstance(path, str) and path:
                    ctx.tools[key] = path


def run_tool(ctx, tool_key, argv: list[str], timeout=None, cwd=None) -> subprocess.CompletedProcess:
    path = ctx.tools.get(tool_key)
    if not path:
        raise ToolNotFound(tool_key)
    cmd = [path] + argv
    if path.endswith(".py"):
        cmd = ["python3"] + cmd
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout or ctx.timeout,
            cwd=cwd,
        )
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout or ""
        stderr = e.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        return subprocess.CompletedProcess(cmd, 124, stdout, stderr + "\nTIMEOUT")


def masked_cmd(ctx, argv) -> str:
    cmd = shlex.join(argv)
    for secret in (ctx.password, ctx.hashes):
        if secret:
            cmd = cmd.replace(secret, "***")
    return cmd


_help_cache: dict[tuple[str, tuple[str, ...]], str] = {}


def tool_supports(ctx, tool_key, needle: str, sub: list[str] | None = None) -> bool:
    key = (tool_key, tuple(sub or ()))
    if key not in _help_cache:
        out = ""
        try:
            cp = run_tool(ctx, tool_key, list(sub or ()) + ["-h"], timeout=30)
            out = (cp.stdout or "") + (cp.stderr or "")
            if cp.returncode != 0:
                cp = run_tool(ctx, tool_key, list(sub or ()) + ["--help"], timeout=30)
                out = (cp.stdout or "") + (cp.stderr or "")
        except Exception:
            out = ""
        _help_cache[key] = out
    return needle in _help_cache[key]


def nxc_auth(ctx) -> list[str]:
    args: list[str] = []
    if ctx.kerberos:
        args.append("-k")
    if ctx.username:
        args += ["-u", ctx.username]
    if ctx.password is not None:
        args += ["-p", ctx.password]
    elif ctx.hashes:
        args += ["-H", ctx.hashes]
    elif ctx.kerberos:
        args += ["-p", ""]
    return args


def ldap_available() -> bool:
    try:
        import ldap3  # noqa: F401
    except ImportError:
        return False
    return True


def ldap_bind(ctx, use_ssl=False, simple=False):
    if not ldap_available():
        return None
    import ldap3

    try:
        tls = ldap3.Tls(validate=ssl.CERT_NONE) if use_ssl else None
        server = ldap3.Server(ctx.dc_ip, port=636 if use_ssl else 389, use_ssl=use_ssl, tls=tls)
        if simple:
            user = f"{ctx.username}@{ctx.domain}"
            authentication = ldap3.SIMPLE
        else:
            user = f"{ctx.domain}\\{ctx.username}"
            authentication = ldap3.NTLM
        passwords = [ctx.password]
        if ctx.hashes:
            passwords.append(ctx.hashes)
            passwords.append(ctx.hashes.split(":")[-1])
        for pw in passwords:
            if pw is None:
                continue
            try:
                return ldap3.Connection(server, user=user, password=pw, authentication=authentication, auto_bind=True)
            except Exception:
                continue
    except Exception:
        pass
    return None


def expand_targets(ctx, cap=256) -> list[str]:
    hosts = [ctx.dc_ip]
    spec = (ctx.targets or "").strip()
    if spec:
        path = Path(spec)
        if path.is_file():
            for line in path.read_text(errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    hosts.append(line)
        else:
            try:
                net = ip_network(spec, strict=False)
                for i, host in enumerate(net.hosts()):
                    if i >= cap:
                        break
                    hosts.append(str(host))
            except ValueError:
                try:
                    hosts.append(str(ip_address(spec)))
                except ValueError:
                    pass
    seen = set()
    out = []
    for host in hosts:
        if host not in seen:
            seen.add(host)
            out.append(host)
    return out


def cprint(ctx, severity, text) -> None:
    if ctx.no_color or not sys.stdout.isatty():
        print(f"[{severity}] {text}")
    else:
        print(f"{SEV_COLORS.get(severity, '')}[{severity}]\033[0m {text}")


def parse_nxc_lines(text) -> list[tuple[str, str, str]]:
    results = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        proto, ip, port, host = parts[0], parts[1], parts[2], parts[3]
        if not (proto.isalpha() and proto.isupper()):
            continue
        if not port.isdigit():
            continue
        results.append((ip, host, " ".join(parts[4:])))
    return results
