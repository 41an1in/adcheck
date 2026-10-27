import re

from ..core import run_tool, tool_supports
from .base import Check

HIT_RE = re.compile(r"(?i)(valid|found|pwned)")
SUMMARY_RE = re.compile(r"(?i)\b(valid|found|hits?)\b")
ACCOUNT_RE = re.compile(r"[A-Za-z0-9_.-]+\$")


class Pre2kCheck(Check):
    id = "pre2k"
    name = "Pre-Windows 2000 computer accounts (pre2k)"
    description = "Find pre-created computer accounts still using their machine name as password"
    requires_auth = True
    requires_tools = ("pre2k",)

    def run(self, ctx):
        argv = ["auth", "-u", ctx.username, "-d", ctx.domain, "-dc-ip", ctx.dc_ip]
        if ctx.password is not None:
            argv += ["-p", ctx.password]
        elif ctx.hashes and tool_supports(ctx, "pre2k", "hashes", sub=["auth"]):
            argv += ["-hashes", ctx.hashes]
        else:
            return [self.f("skipped: pre2k needs password or supported hashes", severity="INFO")]
        if ctx.kerberos and tool_supports(ctx, "pre2k", "kerberos", sub=["auth"]):
            argv.append("-k")

        cp = run_tool(ctx, "pre2k", argv)
        raw = cp.stdout or ""
        if cp.stderr:
            raw += "\n--- stderr ---\n" + cp.stderr
        self.save_raw(ctx, raw)

        hits = []
        summary = ""
        for line in (cp.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            if "[+]" in line and ("$" in line or HIT_RE.search(line)):
                hits.append((self._account(line), line))
            elif SUMMARY_RE.search(line) and any(c.isdigit() for c in line):
                summary = line

        if hits:
            return [
                self.f(
                    f"pre-created computer account with predictable password: {account}",
                    severity="HIGH",
                    host=ctx.dc_ip,
                    detail=summary,
                    evidence=[line],
                )
                for account, line in hits
            ]
        if cp.returncode == 0:
            return [self.f("No pre-2000 computer account hits", severity="OK", host=ctx.dc_ip, detail=summary)]
        return [
            self.f(
                f"pre2k exited with rc={cp.returncode}, no hits parsed",
                severity="INFO",
                host=ctx.dc_ip,
                detail=(cp.stderr or "").strip()[:500],
            )
        ]

    @staticmethod
    def _account(line):
        for token in line.split():
            if "$" in token:
                return token.strip("'\".,:;()[]")
        m = ACCOUNT_RE.search(line)
        return m.group(0) if m else line
