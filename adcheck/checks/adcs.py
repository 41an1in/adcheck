import re

from ..core import run_tool
from .base import Check

TEMPLATE_RE = re.compile(r"Template Name\s*[:\-]\s*(\S+)")
ESC_RE = re.compile(r"\bESC\d+\b")


class AdcsCheck(Check):
    id = "adcs"
    name = "ADCS misconfigurations (certipy)"
    description = "Audit certificate templates for ESC1-16 misconfigurations via certipy find -vulnerable"
    requires_auth = True
    requires_tools = ("certipy",)

    def run(self, ctx):
        argv = ["find", "-u", f"{ctx.username}@{ctx.domain}", "-dc-ip", ctx.dc_ip, "-vulnerable", "-stdout"]
        if ctx.kerberos:
            argv.append("-k")
            if ctx.dc_fqdn:
                argv += ["-target", ctx.dc_fqdn]
        if ctx.password is not None:
            argv += ["-p", ctx.password]
        elif ctx.hashes:
            argv += ["-hashes", ctx.hashes]

        cp = run_tool(ctx, "certipy", argv)
        stdout = cp.stdout or ""
        stderr = cp.stderr or ""
        self.save_raw(ctx, stdout + ("\n--- stderr ---\n" + stderr if stderr else ""), "certipy")

        findings = []
        seen = set()
        template = ""
        for line in stdout.splitlines():
            m = TEMPLATE_RE.search(line)
            if m:
                template = m.group(1)
            for esc in ESC_RE.findall(line):
                key = (esc, template)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self.f(
                    f"{esc} in template {template or '<unknown>'}",
                    severity="HIGH",
                    host=ctx.dc_ip,
                    detail=f"certipy reported {esc} for certificate template '{template or '<unknown>'}'",
                    evidence=[line.strip()],
                ))

        if not findings:
            if cp.returncode == 0:
                findings.append(self.f(
                    "No vulnerable certificate templates reported by certipy",
                    severity="OK",
                    host=ctx.dc_ip,
                    detail="certipy find -vulnerable completed without reporting ESC vulnerabilities",
                ))
            else:
                tail = [ln for ln in stderr.splitlines() if ln.strip()][-5:]
                findings.append(self.f(
                    "certipy failed to enumerate ADCS",
                    severity="INFO",
                    host=ctx.dc_ip,
                    detail=f"certipy exited with code {cp.returncode}",
                    evidence=tail,
                ))
        return findings
