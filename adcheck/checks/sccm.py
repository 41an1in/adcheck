from ..core import Finding, run_tool, tool_supports
from .base import Check


class SccmCheck(Check):
    id = "sccm"
    name = "SCCM/MECM discovery (sccmhunter)"
    description = "Discovers SCCM/MECM site servers, management points, distribution points and PXE with sccmhunter"
    requires_auth = True
    requires_tools = ("sccmhunter",)

    def run(self, ctx) -> list[Finding]:
        workdir = ctx.output_dir / "sccm"
        workdir.mkdir(parents=True, exist_ok=True)
        needles = ("site server", "management point", "distribution point", "mssql", "sccm", "pxe")
        evidence = []
        for module in ("find", "smb", "http"):
            argv = [module, "-u", ctx.username, "-d", ctx.domain, "-dc-ip", ctx.dc_ip]
            if ctx.password is not None:
                argv += ["-p", ctx.password]
            elif ctx.hashes and tool_supports(ctx, "sccmhunter", "hashes", sub=[module]):
                argv += ["-hashes", ctx.hashes]
            else:
                return [self.f("skipped: sccmhunter requires password auth here")]
            if ctx.kerberos and tool_supports(ctx, "sccmhunter", "-k", sub=[module]):
                argv.append("-k")
            cp = run_tool(ctx, "sccmhunter", argv, cwd=workdir)
            out = (cp.stdout or "") + (cp.stderr or "")
            self.save_raw(ctx, out, module)
            for line in out.splitlines():
                line = line.strip()
                if line and (line.startswith("[+]") or any(n in line.lower() for n in needles)):
                    evidence.append(line)
        if evidence:
            severity = "MEDIUM" if any("admin" in line.lower() for line in evidence) else "INFO"
            return [self.f("SCCM infrastructure discovered", severity=severity, evidence=evidence)]
        return [self.f("No SCCM infrastructure discovered", severity="OK")]
