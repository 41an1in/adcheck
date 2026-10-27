from ..core import parse_nxc_lines, run_tool
from .base import Check


class SmbSigningCheck(Check):
    id = "smbsigning"
    name = "SMB signing enforcement"
    description = "Find hosts that do not require SMB signing (NTLM relay candidates)"
    requires_auth = False
    requires_targets = True
    requires_tools = ("nxc",)

    def run(self, ctx):
        relay_out = ctx.raw_dir / "smb_relay_targets.txt"
        argv = ["smb", ctx.targets, "--gen-relay-list", str(relay_out)]
        cp = run_tool(ctx, "nxc", argv)
        raw = (cp.stdout or "") + (cp.stderr or "")
        self.save_raw(ctx, raw)

        unsigned = []
        signed = 0
        for ip, host, message in parse_nxc_lines(cp.stdout or ""):
            if "signing:False" in message:
                unsigned.append((ip, host, message))
            elif "signing:True" in message:
                signed += 1

        findings = []
        for ip, host, message in unsigned:
            findings.append(self.f(
                "SMB signing not required — NTLM relay candidate",
                severity="MEDIUM",
                host=ip,
                detail=f"name: {host}" if host else "",
                evidence=[message],
            ))
        if unsigned:
            findings.append(self.f(
                f"{len(unsigned)} host(s) do not enforce SMB signing",
                severity="INFO",
                detail=f"NTLM relay target list written to {relay_out}",
            ))
        if signed:
            findings.append(self.f(f"{signed} hosts require SMB signing", severity="OK"))
        if not unsigned and not signed:
            findings.append(self.f(
                "No SMB signing results",
                severity="INFO",
                detail="No hosts parsed from nxc output — targets may be down or unreachable",
            ))
        return findings
