import re

from ..core import nxc_auth, parse_nxc_lines, run_tool
from .base import Check

SHARE_ROW = re.compile(r"^(?P<share>.+?)\s{2,}(?P<perms>(READ|WRITE)(,\s*(READ|WRITE))?)\s*(?P<remark>.*)$")
DEFAULT_SHARES = {"SYSVOL", "NETLOGON", "IPC$", "ADMIN$", "C$", "print$"}
ADMIN_SHARES = ("ADMIN$", "C$")


class SharesCheck(Check):
    id = "shares"
    name = "Readable/writable SMB shares"
    description = "Enumerate SMB shares on targets and flag writable or non-default readable shares"
    requires_auth = True
    requires_targets = True
    requires_tools = ("nxc",)

    def run(self, ctx) -> list:
        cp = run_tool(ctx, "nxc", ["smb", ctx.targets, *nxc_auth(ctx), "--shares"])
        self.save_raw(ctx, cp.stdout + cp.stderr)
        findings = []
        enum_hosts = {ip for ip, _, msg in parse_nxc_lines(cp.stdout) if "Enumerated shares" in msg}
        for line in cp.stdout.splitlines():
            parts = line.split(None, 4)
            if len(parts) < 5:
                continue
            proto, ip, port, message = parts[0], parts[1], parts[2], parts[4]
            if not (proto.isalpha() and proto.isupper() and port.isdigit()):
                continue
            if ip not in enum_hosts or "ACCESS_DENIED" in message:
                continue
            m = SHARE_ROW.match(message)
            if not m:
                continue
            share = m.group("share").strip()
            perms = m.group("perms")
            remark = m.group("remark").strip()
            detail = f"permissions: {perms}" + (f"; remark: {remark}" if remark else "")
            if "WRITE" in perms:
                if share in ADMIN_SHARES:
                    findings.append(self.f(f"admin write access to {share}", severity="HIGH", host=ip, detail=detail))
                else:
                    findings.append(self.f(f"writable share {share}", severity="HIGH", host=ip, detail=detail))
            elif share not in DEFAULT_SHARES:
                findings.append(self.f(f"readable share {share}", severity="LOW", host=ip, detail=detail))
        if not findings:
            findings.append(self.f(
                "no interesting shares found",
                severity="OK",
                detail="no writable or non-default readable shares on any target",
            ))
        return findings
