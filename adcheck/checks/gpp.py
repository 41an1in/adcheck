import re

from ..core import nxc_auth, run_tool
from .base import Check


class GppCheck(Check):
    id = "gpp"
    name = "GPP cpasswords in SYSVOL"
    description = "Search SYSVOL for Group Policy Preferences password material"
    requires_auth = True
    requires_tools = ("nxc",)

    def run(self, ctx) -> list:
        cp = run_tool(ctx, "nxc", ["smb", ctx.dc_ip, *nxc_auth(ctx), "-M", "gpp_password"])
        self.save_raw(ctx, (cp.stdout or "") + (cp.stderr or ""))
        evidence = []
        for line in (cp.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            if (
                "cpassword" in line
                or re.search(r"(?i)(password|username)\s*[:=]", line)
                or (".xml" in line and "[+]" in line)
            ):
                evidence.append(line)
        if any("cpassword" in line or re.search(r"(?i)password\s*[:=]", line) for line in evidence):
            return [
                self.f(
                    "GPP password material found in SYSVOL",
                    severity="HIGH",
                    host=ctx.dc_ip,
                    detail="GPP credentials exposed in SYSVOL XML; the cpassword AES key is public.",
                    evidence=evidence,
                )
            ]
        if evidence:
            return [
                self.f(
                    "GPP XML files present (review manually)",
                    severity="MEDIUM",
                    host=ctx.dc_ip,
                    detail="GPP XML artifacts found in SYSVOL; review them for credential material.",
                    evidence=evidence,
                )
            ]
        return [self.f("No GPP passwords found", severity="OK", host=ctx.dc_ip)]
