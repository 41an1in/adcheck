import re

from ..core import Finding, nxc_auth, parse_nxc_lines, run_tool
from .base import Check

WEBDAV_RE = re.compile(r"(?i)webdav|webclient")


class WebdavCheck(Check):
    id = "webdav"
    name = "WebDAV (WebClient service)"
    description = "Finds hosts running the WebClient (WebDAV) service, a candidate for coercion + NTLM relay attacks"
    requires_auth = True
    requires_targets = True
    requires_tools = ("nxc",)

    def run(self, ctx) -> list[Finding]:
        cp = run_tool(ctx, "nxc", ["smb", ctx.targets, *nxc_auth(ctx), "-M", "webdav"])
        self.save_raw(ctx, cp.stdout)
        hits: list[tuple[str, str]] = []
        seen: set[str] = set()
        for ip, host, message in parse_nxc_lines(cp.stdout):
            if ip in seen:
                continue
            if WEBDAV_RE.search(message) and ("enabl" in message.lower() or "[+]" in message):
                seen.add(ip)
                hits.append((ip, host))
        if not hits:
            return [self.f("No hosts with WebDAV WebClient service found", severity="OK")]
        return [
            self.f(
                "WebClient (WebDAV) service running — coerce+relay candidate",
                severity="MEDIUM",
                host=ip,
                detail=f"WebClient service enabled on {host or ip}",
            )
            for ip, host in hits
        ]
