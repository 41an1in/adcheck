import json
import zipfile

from ..core import Finding, run_tool, tool_supports
from .base import Check


class BloodhoundCheck(Check):
    id = "bloodhound"
    name = "BloodHound CE data collection"
    description = "Collects domain data with bloodhound-ce-python for BloodHound CE ingestion"
    requires_auth = True
    requires_tools = ("bloodhound",)

    def run(self, ctx) -> list[Finding]:
        bhdir = ctx.output_dir / "bloodhound"
        bhdir.mkdir(parents=True, exist_ok=True)
        argv = ["-d", ctx.domain, "-u", ctx.username, "-ns", ctx.dc_ip, "-c", "All", "--zip", "-op", str(bhdir / "bh")]
        if ctx.kerberos and tool_supports(ctx, "bloodhound", "-k"):
            argv.append("-k")
        if ctx.password is not None:
            argv += ["-p", ctx.password]
        elif ctx.hashes and tool_supports(ctx, "bloodhound", "hashes"):
            argv += ["-hashes", ctx.hashes]
        elif "-k" not in argv:
            return [self.f("skipped: bloodhound needs password or supported hashes")]
        if ctx.dc_fqdn:
            argv += ["-dc", ctx.dc_fqdn]
        cp = run_tool(ctx, "bloodhound", argv, timeout=max(ctx.timeout, 900), cwd=bhdir)
        out = (cp.stdout or "") + (cp.stderr or "")
        self.save_raw(ctx, out)
        zips = list(bhdir.glob("*.zip"))
        if not zips:
            tail = [line for line in out.splitlines() if line.strip()][-20:]
            return [self.f("collection produced no zip", detail=f"exit code {cp.returncode}", evidence=tail)]
        zpath = max(zips, key=lambda p: p.stat().st_mtime)
        evidence = []
        with zipfile.ZipFile(zpath) as zf:
            for name in sorted(zf.namelist()):
                if not name.endswith(".json"):
                    continue
                try:
                    with zf.open(name) as fh:
                        obj = json.load(fh)
                except Exception:
                    continue
                count = len(obj.get("data", [])) if isinstance(obj, dict) else 0
                evidence.append(f"{name}: {count} objects")
        return [self.f("BloodHound collection complete", detail=f"zip: {zpath}", evidence=evidence)]
