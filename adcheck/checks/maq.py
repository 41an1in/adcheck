import re

from ..core import ldap_available, ldap_bind, nxc_auth, run_tool
from .base import Check


class MaqCheck(Check):
    id = "maq"
    name = "MachineAccountQuota"
    description = "Non-zero ms-DS-MachineAccountQuota lets any domain user add computer accounts (RBCD attack path)"
    requires_auth = True
    requires_tools = ()

    def run(self, ctx):
        value = None
        evidence = []
        if ctx.tools.get("nxc"):
            cp = run_tool(ctx, "nxc", ["ldap", ctx.dc_ip, *nxc_auth(ctx), "-M", "maq"])
            raw = (cp.stdout or "") + (cp.stderr or "")
            path = self.save_raw(ctx, raw, "nxc")
            m = re.search(r"MachineAccountQuota\D*(\d+)", raw)
            if m:
                value = int(m.group(1))
            else:
                evidence.append(f"nxc maq output unparsable (raw: {path})")
        if value is None and ldap_available() and ctx.has_password:
            conn = ldap_bind(ctx)
            if conn:
                try:
                    conn.search(ctx.domain_dn, "(objectClass=domain)", attributes=["ms-DS-MachineAccountQuota"])
                    if conn.entries:
                        value = int(conn.entries[0]["ms-DS-MachineAccountQuota"].value)
                    else:
                        evidence.append("LDAP search for domain object returned no entries")
                except Exception as e:
                    evidence.append(f"LDAP lookup failed: {e}")
            else:
                evidence.append("LDAP bind failed")
        if value is None:
            return [self.f("could not determine MachineAccountQuota", severity="INFO",
                           host=ctx.dc_ip, evidence=evidence)]
        if value > 0:
            return [self.f(f"MachineAccountQuota={value} — any domain user can add computer accounts (RBCD attack path)",
                           severity="MEDIUM", host=ctx.dc_ip,
                           detail="Set ms-DS-MachineAccountQuota to 0 and pre-stage computer accounts")]
        return [self.f("MachineAccountQuota=0", severity="OK", host=ctx.dc_ip)]
