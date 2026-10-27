import ssl

from ..core import ldap_available, nxc_auth, run_tool
from .base import Check


class LdapSecCheck(Check):
    id = "ldapsec"
    name = "LDAP signing & channel binding"
    description = "Probes LDAP signing enforcement on port 389 and LDAPS channel binding on port 636"
    requires_auth = True
    requires_tools = ()

    def run(self, ctx):
        findings = []
        probes_conclusive = False

        if ldap_available() and ctx.has_password:
            import ldap3

            finding, conclusive = self._probe_signing(ctx, ldap3)
            findings.append(finding)
            probes_conclusive = conclusive
            finding, conclusive = self._probe_ldaps(ctx, ldap3)
            findings.append(finding)
            probes_conclusive = probes_conclusive and conclusive
        else:
            reasons = []
            if not ldap_available():
                reasons.append("ldap3 library not installed")
            if not ctx.has_password:
                reasons.append("no plaintext password available for bind probes")
            findings.append(self.f(
                "LDAP signing/channel binding probes skipped",
                severity="INFO",
                host=ctx.dc_ip,
                detail="; ".join(reasons),
            ))

        if ctx.tools.get("nxc"):
            findings.append(self._nxc_corroboration(ctx, probes_conclusive))

        return findings

    def _probe_signing(self, ctx, ldap3):
        try:
            server = ldap3.Server(ctx.dc_ip, port=389)
            conn = ldap3.Connection(
                server,
                user=f"{ctx.domain}\\{ctx.username}",
                password=ctx.password,
                authentication=ldap3.NTLM,
            )
            bound = conn.bind()
            if bound:
                conn.unbind()
            result = conn.result or {}
        except Exception as e:
            return self.f(
                "LDAP signing check inconclusive",
                severity="INFO",
                host=ctx.dc_ip,
                detail=f"NTLM bind attempt failed: {e}",
            ), False
        if bound:
            return self.f(
                "LDAP signing not enforced (unsigned NTLM bind succeeded)",
                severity="HIGH",
                host=ctx.dc_ip,
                detail="DC accepted an unsigned NTLM LDAP bind on port 389",
                evidence=[str(result)],
            ), True
        if "strongerAuthRequired" in str(result.get("description", "")):
            return self.f(
                "LDAP signing enforced",
                severity="OK",
                host=ctx.dc_ip,
                detail="DC rejected the unsigned bind with strongerAuthRequired",
                evidence=[str(result)],
            ), True
        return self.f(
            "LDAP signing check inconclusive",
            severity="INFO",
            host=ctx.dc_ip,
            detail="unsigned NTLM bind failed without a signing-specific error",
            evidence=[str(result)],
        ), False

    def _probe_ldaps(self, ctx, ldap3):
        try:
            tls = ldap3.Tls(validate=ssl.CERT_NONE)
            server = ldap3.Server(ctx.dc_ip, port=636, use_ssl=True, tls=tls)
            conn = ldap3.Connection(
                server,
                user=f"{ctx.username}@{ctx.domain}",
                password=ctx.password,
                authentication=ldap3.SIMPLE,
            )
            bound = conn.bind()
            if bound:
                conn.unbind()
            result = conn.result or {}
        except Exception as e:
            return self.f(
                "LDAPS channel binding check inconclusive",
                severity="INFO",
                host=ctx.dc_ip,
                detail=f"LDAPS simple bind attempt failed: {e}",
            ), False
        if bound:
            return self.f(
                "LDAPS channel binding likely not enforced (bind without channel-binding token succeeded)",
                severity="MEDIUM",
                host=ctx.dc_ip,
                detail="DC accepted an LDAPS simple bind without a channel-binding token",
                evidence=[str(result)],
            ), True
        return self.f(
            "LDAPS channel binding check inconclusive",
            severity="INFO",
            host=ctx.dc_ip,
            detail="LDAPS simple bind failed; enforcement cannot be distinguished from other bind failures",
            evidence=[str(result)],
        ), False

    def _nxc_corroboration(self, ctx, probes_conclusive):
        cp = run_tool(ctx, "nxc", ["ldap", ctx.dc_ip, *nxc_auth(ctx), "-M", "ldap-checker"])
        output = (cp.stdout or "") + (cp.stderr or "")
        raw = self.save_raw(ctx, output)
        lines = [
            line.strip()
            for line in output.splitlines()
            if "signing" in line.lower() or "channel binding" in line.lower()
        ]
        severity = "INFO"
        title = "netexec ldap-checker corroboration"
        if not probes_conclusive:
            text = output.lower()
            if any(w in text for w in ("not enforced", "disabled", "never")):
                severity = "HIGH"
                title = "LDAP signing/channel binding not enforced (per nxc ldap-checker)"
            elif any(w in text for w in ("enforced", "required")):
                severity = "OK"
                title = "LDAP signing/channel binding enforced (per nxc ldap-checker)"
        return self.f(
            title,
            severity=severity,
            host=ctx.dc_ip,
            detail=f"raw output saved to {raw}",
            evidence=lines,
        )
