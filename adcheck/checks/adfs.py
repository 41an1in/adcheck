import socket

from ..core import ldap_available, ldap_bind
from .base import Check

PREFIXES = ("adfs", "fs", "sts", "sso", "login")
METADATA_URL = "https://{host}/FederationMetadata/2007-06/FederationMetadata.xml"


class AdfsCheck(Check):
    id = "adfs"
    name = "ADFS discovery"
    description = "Discover ADFS hosts via DNS names, federation metadata, and LDAP objects"
    requires_auth = False
    requires_tools = ()

    def run(self, ctx):
        findings = []
        for host, ips in self._resolve(ctx).items():
            evidence = [f"DNS: {host} -> {', '.join(ips)}"]
            if self._probe_metadata(host, evidence):
                findings.append(self.f(
                    f"ADFS federation service confirmed at https://{host}",
                    severity="MEDIUM",
                    host=host,
                    detail="ADFS endpoints are phishing/golden-SAML attack surface",
                    evidence=evidence,
                ))
            else:
                findings.append(self.f(
                    "possible ADFS host (DNS resolves, metadata endpoint not confirmed)",
                    severity="LOW",
                    host=host,
                    detail="hostname commonly used for ADFS resolves in DNS",
                    evidence=evidence,
                ))
        findings.extend(self._ldap(ctx))
        if not findings:
            findings.append(self.f("No ADFS indicators found", severity="OK"))
        return findings

    def _resolve(self, ctx) -> dict:
        out = {}
        for prefix in PREFIXES:
            host = f"{prefix}.{ctx.domain}"
            try:
                infos = socket.getaddrinfo(host, None)
            except OSError:
                continue
            ips = sorted({info[4][0] for info in infos})
            if ips:
                out[host] = ips
        return out

    def _probe_metadata(self, host, evidence) -> bool:
        try:
            import requests
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except ImportError:
            return False
        try:
            resp = requests.get(METADATA_URL.format(host=host), verify=False, timeout=8)
        except Exception:
            return False
        if resp.status_code == 200 and "EntityDescriptor" in resp.text:
            evidence.append(f"GET {METADATA_URL.format(host=host)} -> 200 (EntityDescriptor present)")
            return True
        return False

    def _ldap(self, ctx) -> list:
        findings = []
        if not (ldap_available() and ctx.has_password):
            return findings
        conn = ldap_bind(ctx)
        if conn is None:
            return findings
        try:
            conn.search(
                ctx.domain_dn,
                "(|(sAMAccountName=*adfs*)(servicePrincipalName=*adfs*))",
                attributes=["sAMAccountName"],
            )
            objects = self._names(conn)
            if objects:
                findings.append(self.f(
                    "ADFS-related AD objects found",
                    severity="INFO",
                    detail="accounts with 'adfs' in sAMAccountName or servicePrincipalName",
                    evidence=objects,
                ))
            conn.search(
                ctx.domain_dn,
                "(objectClass=msDS-GroupManagedServiceAccount)",
                attributes=["sAMAccountName"],
            )
            gmsas = self._names(conn)
            if gmsas:
                findings.append(self.f(
                    "gMSA accounts found",
                    severity="INFO",
                    detail="group Managed Service Accounts (ADFS commonly uses one)",
                    evidence=gmsas,
                ))
        except Exception:
            pass
        finally:
            try:
                conn.unbind()
            except Exception:
                pass
        return findings

    def _names(self, conn) -> list:
        out = set()
        for entry in conn.entries:
            for value in entry.entry_attributes_as_dict.get("sAMAccountName", []):
                out.add(str(value))
        return sorted(out)
