from datetime import datetime, timezone
from time import time

from ..core import ldap_available, ldap_bind
from .base import Check


class AzureSsoCheck(Check):
    id = "azuresso"
    name = "AZUREADSSOACC$ (Azure AD Seamless SSO)"
    description = "Detect the AZUREADSSOACC$ computer account used by Azure AD Connect Seamless SSO"
    requires_auth = True
    requires_tools = ()

    def run(self, ctx):
        if not ldap_available() or not ctx.has_password:
            return [self.f("skipped: requires ldap3 and password auth", "INFO")]
        conn = ldap_bind(ctx)
        if conn is None:
            return [self.f("LDAP bind failed", "INFO", host=ctx.dc_ip)]
        conn.search(
            ctx.domain_dn,
            "(&(objectClass=computer)(sAMAccountName=AZUREADSSOACC$))",
            attributes=["sAMAccountName", "dNSHostName", "pwdLastSet", "whenCreated"],
        )
        if not conn.entries:
            return [self.f(
                "AZUREADSSOACC$ not found",
                "OK",
                host=ctx.dc_ip,
                detail="Azure AD Seamless SSO does not appear to be enabled in this domain",
            )]
        entry = conn.entries[0]
        evidence = [f"sAMAccountName: {entry.sAMAccountName.value}", f"whenCreated: {entry.whenCreated.value}"]
        pls = entry.pwdLastSet.value
        epoch = None
        if isinstance(pls, datetime):
            epoch = (pls if pls.tzinfo else pls.replace(tzinfo=timezone.utc)).timestamp()
        elif isinstance(pls, (int, float)):
            epoch = pls / 10**7 - 11644473600
        if epoch is not None:
            evidence.append(f"password age: {max(0, int((time() - epoch) / 86400))} days")
        return [self.f(
            "AZUREADSSOACC$ present — Azure AD Connect Seamless SSO enabled",
            "MEDIUM",
            host=ctx.dc_ip,
            detail=("The AZUREADSSOACC$ computer account holds the Kerberos keys Azure AD trusts to validate "
                    "Seamless SSO tickets. The keys change rarely, so if the domain is compromised (e.g. via "
                    "DCSync) they enable forging silver tickets for the autologon.microsoftazuread-sso.com "
                    "service and signing in to Azure AD as any synced user."),
            evidence=evidence,
        )]
