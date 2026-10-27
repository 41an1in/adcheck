from ..core import Finding, expand_targets, run_tool
from .base import Check


class NullRpcCheck(Check):
    id = "nullrpc"
    name = "NULL sessions over RPC"
    description = "Test anonymous (NULL session) RPC access via rpcclient"
    requires_auth = False
    requires_tools = ("rpcclient",)

    def run(self, ctx) -> list[Finding]:
        findings: list[Finding] = []
        denied: list[str] = []
        unknown: list[str] = []
        raw: list[str] = []
        for host in expand_targets(ctx)[:64]:
            cp = run_tool(ctx, "rpcclient", ["-U", "", "-N", "-c", "srvinfo", host], timeout=30)
            out = (cp.stdout or "") + (cp.stderr or "")
            raw.append(f"### rpcclient -U '' -N -c srvinfo {host} (rc={cp.returncode})\n{out}")
            if "NT_STATUS_LOGON_FAILURE" in out or "NT_STATUS_ACCESS_DENIED" in out:
                denied.append(host)
            elif "platform_id" in out:
                cp2 = run_tool(ctx, "rpcclient", ["-U", "", "-N", "-c", "enumdomusers", host], timeout=30)
                out2 = (cp2.stdout or "") + (cp2.stderr or "")
                raw.append(f"### rpcclient -U '' -N -c enumdomusers {host} (rc={cp2.returncode})\n{out2}")
                if "user:" in out2:
                    users = [line.strip() for line in out2.splitlines() if "user:" in line][:5]
                    findings.append(self.f(
                        "NULL session allows domain user enumeration",
                        severity="HIGH",
                        host=host,
                        detail="Anonymous RPC session succeeded and enumdomusers returned domain accounts",
                        evidence=users,
                    ))
                else:
                    findings.append(self.f(
                        "NULL session permitted (srvinfo readable)",
                        severity="MEDIUM",
                        host=host,
                        detail="Anonymous RPC session succeeded; server information disclosed",
                    ))
            else:
                unknown.append(host)
        if denied:
            findings.append(self.f(
                "NULL sessions denied",
                severity="OK",
                detail=f"Anonymous RPC logon rejected on {len(denied)} host(s)",
                evidence=denied,
            ))
        if unknown:
            findings.append(self.f(
                "NULL session check inconclusive",
                severity="INFO",
                detail=f"No conclusive response (timeout/unreachable) from {len(unknown)} host(s)",
                evidence=unknown,
            ))
        self.save_raw(ctx, "\n\n".join(raw))
        return findings
