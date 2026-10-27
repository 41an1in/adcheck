import argparse
import traceback
from datetime import datetime
from pathlib import Path

from .checks import discover_checks
from .core import SEVERITIES, Context, Finding, ToolNotFound, cprint, resolve_tools
from .report import write_reports


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="adcheck",
        description="Active Directory security audit orchestrator (read-only checks)",
    )
    parser.add_argument("-d", "--domain", help="AD domain, e.g. corp.local")
    parser.add_argument("--dc-ip", dest="dc_ip", help="domain controller IP")
    parser.add_argument("--dc-fqdn", dest="dc_fqdn", default="", help="domain controller FQDN")
    parser.add_argument("-u", "--username", default="")
    parser.add_argument("-p", "--password", default=None)
    parser.add_argument("-H", "--hashes", default="", help="LM:NT or :NT")
    parser.add_argument("-k", "--kerberos", action="store_true", help="use Kerberos authentication")
    parser.add_argument("--targets", default="", help="IP, CIDR, or file with one target per line (default: --dc-ip)")
    parser.add_argument("-o", "--output", default=None, help="output directory (default: adcheck_<domain>_<timestamp>)")
    parser.add_argument("--checks", default=None, help="comma-separated check ids to run (default: all)")
    parser.add_argument("--skip", default=None, help="comma-separated check ids to skip")
    parser.add_argument("--timeout", type=int, default=300, help="per-tool timeout in seconds")
    parser.add_argument("--sccmhunter", default=None, metavar="PATH", help="explicit path to sccmhunter")
    parser.add_argument("--pre2k", default=None, metavar="PATH", help="explicit path to pre2k")
    parser.add_argument("--no-color", dest="no_color", action="store_true")
    parser.add_argument("--list", dest="list_checks", action="store_true", help="list discovered checks and exit")
    args = parser.parse_args()

    checks = discover_checks()
    if args.list_checks:
        for c in checks:
            print(f"{c.id}\t{c.name}\t{c.description}\trequires_auth={c.requires_auth}")
        return 0

    missing = []
    if not args.domain:
        missing.append("-d/--domain")
    if not args.dc_ip:
        missing.append("--dc-ip")
    if missing:
        parser.error(f"the following arguments are required: {', '.join(missing)}")

    if args.output:
        output_dir = Path(args.output)
    else:
        output_dir = Path(f"adcheck_{args.domain}_{datetime.now():%Y%m%d_%H%M%S}")
    raw_dir = output_dir / "raw"

    ctx = Context(
        domain=args.domain,
        dc_ip=args.dc_ip,
        dc_fqdn=args.dc_fqdn,
        username=args.username,
        password=args.password,
        hashes=args.hashes,
        kerberos=args.kerberos,
        targets=args.targets or args.dc_ip,
        output_dir=output_dir,
        raw_dir=raw_dir,
        timeout=args.timeout,
        no_color=args.no_color,
    )
    raw_dir.mkdir(parents=True, exist_ok=True)

    resolve_tools(ctx, sccmhunter_path=args.sccmhunter, pre2k_path=args.pre2k)
    for key, path in ctx.tools.items():
        print(f"tool {key}: {path or 'MISSING'}")

    known = {c.id for c in checks}
    selected = list(checks)
    if args.checks:
        wanted = [s.strip() for s in args.checks.split(",") if s.strip()]
        unknown = [w for w in wanted if w not in known]
        if unknown:
            parser.error(f"unknown check id(s): {', '.join(unknown)}")
        selected = [c for c in selected if c.id in wanted]
    if args.skip:
        skipped = {s.strip() for s in args.skip.split(",") if s.strip()}
        unknown = [s for s in skipped if s not in known]
        if unknown:
            parser.error(f"unknown check id(s): {', '.join(unknown)}")
        selected = [c for c in selected if c.id not in skipped]

    started = datetime.now()
    findings: list[Finding] = []
    for check in selected:
        print(f"\n=== {check.id}: {check.name} ===")
        ok, reason = check.available(ctx)
        if not ok:
            print(f"SKIP {check.id}: {reason}")
            continue
        try:
            results = check.run(ctx)
        except ToolNotFound as e:
            print(f"SKIP {check.id}: tool not found ({e})")
            continue
        except Exception:
            results = [
                Finding(check=check.id, title="check crashed", severity="INFO", detail=traceback.format_exc())
            ]
        findings.extend(results)
        for f in results:
            cprint(ctx, f.severity, f"({f.host}) {f.title}" if f.host else f.title)

    write_reports(ctx, findings, started)
    counts = {sev: 0 for sev in SEVERITIES}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    print("\nsummary: " + ", ".join(f"{sev}={counts[sev]}" for sev in SEVERITIES))
    print(f"reports written to {output_dir}/ (findings.json, summary.txt, report.html)")
    return 0
