import html
import json
from datetime import datetime

from . import __version__
from .core import SEVERITIES, Finding


def write_reports(ctx, findings: list[Finding], started: datetime) -> None:
    duration = round((datetime.now() - started).total_seconds(), 2)
    meta = {
        "tool": "adcheck",
        "version": __version__,
        "domain": ctx.domain,
        "dc_ip": ctx.dc_ip,
        "date": started.isoformat(),
        "duration_s": duration,
    }
    (ctx.output_dir / "findings.json").write_text(
        json.dumps({"meta": meta, "findings": [f.to_dict() for f in findings]}, indent=2) + "\n"
    )

    counts = {sev: 0 for sev in SEVERITIES}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines = [
        f"adcheck summary - {ctx.domain} ({ctx.dc_ip})",
        f"date: {meta['date']}",
        f"duration_s: {duration}",
        "",
    ]
    lines += [f"{sev}: {counts.get(sev, 0)}" for sev in SEVERITIES]
    lines.append("")
    for f in findings:
        if f.severity == "OK":
            continue
        host = f" ({f.host})" if f.host else ""
        lines.append(f"[{f.severity}] {f.check}: {f.title}{host}")
    (ctx.output_dir / "summary.txt").write_text("\n".join(lines) + "\n")

    esc = html.escape
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.check, []).append(f)

    toc = "\n".join(
        f'<li><a href="#check-{esc(check_id)}">{esc(check_id)}</a> ({len(items)})</li>'
        for check_id, items in sorted(groups.items())
    )
    sections = []
    for check_id, items in sorted(groups.items()):
        parts = [f'<h2 id="check-{esc(check_id)}">{esc(check_id)} ({len(items)})</h2>']
        for f in items:
            host = f' <span class="host">{esc(f.host)}</span>' if f.host else ""
            detail = f"<p>{esc(f.detail)}</p>" if f.detail else ""
            evidence = ""
            if f.evidence:
                evidence = "<ul>" + "".join(f"<li>{esc(e)}</li>" for e in f.evidence) + "</ul>"
            parts.append(
                '<div class="finding">'
                f'<span class="badge sev-{esc(f.severity)}">{esc(f.severity)}</span> '
                f"<strong>{esc(f.title)}</strong>{host}{detail}{evidence}"
                "</div>"
            )
        sections.append("\n".join(parts))

    badges = " ".join(
        f'<span class="badge sev-{sev}">{sev}</span>&nbsp;{counts.get(sev, 0)}' for sev in SEVERITIES
    )
    date_iso = meta["date"]
    body = "\n".join(sections)
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>adcheck report - {esc(ctx.domain)}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #222; }}
h1 {{ border-bottom: 2px solid #ccc; padding-bottom: .3rem; }}
.meta {{ color: #555; }}
.badge {{ display: inline-block; min-width: 4em; text-align: center; padding: .15em .5em; border-radius: 4px; color: #fff; font-size: .8em; font-weight: 700; }}
.sev-OK {{ background: #2e7d32; }}
.sev-INFO {{ background: #616161; }}
.sev-LOW {{ background: #1565c0; }}
.sev-MEDIUM {{ background: #f9a825; }}
.sev-HIGH {{ background: #c62828; }}
.finding {{ border: 1px solid #ddd; border-radius: 6px; padding: .7rem 1rem; margin: .6rem 0; }}
.host {{ font-family: monospace; color: #555; }}
</style>
</head>
<body>
<h1>adcheck report</h1>
<p class="meta">domain {esc(ctx.domain)} &middot; dc {esc(ctx.dc_ip)} &middot; {esc(date_iso)} &middot; {duration}s</p>
<p>{badges}</p>
<h2>Contents</h2>
<ul>
{toc}
</ul>
{body}
</body>
</html>
"""
    (ctx.output_dir / "report.html").write_text(page)
