from ..core import Finding


class Check:
    id = "base"
    name = ""
    description = ""
    requires_auth = True  # check needs valid domain credentials
    requires_targets = False  # informational only
    requires_tools: tuple[str, ...] = ()  # keys into ctx.tools

    def available(self, ctx) -> tuple[bool, str]:
        if self.requires_auth and not ctx.has_creds:
            return False, "requires domain credentials"
        for tool in self.requires_tools:
            if not ctx.tools.get(tool):
                return False, f"missing tool: {tool}"
        return True, ""

    def run(self, ctx) -> list[Finding]:
        raise NotImplementedError

    def save_raw(self, ctx, text: str, suffix: str = "") -> str:
        name = f"{self.id}{('_' + suffix) if suffix else ''}.log"
        path = ctx.raw_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return str(path)

    def f(self, title, severity="INFO", host="", detail="", evidence=None) -> Finding:
        return Finding(
            check=self.id,
            title=title,
            severity=severity,
            host=host,
            detail=detail,
            evidence=list(evidence) if evidence else [],
        )
