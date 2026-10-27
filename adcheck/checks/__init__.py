import importlib
import inspect
import pkgutil
import sys

from .base import Check


def discover_checks() -> list[Check]:
    checks: dict[str, Check] = {}
    for mod_info in pkgutil.iter_modules(__path__):
        if mod_info.name == "base":
            continue
        try:
            module = importlib.import_module(f".{mod_info.name}", __package__)
        except Exception as e:
            print(f"warning: failed to import check module '{mod_info.name}': {e}", file=sys.stderr)
            continue
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, Check) and obj is not Check:
                inst = obj()
                checks[inst.id] = inst
    return [checks[check_id] for check_id in sorted(checks)]
