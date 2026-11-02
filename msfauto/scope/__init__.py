"""Authorization scope parsing and policy construction."""
from .manager import PROFILES, ScopeError, build_policy, parse_ports, parse_targets

__all__ = ["PROFILES", "ScopeError", "build_policy", "parse_ports", "parse_targets"]
