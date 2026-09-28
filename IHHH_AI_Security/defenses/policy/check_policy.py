"""정책 파일(rules.yaml)을 불러와 단일 도구 호출을 검사하는 CLI/라이브러리.

라이브러리로 사용:
    from defenses.policy.check_policy import load_policy, check_policy
    allowed, msg = check_policy("read_files", {"path": "secrets.txt"})

CLI로 사용:
    python defenses/policy/check_policy.py read_files '{"path": "secrets.txt"}'
"""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Any, Dict, Optional, Tuple

import yaml

_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from progent.policy import Effect, Policy, Rule  # noqa: E402

RULES_PATH = pathlib.Path(__file__).parent / "rules.yaml"


def load_policy(path: pathlib.Path = RULES_PATH) -> Policy:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    rules = [
        Rule(d["tool"], Effect(d["effect"]), d.get("when", {}), d.get("fallback_msg", ""))
        for d in data
    ]
    return Policy(rules)


def check_policy(tool: str, args: Dict[str, Any], policy: Optional[Policy] = None) -> Tuple[bool, str]:
    """제안된 도구 호출 하나가 (기본값: rules.yaml의) 정책 하에서 허용되는지 검사.

    반환값: (allowed, message)
    """
    policy = policy or load_policy()
    decision = policy.check(tool, args)
    return decision.allowed, decision.message


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("사용법: python check_policy.py <tool> '<json args>'", file=sys.stderr)
        raise SystemExit(1)
    tool_name = sys.argv[1]
    call_args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    is_allowed, message = check_policy(tool_name, call_args)
    print(
        json.dumps(
            {"tool": tool_name, "args": call_args, "allowed": is_allowed, "message": message},
            ensure_ascii=False,
        )
    )
