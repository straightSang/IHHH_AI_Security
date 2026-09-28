# yaml 파일 형태의 정책을 로드해서 그 규칙들을 Rule 객체들로 만들고, 
# 그걸 Policy 객체 안에 담아서 반환한다. 
# 이후 도구호출 요청이 들어오면 관련된 규칙을 로드해서 해당 도구 호출이 허용되는지 검사한 후 (허용여부, 메세지) 를 정리해서 반환한다.


from __future__ import annotations 

import json
import pathlib
import sys
from typing import Any, Dict, Optional, Tuple

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from progent.policy import Effect, Policy, Rule # noqa: E402

RULES_PATH = pathlib.Path(__file__).parent / "rules.yaml"

# 함수이름: load_policy
# 인자:   path (경로, 기본값 RULES_PATH)
# 반환값: Policy 객체 (규칙 여러 개를 담은 상자)
# 기능:   yaml 파일을 읽어서, 그 안의 규칙들을 progent.policy의
#         Rule 객체들로 하나씩 만들고, 그것들을 Policy 안에 넣어서 반환.
def load_policy(path: pathlib.Path = RULES_PATH) -> Policy:
    data = yaml.safe_load(path.read_text(encoding='utf-8')) or []
    rules = [
        Rule(d["tool"], Effect(d["effect"]), d.get("when", {}), d.get("fallback_mag", ""))
        for d in data
    ]

    return Policy(rules)


# 함수이름: check_policy
# 인자:   tool (도구 이름), args (그 도구에 줄 인자들), policy (선택, 없으면 rules.yaml 자동 로드)
# 반환값: (allowed: bool, message: str) 튜플
# 기능:   정책 하나를 로드해서(안 주면 rules.yaml에서 자동으로), 이 도구 호출이
#         허용되는지 policy.check()에게 물어보고, (허용여부, 이유메시지)로 정리해 반환.
def check_policy(tool: str, args: Dict[str, Any], policy: Optional[Policy] = None) -> Tuple[bool, str]:
    # 제안된 도구가 정책에서 허용되는지 검사한다
    # 반환값 (allowed, msg)
    policy = policy or load_policy()
    decision = policy.check(tool, args)
    return decision.allowed, decision.message



if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("사용법: python3 check_policy.py <tool> '<json args>'", file=sys.stderr)
        raise SystemExit(1)
    tool_name = sys.argv[1]
    call_args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    is_allowed, message = check_policy(tool_name, call_args)
    print(
        json.dumps({"tool": tool_name, "args": call_args, "allowed": is_allowed, "message":message}, ensure_ascii=False)
    )