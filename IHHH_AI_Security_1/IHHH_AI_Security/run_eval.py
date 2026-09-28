"""실습 3 — 자동 실행기 (run_eval.py) + 실습 5 — 정책 엔진 ON/OFF 비교.

    YAML을 읽어 -> 미끼를 심고 -> 에이전트를 1회 실행하고 -> judge()로
    판정하고 -> 개수를 센다.

사용법
------
    # 공격 케이스 20개, 정책 없이(무방어) 실행 — 실습3
    python run_eval.py

    # 공격 케이스 20개, 정책 켜고 실행 — 실습5 (ON)
    python run_eval.py --policy

    # 정상 요청(유용성) 케이스 5개로 "막지 말아야 할 것을 막았는지" 확인 — 실습5-4
    python run_eval.py --policy --utility

실행할 때마다:
  * 콘솔에 케이스별 "ATTACK OK / BLOCKED" (또는 유용성 모드에서는 "OK / BLOCKED")
  * results/baseline_<on|off>[_utility].json  : 케이스별 결과 요약 + ASR
  * results/traces/<on|off>[_utility]/<id>.json : 케이스별 전체 TRACE 로그
가 남는다 (요청하신 "실행시키면 trace 로그가 남게" 부분).
"""

from __future__ import annotations

import argparse
import glob
import json
import pathlib
import sys
from typing import Any, Callable, Dict, List, Optional

import yaml

_ROOT = pathlib.Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from evaluator import (  # noqa: E402
    judge,
    judge_not_blocked,
    make_traced_tools,
    new_trace,
    plant_payload,
)
from progent.policy import Policy  # noqa: E402
from run_agent import run_agent  # noqa: E402

COURSE_POLICY_PATH = _ROOT / "attacks_course" / "policy" / "course_policy.yaml"
RESULTS_DIR = _ROOT / "results"


def load_cases(path: str = "attacks_course/*.yaml") -> List[dict]:
    return [
        yaml.safe_load(open(f, encoding="utf-8"))
        for f in sorted(glob.glob(str(_ROOT / path)))
    ]


def load_course_policy() -> Policy:
    data = yaml.safe_load(COURSE_POLICY_PATH.read_text(encoding="utf-8")) or []
    return Policy.from_dict(data)


def make_policy_check(enabled: bool) -> Optional[Callable[[str, dict], str]]:
    """실습5의 check_policy(name, args) -> "allow"/"deny" 를 만든다.

    enabled=False 면 None을 반환해서(=정책 없이 실행) 기존 무방어 베이스라인과
    동일하게 동작한다."""
    if not enabled:
        return None
    policy = load_course_policy()

    def check_policy(tool: str, args: dict) -> str:
        decision = policy.check(tool, args)
        return "allow" if decision.allowed else "deny"

    return check_policy


def run_one_case(case: dict, policy_enabled: bool) -> Dict[str, Any]:
    plant_payload(case)
    trace = new_trace()
    tools = make_traced_tools(trace, policy_check=make_policy_check(policy_enabled))
    run_agent(case["user_request"], tools)
    return {"trace": trace}


def main() -> None:
    parser = argparse.ArgumentParser(description="실습3/5 자동 실행기")
    parser.add_argument("--policy", action="store_true", help="정책 엔진을 켜고 실행 (실습5)")
    parser.add_argument("--utility", action="store_true", help="공격 케이스 대신 정상 요청(유용성) 케이스를 실행")
    parser.add_argument(
        "--cases", type=str, default=None, help="케이스 경로 glob (기본: attacks_course/*.yaml 또는 utility/*.yaml)"
    )
    args = parser.parse_args()

    on_off = "on" if args.policy else "off"
    mode_tag = f"{on_off}_utility" if args.utility else on_off

    cases_glob = args.cases or ("attacks_course/utility/*.yaml" if args.utility else "attacks_course/*.yaml")
    cases = load_cases(cases_glob)
    if not cases:
        print(f"[경고] '{cases_glob}' 에 케이스가 없습니다.")
        return

    trace_dir = RESULTS_DIR / "traces" / mode_tag
    trace_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    for case in cases:
        run_result = run_one_case(case, policy_enabled=args.policy)
        trace = run_result["trace"]

        # trace 로그 저장 (요청하신 "실행하면 trace 로그가 남게")
        (trace_dir / f"{case['id']}.json").write_text(
            json.dumps(trace, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        if args.utility:
            ok = judge_not_blocked(trace, case["success_if"])
            label = "OK (허용됨)" if ok else "BLOCKED (잘못 차단됨!)"
        else:
            ok = judge(trace, case["success_if"])
            label = "ATTACK OK (뚫림)" if ok else "BLOCKED (방어됨)"

        print(f'{case["id"]:12} {label}')
        rows.append({"id": case["id"], "type": case.get("type"), "success": ok})

    n = len(rows)
    rate = sum(r["success"] for r in rows) / n if n else 0.0
    metric_name = "유용성 통과율(정상 허용률)" if args.utility else "ASR(공격 성공률)"
    print(f"\n정책: {'ON' if args.policy else 'OFF'} / 케이스 종류: {'유용성' if args.utility else '공격'}")
    print(f"{metric_name} = {sum(r['success'] for r in rows)}/{n} = {rate:.0%}")

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / f"baseline_{mode_tag}.json"
    out_path.write_text(
        json.dumps({"policy_enabled": args.policy, "mode": mode_tag, "rate": rate, "rows": rows}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"결과 저장: {out_path.relative_to(_ROOT)}")
    print(f"trace 로그 저장 위치: {trace_dir.relative_to(_ROOT)}/<id>.json")


if __name__ == "__main__":
    main()
