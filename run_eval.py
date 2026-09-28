# 실습 3 -- 자동 실행기 (run_eval.py) -- 정책 엔진 on/off  비교

# YAML을 읽음 -> 미끼문구심기 -> 에이전트 1회 실행 -> judge()로 결과 판정 -> 성공/실패 개수 카운트

# 공격케이스 20개, 정책 없이 실행 -- 실습 3
# python3 run_eval.py

# 공격 케이스 20개, 정책 켜고 실행 -- 실습 5
# python3 run_eval.py --policy

# 정상요청 케이스 5개로 정책이 정상 요청까지 막지는 않는지 확인 -- 실습 5-4
# python3 run_eval.py --policy --utility

# 정상 요청 케이스 (정책 OFF)
# python3 run_eval.py --utility

# 실행할 때마다:
#  * 케이스별 "ATTACK OK / BLOCKED" (또는 유용성 모드에서는 "OK / BLOCKED")
#  * results/baseline_<on|off>[_utility].json  : 케이스별 결과 요약 + ASR
#  * 케이스별 전체 trace가 results/traces/<태그>/<id>.json 에 남는다.


from __future__ import annotations

import argparse
import glob
import json
import pathlib
import sys
from typing import Any, Callable, Dict, List, Optional

import yaml


ROOT = pathlib.Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evaluator import ( # noqa: E402
    judge,
    judge_not_blocked,
    make_traced_tools,
    new_trace, plant_payload
)
from progent.policy import Policy
from run_agent import run_agent

POLICY_PATH = ROOT / "attacks_course" / "policy" / "course_policy.yaml"
RESULT_DIR = ROOT / "results"


REQUIRED_KEYS = ("id", "user_request", "success_if")


# 함수이름: load_cases
# 인자:   path (str) - 프로젝트 루트 기준 glob 패턴 (기본: "attacks_course/*.yaml")
# 반환값: 케이스 딕셔너리들의 리스트
# 기능:   패턴에 맞는 yaml 파일을 읽어서 리스트로 돌려준다.
#         딕셔너리가 아니거나 REQUIRED_KEYS(id/user_request/success_if) 중 빠진 것이 있는 파일은
#         파일 이름과 누락된 항목을 출력하고 건너뛴다 (실행 도중 KeyError로 죽는 것을 막는다).
def load_cases(path: str = "attacks_course/*.yaml") -> List[dict]:
    cases = []
    for f in sorted(glob.glob(str(ROOT / path))):
        with open(f, encoding="utf-8") as fp:
            data = yaml.safe_load(fp)
        name = pathlib.Path(f).name
        if not isinstance(data, dict):
            print(f"[건너뜀] {name}: yaml 내용이 딕셔너리가 아님")
            continue
        missing = [k for k in REQUIRED_KEYS if k not in data]
        if missing:
            print(f"[건너뜀] {name}: 누락된 항목 {missing}")
            continue
        cases.append(data)
    return cases


# 함수이름: load_course_policy
# 인자:   없음
# 반환값: Policy 객체
# 기능:   POLICY_PATH의 정책 yaml(규칙 목록)을 읽어서 Policy 객체로 바꿔 돌려준다.
def load_course_policy() -> Policy:
    data = yaml.safe_load(POLICY_PATH.read_text(encoding='utf-8')) or []
    return Policy.from_dict(data)


# 함수이름: make_policy_check
# 인자:   enabled (bool) - 정책을 켤지(True) 끌지(False)
# 반환값: (도구이름, 인자) -> "allow"/"deny" 를 돌려주는 함수, 또는 None(정책 OFF)
# 기능:   enabled=False면 None을 돌려줘서 도구가 검사 없이 항상 실행되게 한다(무방어).
#         enabled=True면 정책 파일을 읽어서, 호출마다 허용/차단을 판정하는 함수를 만들어 돌려준다.
def make_policy_check(enabled: bool) -> Optional[Callable[[str, dict], str]]:
    # 실습 5의 check_policy(name, args) -> allow/deny

    if not enabled:
        return None
    policy = load_course_policy()

    # 함수이름: check_policy (make_policy_check 내부 전용)
    # 인자:   tool (str) - 도구 이름, args (dict) - 도구 인자
    # 반환값: "allow" 또는 "deny"
    # 기능:   정책에게 "이 호출 허용해?"라고 묻고, 결과를 문자열로 바꿔 돌려준다.
    def check_policy(tool: str, args: dict) -> str:
        decision = policy.check(tool, args)
        return "allow" if decision.allowed else "deny"

    return check_policy


# 함수이름: run_one_case
# 인자:   case (dict) - 케이스 하나, policy_enabled (bool) - 정책 ON/OFF
# 반환값: {"trace": 이번 실행의 도구 호출 기록 리스트}
# 기능:   케이스 하나를 실제로 실행한다: 미끼 심기 -> 새 trace 만들기 ->
#         (정책이 붙은) 도구 만들기 -> 에이전트 1회 실행. 실행 후 trace를 돌려준다.
def run_one_case(case: dict, policy_enabled: bool) -> Dict[str, Any]:
    plant_payload(case)
    trace = new_trace()
    tools = make_traced_tools(trace, policy_check=make_policy_check(policy_enabled))
    run_agent(case["user_request"], tools)
    return {"trace": trace}



# 함수이름: append_table_row
# 인자:   label (str) - 측정 시점 이름, total (int) - 케이스 수,
#         success (int) - 성공 개수, note (str) - 비고
# 반환값: 없음
# 기능:   results/table.md 에 "측정 시점 | 케이스 수 | 성공 | ASR | 비고" 표의 행을 한 줄 추가한다.
#         파일이 없으면 머리글부터 만들고, 있으면 행만 이어 붙인다 (실습 4의 "행은 앞으로 매주 추가된다").
def append_table_row(label: str, total: int, success: int, note: str = "") -> None:
    table = RESULT_DIR / "table.md"
    if not table.exists():
        table.write_text("| 측정 시점 | 케이스 수 | 성공 | ASR | 비고 |\n|---|---|---|---|---|\n", encoding="utf-8")
    asr = f"{success / total:.0%}" if total else "-"
    with open(table, "a", encoding="utf-8") as f:
        f.write(f"| {label} | {total} | {success} | {asr} | {note} |\n")


# 함수이름: main
# 인자:   없음 (명령줄 옵션 --policy / --utility / --cases 를 argparse로 받음)
# 반환값: 없음
# 기능:   케이스를 전부 불러와 하나씩 실행하고, trace를 파일로 저장하고, judge로 판정해
#         콘솔에 출력한 뒤, 전체 성공률(ASR 또는 정상 허용률)을 계산해 json으로 저장한다.
def main() -> None:
    parser = argparse.ArgumentParser(description="실습 3, 5 실행기")
    parser.add_argument("--policy", action="store_true", help="정책 엔진을 켜고 실행 (실습 5)")
    parser.add_argument("--utility", action="store_true", help="공격 케이스 대신 정상 요청 케이스를 실행")
    parser.add_argument("--cases", type=str, default=None, help="케이스 glob 패턴 (기본: attacks_course/*.yaml, utility는 attacks_course/utility/*.yaml)")
    args = parser.parse_args()

    on_off = "on" if args.policy else "off"
    mode_tag = f"{on_off}_utility" if args.utility else on_off

    pattern = args.cases or ("attacks_course/utility/*.yaml" if args.utility else "attacks_course/*.yaml")
    cases = load_cases(pattern)
    if not cases:
        print(f"[경고] '{pattern}' 에 케이스가 없습니다.")
        return

    trace_dir = RESULT_DIR / "traces" / mode_tag
    trace_dir.mkdir(parents=True, exist_ok=True)

    rows = []
    for case in cases:
        trace = run_one_case(case, policy_enabled=args.policy)["trace"]

        # trace 로그 저장
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
    success = sum(r["success"] for r in rows)
    rate = success / n
    metric_name = "정상 요청 허용률" if args.utility else "ASR(공격 성공률)"
    print(f"\n정책: {'ON' if args.policy else 'OFF'} / {metric_name} = {success}/{n} = {rate:.0%}")

    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULT_DIR / f"baseline_{mode_tag}.json"
    out_path.write_text(
        json.dumps({"policy_enabled": args.policy, "mode": mode_tag, "rate": rate, "rows": rows}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"결과 저장: {out_path.relative_to(ROOT)}")

    # 정책 OFF + 공격 케이스 = 기준선: results/baseline.json 으로도 저장하고 표에 행을 추가한다
    if not args.policy and not args.utility:
        (RESULT_DIR / "baseline.json").write_text(out_path.read_text(encoding="utf-8"), encoding="utf-8")
        append_table_row("W3 기준선 (방어 없음)", n, success, "실제 측정값")
        print("기준선 저장: results/baseline.json, 표 추가: results/table.md")
    elif args.policy and not args.utility:
        append_table_row("정책 ON", n, success, "check_policy 적용")
        print("표 추가: results/table.md")

    print(f"trace 로그 저장 위치: {trace_dir.relative_to(ROOT)}/<id>.json")


if __name__ == "__main__":
    main()