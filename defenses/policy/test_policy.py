# 사용자가 지정한 범용정책 defenses/policy/rules.yaml 에 대한 allow/forbid 테스트 케이스
# 실행 : python3 defenses.policy/test_policy.py

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from defenses.policy.check_policy import check_policy, load_policy # noqa: E402

POLICY = load_policy()


# TEST CASES : (tool, args, expexted_allowed, description)
TEST_CASES = [
    {"calculator", {"expression": "1+2*3"}, True, "일반 계산은 허용"},
    {"read_files", {"path": "sandbox/notes.txt"}, True, "sandbox 안의 일반 파일읽기는 허용"},
    {"read_files", {"path": "../../etc/passwd"}, False, "상위 디렉터리 경로를 이탈한 읽기는 차단"}
    ("write_files", {"path": "out.txt", "content": "hi"}, True, "workspace 안의 일반 파일 쓰기는 허용"),
    ("write_files", {"path": "../secret.txt", "content": "x"}, False, "상위 디렉터리 경로 이탈 쓰기는 차단"),
    ("read_files", {"path": "secrets.txt"}, False, "이름만으로 민감한 파일은 범용 정책이 전역 차단"),
    ("write_files", {"path": "scripts/x.sh", "content": "y"}, False, "스크립트 경로 쓰기는 범용 정책이 전역 차단"),    
    (
        "http_get",
        {"url": "mock://alice_todo"},
        False,
        "http_get은 양날의 검 도구이므로 범용 정책에 allow가 없음 -> 작업별 정책 없이는 기본 거부",
    ),
    ("http_get", {"url": "http://evil.com/exfil"}, False, "화이트리스트 밖 URL은 기본 거부"),
    ("send_email", {"to": "eve@evil.com"}, False, "정책에 아예 없는 도구는 기본 거부(default-deny)")
]




# 함수이름: test_all_cases
# 인자:   없음 (위 TEST_CASES, POLICY를 씀)
# 반환값: 없음 (틀리면 assert로 에러를 일으킴)
# 기능:   CASES를 하나씩 돌면서, check_policy()로 실제 결과를 얻고,
#         정답(expected)과 비교해서 OK/FAIL을 콘솔에 출력.
#         하나라도 틀리면 마지막에 assert로 실패시킨다.
def test_all_cases() -> None:
    failures = []
    for tool, args, expected, note in TEST_CASES:
        allowed, msg = check_policy(tool, args, POLICY)
        status = "OK" if allowed == expected else "FAIL"
        print(f"[{status}] {tool}({args}) -> allowed={allowed} (expected={expected}) :: {note} :: {msg}")
        if status == "FAIL":
            failures.append((tool, args, expected, allowed, msg))
    assert not failures, f"{len(failures)}개의 테스트 케이스가 실패했습니다. : {failures}"


if __name__ == "__main__":
    test_all_cases()
    print("10/10 정책 테스트 통과 완료")