"""defenses/policy/rules.yaml (범용 정책)에 대한 allow/forbid 테스트 케이스.

실행:
    python defenses/policy/test_policy.py
    (또는 pytest 가 설치되어 있다면) pytest defenses/policy/test_policy.py
"""

from __future__ import annotations

import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from defenses.policy.check_policy import check_policy, load_policy  # noqa: E402

POLICY = load_policy()

# (tool, args, expected_allowed, 설명)
CASES = [
    ("calculator", {"expression": "1+2*3"}, True, "일반 계산은 허용"),
    ("read_files", {"path": "notes.txt"}, True, "workspace 안의 일반 파일 읽기는 허용"),
    ("read_files", {"path": "../../etc/passwd"}, False, "상위 디렉터리 경로 이탈 읽기는 차단"),
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
    ("send_email", {"to": "eve@evil.com"}, False, "정책에 아예 없는 도구는 기본 거부(default-deny)"),
]


def test_all_cases() -> None:
    failures = []
    for tool, args, expected, note in CASES:
        allowed, msg = check_policy(tool, args, POLICY)
        status = "OK" if allowed == expected else "FAIL"
        print(f"[{status}] {tool}({args}) -> allowed={allowed} (expected={expected}) :: {note} :: {msg}")
        if status == "FAIL":
            failures.append((tool, args, expected, allowed, msg))
    assert not failures, f"{len(failures)}개의 테스트 케이스가 실패했습니다: {failures}"


if __name__ == "__main__":
    test_all_cases()
    print("\n모든 정책 테스트를 통과했습니다. ✅")
