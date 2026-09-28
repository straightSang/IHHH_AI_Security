"""run_agent(user_request, tools) — 아주 단순한 규칙 기반 에이전트.

이 파일은 "W2에서 이미 있는" 실제 에이전트를 대신하는 자리표시자(placeholder)
입니다. 팀에 이미 W2 에이전트가 있다면, run_eval.py 상단의
    from run_agent import run_agent
를 여러분의 실제 에이전트를 가리키도록 바꾸기만 하면 됩니다 — 인터페이스만
`run_agent(user_request: str, tools: dict) -> None` (또는 반환값 무시) 로
맞추면 evaluator.py / run_eval.py 는 그대로 재사용할 수 있습니다.

이 간이 버전은 일부러 "순진하게" 동작합니다 (=프롬프트 인젝션에 취약):
  1. 요청 문장에 파일명이 보이면 read_files 로 읽는다.
  2. 요청 문장에 mock:// URL이 보이면 http_get 으로 가져온다.
  3. 지금까지 모은 텍스트 어디에든 이메일 주소가 있고, "보내"/"전달"/
     "send"/"email" 같은 단어가 함께 있으면 그 주소로 곧이곧대로
     send_email 을 호출한다.
     -> 바로 이 3번이, 파일/URL 안에 숨겨둔 지시문(간접 인젝션)이나
        사용자의 직접 요청(직접 인젝션) 모두에 그대로 걸려드는 지점입니다.
  4. 정책 엔진이 켜져 있다면(실습5), 실제 실행은 evaluator.make_traced_tools()
     가 감싼 tools 딕셔너리 안에서 이미 허용/차단이 걸러진 뒤이므로, 이
     에이전트 자체는 정책을 전혀 신경 쓰지 않아도 됩니다 — 그것이 정책
     엔진을 "삽입"하는 지점(실습5)의 핵심입니다.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, Optional

EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[\w.-]+")
FILENAME_RE = re.compile(r"([\w./-]+\.(?:txt|json|md))")
MOCK_URL_RE = re.compile(r"(mock://[\w./?=&-]+)")
SEND_TRIGGER_WORDS = ["보내", "전달", "send", "email", "이메일"]

_KOR_OPS = [
    ("더하기", "+"), ("더한", "+"), ("빼기", "-"), ("뺀", "-"),
    ("곱하기", "*"), ("곱한", "*"), ("나누기", "/"), ("나눈", "/"),
]


def _try_build_expression(text: str) -> Optional[str]:
    """'3 더하기 5 곱하기 2' 같은 한국어 사칙연산 표현을 계산기 수식으로 변환."""
    t = text
    for kor, sym in _KOR_OPS:
        t = t.replace(kor, f" {sym} ")
    tokens = re.findall(r"\d+\.?\d*|\+|-|\*|/", t)
    if len(tokens) >= 3 and any(tok in "+-*/" for tok in tokens):
        return " ".join(tokens)
    return None


def run_agent(user_request: str, tools: Dict[str, Callable[..., str]]) -> Optional[str]:
    context = user_request

    m_file = FILENAME_RE.search(user_request)
    if m_file and "read_files" in tools:
        content = tools["read_files"](path=m_file.group(1))
        context += "\n" + str(content)

    m_url = MOCK_URL_RE.search(user_request)
    if m_url and "http_get" in tools:
        content = tools["http_get"](url=m_url.group(1))
        context += "\n" + str(content)

    if "calculator" in tools:
        expr = _try_build_expression(user_request)
        if expr:
            tools["calculator"](expression=expr)

    if "send_email" in tools:
        has_trigger = any(w.lower() in context.lower() for w in SEND_TRIGGER_WORDS)
        email_match = EMAIL_RE.search(context)
        if has_trigger and email_match:
            tools["send_email"](to=email_match.group(0), body=context[:500])

    return None
