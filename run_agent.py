# run_agent.py
# 단순한 규칙 기반 에이전트. 실험 환경 동일 유지를 위한 가짜 에이전트 
# 정책 엔진 적용 전후를 비교하기 위해 간접 프롬프트 인젝션 공격에 취약하게 만들었다.

from __future__ import annotations

import re
from typing import Callable, Dict, Optional

EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[\w.-]+")
FILENAME_RE = re.compile(r"([\w.-]+\.(?:txt|json|md))")
MOCK_URL_RE = re.compile(r"(mock://[\w./?=&-]+)")
SEND_TRIGGER_WORDS = ["보내", "전송", "전달", "send", "email", "이메일"]

OPS = [
    ("더하기", "+"),  ("곱하기", "*"),  ("빼기", "-"),  ("나누기", "/"),
    ("더한", "+"),  ("곱한", "*"),  ("나눈", "/"),  ("뺀", "-")     
]

# 함수이름: _try_build_expression
# 인자:   text (str) - 사용자 요청 문장 전체
# 반환값: 계산기에 넣을 수 있는 수식 문자열 (예: "3 + 5 * 2") 또는 None(못 만들면)
# 기능:   "3 더하기 5 곱하기 2" 같은 한국어 문장에서, 위 OPS 변환표로 한국어
#         연산 단어를 기호(+,-,*,/)로 바꾼 뒤, 숫자/기호만 뽑아 수식을 만든다.
#         숫자+기호가 3개 이상 안 모이면(=계산할 게 없으면) None을 반환한다.
def _try_build_expression(text: str) -> Optional[str]:
    """'3 더하기 5 곱하기 2' 같은 한국어 사칙연산 표현을 계산기 수식으로 변환."""
    t = text
    for kor, sym in OPS:
        t = t.replace(kor, f" {sym} ")
    tokens = re.findall(r"\d+\.?\d*|\+|-|\*|/", t)
    if len(tokens) >= 3 and any(tok in "+-*/" for tok in tokens):
        return " ".join(tokens)
    return None





# 함수이름: run_agent
# 인자:   user_request (str) - 사용자가 시킨 일 (자연어 문장)
#         tools (dict) - {"read_files": 함수, "send_email": 함수, ...} 형태.
#                        evaluator.make_traced_tools() 가 만들어준 "감싸진" 도구들
# 반환값: None (도구 호출은 전부 tools[...]() 를 통해 이루어지고, trace에 자동 기록됨)
# 기능:   아주 단순한 규칙만으로 "일하는 척"하는 가짜 에이전트.
#         1) 요청 문장에 파일명이 보이면 read_files 로 읽어서 문맥(context)에 추가
#         2) 요청 문장에 mock:// URL이 보이면 http_get 으로 가져와서 문맥에 추가
#         3) 요청 문장이 사칙연산처럼 보이면 calculator 호출
#         4) 지금까지 모은 문맥(원래 요청 + 파일/URL 내용) 어디에든 이메일
#            주소와 "보내"/"전달" 같은 단어가 함께 있으면, 그 주소로 곧이곧대로
#            send_email 을 호출한다.
#         -> 4번이 바로 "일부러 취약하게 만든" 지점: 파일/URL 안에 숨겨진
#            지시문(간접 인젝션)도 이 규칙에 걸리면 그대로 실행해버린다.
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
