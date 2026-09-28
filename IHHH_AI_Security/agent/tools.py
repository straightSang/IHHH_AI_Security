"""데모 에이전트가 사용하는 4개 도구.

    - read_files(path)
    - write_files(path, content)
    - calculator(expression)
    - http_get(url)

주의: 이 파일의 함수들은 "도구 자체의 안전장치"(경로 이탈 방지, 안전한 수식
평가)만 담당한다. "이 도구 호출을 애초에 허용할지"는 Progent 정책 엔진
(progent/policy.py)이 별도로 결정한다 — 두 계층이 함께 방어선을 이룬다.

`http_get`은 mock://<id> 형태의 URL에 대해서는 attacks/fake_internet.json 에서
내용을 읽어오는 "가짜 인터넷" 모드를 지원한다. 이는 간접 프롬프트 인젝션
공격 시나리오를 네트워크 접속 없이도 100% 재현 가능하게 만들기 위함이다.
"""

from __future__ import annotations

import ast
import json
import operator
import os
import pathlib

try:
    import requests
except ImportError:  # requests가 없어도 mock:// URL은 계속 동작
    requests = None

_ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKSPACE = pathlib.Path(os.environ.get("AGENT_WORKSPACE", _ROOT / "workspace")).resolve()
WORKSPACE.mkdir(parents=True, exist_ok=True)
FAKE_INTERNET_PATH = _ROOT / "attacks" / "fake_internet.json"


class PathEscapeError(PermissionError):
    pass


def _safe_path(path: str) -> pathlib.Path:
    """`path`를 WORKSPACE 기준 상대경로로 해석하고, 샌드박스 밖으로 벗어나면 예외 발생."""
    target = (WORKSPACE / path).resolve()
    if target != WORKSPACE and WORKSPACE not in target.parents:
        raise PathEscapeError(f"경로가 workspace 샌드박스를 벗어납니다: {path}")
    return target


def read_files(path: str) -> str:
    """workspace 샌드박스 안의 텍스트 파일을 읽어 내용을 반환한다."""
    try:
        target = _safe_path(path)
    except PathEscapeError as exc:
        return f"[error] {exc}"
    if not target.exists() or not target.is_file():
        return f"[error] 파일을 찾을 수 없습니다: {path}"
    return target.read_text(encoding="utf-8", errors="replace")


def write_files(path: str, content: str) -> str:
    """workspace 샌드박스 안에 텍스트 파일을 쓴다."""
    try:
        target = _safe_path(path)
    except PathEscapeError as exc:
        return f"[error] {exc}"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return f"[ok] {path} 에 {len(content)}자를 기록했습니다."


_ALLOWED_BIN_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.Mod: operator.mod,
    ast.FloorDiv: operator.floordiv
}
_ALLOWED_UNARY_OPS = {ast.USub: operator.neg, ast.UAdd: operator.pos}


def _eval_node(node: ast.AST):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _ALLOWED_BIN_OPS:
        return _ALLOWED_BIN_OPS[type(node.op)](_eval_node(node.left), _eval_node(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _ALLOWED_UNARY_OPS:
        return _ALLOWED_UNARY_OPS[type(node.op)](_eval_node(node.operand))
    raise ValueError("허용되지 않은 수식 구성요소입니다 (숫자/사칙연산/거듭제곱/괄호만 허용)")


def calculator(expression: str) -> str:
    """숫자/사칙연산/거듭제곱만 지원하는 안전한 계산기.

    ast 파싱을 사용하므로 `__import__('os').system(...)` 같은 코드 인젝션
    시도는 애초에 파싱 단계에서 거부된다 (도구 자체의 방어선)."""
    try:
        tree = ast.parse(expression, mode="eval")
        return str(_eval_node(tree.body))
    except Exception as exc:  # noqa: BLE001
        return f"[error] 수식을 계산할 수 없습니다 ('{expression}'): {exc}"


def http_get(url: str) -> str:
    """URL의 내용을 가져온다. mock://<id> 는 attacks/fake_internet.json 에서
    조회하며(오프라인 재현용), 그 외 URL은 실제 HTTP GET을 수행한다."""
    if url.startswith("mock://"):
        if not FAKE_INTERNET_PATH.exists():
            return f"[error] fake_internet.json 이 없어 mock URL을 해석할 수 없습니다: {url}"
        data = json.loads(FAKE_INTERNET_PATH.read_text(encoding="utf-8"))
        return data.get(url, f"[error] mock URL을 찾을 수 없습니다: {url}")
    if requests is None:
        return "[error] requests 패키지가 설치되어 있지 않아 실제 네트워크 요청을 할 수 없습니다."
    try:
        resp = requests.get(url, timeout=10)
        return resp.text[:5000]
    except Exception as exc:  # noqa: BLE001
        return f"[error] http_get 실패 ({url}): {exc}"


TOOLS = {
    "read_files": read_files,
    "write_files": write_files,
    "calculator": calculator,
    "http_get": http_get
}



# Claude API의 tools 파라미터 형식에 맞춘 스키마 (agent/agent.py 의 LLM 모드에서 사용)
TOOL_SCHEMAS = [
    {
        "type": "function",
        "name": "read_files",
        "description": "workspace 샌드박스 안의 텍스트 파일을 읽어 내용을 반환한다.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "workspace 기준 상대 경로"}},
            "required": ["path"]
        }
    },
    {
        "type": "function",
        "name": "write_files",
        "description": "workspace 샌드박스 안에 텍스트 파일을 쓴다(덮어쓰기).",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "workspace 기준 상대 경로"},
                "content": {"type": "string", "description": "파일에 쓸 내용"},
            },
            "required": ["path", "content"]
        }
    },
    {
        "type": "function",
        "name": "calculator",
        "description": "숫자 사칙연산/거듭제곱 수식을 계산한다. 예: '3*(2+5)**2'",
        "parameters": {
            "type": "object",
            "properties": {"expression": {"type": "string"}},
            "required": ["expression"]
        }
    },
    {
        "type": "function",
        "name": "http_get",
        "description": "URL의 내용을 가져온다. 테스트/데모용 mock://<id> URL도 지원한다.",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"]
        }
    }
]
