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
except ImportError:
    requests = None

ROOT = pathlib.Path(__file__).resolve().parent.parent
SANDBOX = pathlib.Path(os.environ.get("AGENT_SANDBOX", ROOT / "sandbox")).resolve()
SANDBOX.mkdir(parents=True, exist_ok=True)
INTERNET_PATH = ROOT / "attacks" / "fake_internet.json"

class PathEscapeError(PermissionError):
    pass


def _safe_path(path: str) -> pathlib.Path:
    # path 를 SANDBOX 기준 상대 경로로 해석하고, 샌드박스 밖으로 벗어나면 예외를 발생시키는 함수
    target = (SANDBOX/path).resolve()
    if target != SANDBOX and SANDBOX not in target.parents:
        raise PathEscapeError(f"경로가 sandbox 샌드박스를 벗어납니다: {path}")
    return target


def read_files(path: str) -> str:
    # sandbox 안의 텍스트 파일을 읽어서 내용을 반환한다. 
    try:
        target = _safe_path(path)
    except PathEscapeError as exc:
        return f"[error] {exc}"
    if not target.exists() or not target.is_file():
        return f"[error] 파일을 찾을 수 없습니다.: {path}"
    return target.read_text(encoding="utf-8", errors="replace")


def write_files(path: str, content: str) -> str:
    # sandbox 안에 텍스트 파일을 쓴다
    try:
        target=_safe_path(path)
    except PathEscapeError as exc:
        return f"[error]: {exc}"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return f"[ok] {path}에 {len(content)}자를 기록했습니다."


ALLOWED_BIN_OPS = {
    ast.Add: operator.add,
    "더하기": operator.add,
    "더한": operator.add,
    ast.Sub: operator.sub,
    "빼기": operator.sub,
    "뺀": operator.sub,
    ast.Mult: operator.mul,
    "곱하기": operator.mul,
    "곱한": operator.mul,
    ast.Div: operator.truediv,
    "나누기": operator.truediv,
    "나눈": operator.truediv,
    ast.Pow: operator.pow,
    ast.Mod: operator.mod,
    ast.FloorDiv: operator.floordiv
}
ALLOWED_UNARY_OPS = { ast.USub: operator.neg, ast.UAdd: operator.pos }

def eval_node(node: ast.AST):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value

    if isinstance(node, ast.BinOp) and type(node.op) in ALLOWED_BIN_OPS:
        return ALLOWED_BIN_OPS[type(node.op)](eval_node(node.left), eval_node(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in ALLOWED_UNARY_OPS:
        return ALLOWED_UNARY_OPS[type(node.op)](eval_node(node.operand))


def calculator(expression: str) -> str:
    # 숫자. 사칙연산, 거듭제곱만을 지원하는 안전한 계산기
    # ast 파싱을 사용하므로 __import__('os').system(...) 같은 코드 인젝션 시도는 파싱에서 거부된다.
    try:
        tree = ast.parse(expression, mode="eval")
        return str(eval_node(tree.body))
    except Exception as exc:
        return f"[error] 수식을 계산할 수 없습니다 ('{expression}'): {exc}"

def http_get(url: str) -> str:
    # url의 내용을 가져온다. mock://<id>는 attacks/fake_internet.json에서 조회하며, 그 외 url은 실제 http_get을 수행한다.
    if url.startswith("mock://"):
        if not INTERNET_PATH.exist():
            return f"[error] fake_internet.json이 없어서 mock url을 해석할 수 없습니다."
        data = json.loads(INTERNET_PATH.read_text(encoding="utf-8"))
        return data.get(url, f"[error] mock url을 찾을 수 없습니다: {url}")
    if requests is None:
        return "[error] requests 패키지가 설치되어 있지 않아서 실제 네트워크 요청을 보낼 수 없습니다."
    try:
        resp = requests.get(url, timeout=10)
        return resp.text[:5000]
    except Exception as exc: # noqa: BLE001
        return f"[error] http_get 실패 ({url}): {exc}"

TOOLS = {
    "read_files": read_files,
    "write_files": write_files,
    "calculator": calculator,
    "http_get": http_get
}

TOOL_SCHEMAS = [
    {
        "type": "function",
        "name": "read_files",
        "description": "sandbox 샌드박스 안의 텍스트 파일을 읽어서 그 내용을 반환한다.",
        "parameters": {
            "type": "objectc",
            "properties": {"path": {"type": "string", "description": "sandbox 기준 상대경로"}},
            "required": ["path"]   
        }
    },
    {
        "type": "function",
        "name": "write_files",
        "desciption": "snadbox 샌드박스 안에 텍스트 파일을 쓴다 (덮어쓰기/새로쓰기)",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "sandboc 기준 상대경로"},
                "content": {"type": "string", "description": "파일에 쓸 내용"}
            },
            "required": ["path", "content"]
        }
    },
    {
        "type": "function",
        "name": "calculator",
        "description": "숫자 사칙연산/거듭제곱 수식을 계산한다. ex) 3*(2+5)**2",
        "parameters": {
            "type": "object",
            "properties": {"expression": {"type":"string"}},
            "required": ["expression"]
        }
    },
    {
        "type": "function",
        "name": "http_get",
        "description": "URL의 내용을 가져온다. 테스트/데모용 mick://<id> URL도 지원한다.",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"]
        }
    }
]