
# trace_logger.py
# W2 — 에이전트가 한 일을 순서대로 남기는 기록기.
#
# 두 군데에 남긴다.
#   1) self.events  — 메모리. 이번 주 성공/실패 판정은 이 리스트로 한다.
#   2) JSONL 파일   — 나중에 다시 볼 수 있게.
#
# W3에서 자동 채점기(run_eval.py)가 읽는 형식이 이 record다.
# 그래서 필드 이름을 팀 전체가 똑같이 맞춰야 한다.
 
import json
import uuid
 
from datetime import datetime
from pathlib import Path
 
TRACE_DIR = Path("traces")
TRACE_DIR.mkdir(exist_ok=True)
 
TRACE_FILE = TRACE_DIR / "agent_trace.jsonl"
 
 
class TraceLogger:
 
    def __init__(self):
        self.run_id = str(uuid.uuid4())  # 실행 한 번을 구분하는 ID
        self.step = 0
        self.event_index = 0
        self.events = []  # 메모리 기록
 
    def log(
        self,
        event_type: str,
        data: dict = None,
        tool: dict = None,
        execution: dict = None,
        result: dict = None,
    ):
        self.event_index += 1
 
        record = {
            "timestamp": datetime.now().isoformat(),
            "run_id": self.run_id,
            "step": self.step,
            "event_index": self.event_index,
 
            "event": event_type,
 
            "tool": tool,
 
            "execution": execution,
 
            "result": result,
 
            "data": data or {},
        }
 
        self.events.append(record)
 
        with TRACE_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
 
        return record
 
    def next_step(self):
        self.step += 1
 
    def tool_calls(self):
        """도구 호출만 순서대로. 판정은 여기만 보면 된다."""
        return [e for e in self.events if e["event"] == "tool_call"]
 

