"""Progent 논문(2504.11703)의 권한 제어 정책 엔진을 간략화하여 재구현한 모듈.

논문과의 대응 관계
------------------
* Rule / Policy                      -> 논문 Figure 2b의 정책 문법
* Policy.check()                     -> 논문 Algorithm 2 (런타임 정책 적용)
* compose_check()                    -> 논문 Algorithm 4 (범용 정책 + 작업별 정책 합성)
* compare_policies()                 -> 논문 4.3절 (SMT 기반 확장/축소 판정)

이 구현은 "교육/데모용 간략 버전"입니다. 실제 Progent 논문과 다른 점:
  * 인자 조건은 정확값 / 와일드카드(*) / in-리스트 / glob(`*`만 지원하는
    단순 패턴) 네 가지만 지원합니다. 임의의 정규식은 지원하지 않습니다.
  * SMT 증명이 불가능한 조건(지원하지 않는 패턴 등)을 만나면, 항상
    "narrowing이 아니다(=expansion, 승인 필요)" 쪽으로 판정합니다
    (fail-closed). 이는 논문 6절의 핵심 안전 속성—증명되지 않은 갱신은
    절대 조용히 권한을 확장하지 않는다—을 그대로 지키기 위함입니다.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

try:
    import z3

    _Z3_AVAILABLE = True
except ImportError:  # pragma: no cover
    _Z3_AVAILABLE = False


# ---------------------------------------------------------------------------
# 정책 정의 (논문 Figure 2b)
# ---------------------------------------------------------------------------


class Effect(str, Enum):
    ALLOW = "allow"
    FORBID = "forbid"


@dataclass
class Rule:
    tool: str
    effect: Effect
    when: Dict[str, Any] = field(default_factory=dict)  # 인자명 -> 조건
    fallback_msg: str = "정책에 의해 이 도구 호출이 차단되었습니다."

    def matches(self, args: Dict[str, Any]) -> bool:
        for arg_name, cond in self.when.items():
            if not _condition_matches(cond, args.get(arg_name)):
                return False
        return True


@dataclass
class ToolCallDecision:
    allowed: bool
    matched_rule: Optional[Rule]
    message: str
    source: str = "policy"  # 어떤 정책 레이어가 판정했는지 (디버깅/로깅용)


def _condition_matches(cond: Any, value: Any) -> bool:
    """조건 하나가 실제 인자값과 매치되는지 검사 (런타임 강제용, 논문 Algorithm 2)."""
    if cond == "*":
        return True
    if isinstance(cond, dict):
        if "in" in cond:
            return value in cond["in"]
        if "match" in cond:
            return bool(re.fullmatch(_glob_to_regex(cond["match"]), str(value or "")))
        if "eq" in cond:
            return value == cond["eq"]
        raise ValueError(f"지원하지 않는 조건입니다: {cond!r}")
    return value == cond


def _glob_to_regex(glob: str) -> str:
    """아주 단순한 glob 방언(와일드카드는 `*`만 지원)을 정규식으로 변환."""
    return "".join(".*" if ch == "*" else re.escape(ch) for ch in glob)


@dataclass
class Policy:
    rules: List[Rule] = field(default_factory=list)

    def rules_for(self, tool: str) -> List[Rule]:
        """forbid 규칙을 allow 규칙보다 먼저 배치 (논문 Algorithm 2, Line 3)."""
        forbid = [r for r in self.rules if r.tool == tool and r.effect == Effect.FORBID]
        allow = [r for r in self.rules if r.tool == tool and r.effect == Effect.ALLOW]
        return forbid + allow

    def check(self, tool: str, args: Dict[str, Any]) -> ToolCallDecision:
        """Algorithm 2: 도구 호출을 정책과 대조해 결정론적으로 허용/차단."""
        for rule in self.rules_for(tool):
            if rule.matches(args):
                if rule.effect == Effect.FORBID:
                    return ToolCallDecision(False, rule, rule.fallback_msg)
                return ToolCallDecision(True, rule, "허용됨")
        return ToolCallDecision(
            False, None, f"[기본 거부] '{tool}' 호출을 허용하는 규칙이 정책에 없습니다."
        )

    def add(self, rule: Rule) -> "Policy":
        new = copy.deepcopy(self)
        new.rules.append(rule)
        return new

    def to_dict(self) -> List[dict]:
        return [
            {"tool": r.tool, "effect": r.effect.value, "when": r.when, "fallback_msg": r.fallback_msg}
            for r in self.rules
        ]

    @staticmethod
    def from_dict(data: List[dict]) -> "Policy":
        return Policy(
            [
                Rule(d["tool"], Effect(d["effect"]), d.get("when", {}), d.get("fallback_msg", ""))
                for d in (data or [])
            ]
        )


def compose_check(generic: Policy, specific: Policy, tool: str, args: Dict[str, Any]) -> ToolCallDecision:
    """Algorithm 4: 범용(generic) 정책을 먼저 평가하고, 명시적으로 allow/forbid
    하지 않는 경우에만 작업별(task-specific) 정책을 적용한다."""
    for rule in generic.rules_for(tool):
        if rule.matches(args):
            if rule.effect == Effect.FORBID:
                return ToolCallDecision(False, rule, rule.fallback_msg, source="generic")
            return ToolCallDecision(True, rule, "범용 정책에 의해 허용됨", source="generic")
    decision = specific.check(tool, args)
    decision.source = "task-specific" if decision.matched_rule else "default-deny"
    return decision


# ---------------------------------------------------------------------------
# SMT 기반 확장/축소 판정 (논문 4.3절, 6절)
# ---------------------------------------------------------------------------


def collect_arg_names(*policies: Policy) -> Dict[str, List[str]]:
    """여러 정책에 등장하는 규칙들로부터, 도구별로 언급된 인자 이름을 모두
    모은다. compare_policies() 호출 시 arg_names를 일일이 손으로 나열하지
    않아도 되도록 돕는 헬퍼."""
    names: Dict[str, set] = {}
    for policy in policies:
        for rule in policy.rules:
            names.setdefault(rule.tool, set()).update(rule.when.keys())
    return {tool: sorted(vs) for tool, vs in names.items()}


class UpdateKind(str, Enum):
    NARROWING = "narrowing"  # A(P') ⊆ A(P): 자동 적용
    EXPANSION = "expansion"  # 그 외 (또는 증명 불가): 승인 필요


def compare_policies(
    old: Policy, new: Policy, tools: List[str], arg_names: Dict[str, List[str]]
) -> UpdateKind:
    """`new`가 `old`의 축소(narrowing)인지 SMT로 증명을 시도한다.

    Z3가 없거나, 어떤 조건이라도 SMT로 인코딩할 수 없으면 항상 EXPANSION으로
    (안전하게) 판정한다 — 즉 "증명된 축소만 자동 승인, 나머지는 전부 사람
    승인 필요"라는 논문의 단조적 제약(monotonic confinement) 철학을 그대로
    따른다.
    """
    if not _Z3_AVAILABLE:
        return UpdateKind.EXPANSION

    for tool in tools:
        names = arg_names.get(tool, [])
        if not names:
            continue
        solver = z3.Solver()
        svars = {name: z3.String(f"{tool}__{name}") for name in names}

        allowed_new = _allowed_formula(new, tool, svars, permissive_on_unknown=True)
        allowed_old = _allowed_formula(old, tool, svars, permissive_on_unknown=False)

        # 반례 탐색: new는 허용하지만 old는 허용하지 않는 호출이 존재하는가?
        solver.add(z3.And(allowed_new, z3.Not(allowed_old)))
        result = solver.check()
        if result != z3.unsat:
            # SAT(실제 반례 발견) 또는 UNKNOWN(증명 불가) -> narrowing으로 인정하지 않음
            return UpdateKind.EXPANSION
    return UpdateKind.NARROWING


def _allowed_formula(policy: Policy, tool: str, svars: Dict[str, "z3.SeqRef"], permissive_on_unknown: bool):
    """'이 정책이 이 심볼릭 호출을 허용한다'는 z3 불리언 논리식을 구성.

    permissive_on_unknown=True  : 인코딩 불가능한 allow 조건 -> True,
                                   인코딩 불가능한 forbid 조건 -> False
                                   (허용 집합을 과대추정; new 쪽에 사용)
    permissive_on_unknown=False : 그 반대 (허용 집합을 과소추정; old 쪽에 사용)

    두 선택 모두 "불확실하면 expansion으로 판정"하는 방향으로 편향되어 있다.
    """
    forbid_terms, allow_terms = [], []
    for rule in policy.rules_for(tool):
        unknown_default = (
            (not permissive_on_unknown) if rule.effect == Effect.FORBID else permissive_on_unknown
        )
        term = _rule_to_z3(rule, svars, unknown_default)
        (forbid_terms if rule.effect == Effect.FORBID else allow_terms).append(term)
    forbidden = z3.Or(*forbid_terms) if forbid_terms else z3.BoolVal(False)
    allowed = z3.Or(*allow_terms) if allow_terms else z3.BoolVal(False)
    return z3.And(z3.Not(forbidden), allowed)


def _rule_to_z3(rule: Rule, svars: Dict[str, "z3.SeqRef"], unknown_default: bool):
    terms = []
    for arg_name, cond in rule.when.items():
        var = svars.get(arg_name)
        if var is None:
            terms.append(z3.BoolVal(unknown_default))
        else:
            terms.append(_condition_to_z3(cond, var, unknown_default))
    return z3.And(*terms) if terms else z3.BoolVal(True)


_GLOB_SAFE_CHARS = set(
    "*abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._-/: "
)


def _condition_to_z3(cond: Any, var: "z3.SeqRef", unknown_default: bool):
    if cond == "*":
        return z3.BoolVal(True)
    if isinstance(cond, dict):
        if "in" in cond:
            return z3.Or(*[var == z3.StringVal(str(v)) for v in cond["in"]])
        if "eq" in cond:
            return var == z3.StringVal(str(cond["eq"]))
        if "match" in cond:
            glob = cond["match"]
            if set(glob) <= _GLOB_SAFE_CHARS:
                return z3.InRe(var, _glob_to_z3_re(glob))
            return z3.BoolVal(unknown_default)  # 지원하지 않는 정규식 -> 보수적으로 처리
        return z3.BoolVal(unknown_default)
    return var == z3.StringVal(str(cond))


def _glob_to_z3_re(glob: str):
    parts, literal = [], ""
    for ch in glob:
        if ch == "*":
            if literal:
                parts.append(z3.Re(literal))
                literal = ""
            parts.append(z3.Star(z3.AllChar(z3.StringSort())))
        else:
            literal += ch
    if literal:
        parts.append(z3.Re(literal))
    if not parts:
        return z3.Star(z3.AllChar(z3.StringSort()))
    result = parts[0]
    for p in parts[1:]:
        result = z3.Concat(result, p)
    return result
