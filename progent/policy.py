"""
Progent 논문의 권한제어 정책 엔진을 간략화해서 재구현한 모듈

- Rule / Policy -> 정책 문법
- Policy.check() -> 논문의 알고리즘2 (런타임 정책 적용)
- compose_check() -> 논문의 알고리즘 4 (generic 정책 + task 별 정책)
- compare_policies() -> SMT 기반 정책 업데이트 (축소/확장)


실제 Progent 논문과 다른 점:
  - 인자 조건은 정확값 / 와일드카드(*) / in-리스트 / glob(`*`만 지원하는
    단순 패턴) 네 가지만 지원한다. 임의의 정규식은 지원하지 않음
  - SMT 증명이 불가능한 조건(지원하지 않는 패턴 등)을 만나면 항상
    "narrowing이 아니다(=expansion, 승인 필요)" 쪽으로 판정
"""

from __future__ import annotations 

import copy
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

try:
    import z3  # 논문에서 사용한 SMT solver
    Z3_AVAILABLE = True
except ImportError:  # pragma: no cover
    Z3_AVAILABLE = False


# ----------------
# 1. 정책 정의 -> Rule / Policy
# ----------------

# 클래스이름: Effect
# 인자:   없음 (Enum 자체가 "허용값 목록"임)
# 반환값: 해당 없음
# 기능:   규칙의 효과(effect)가 가질 수 있는 값 두 가지("allow"/"forbid")를
#         정해둔 열거형(Enum). 오타 방지+코드 자동완성을 위해 문자열
#         allow/forbid를 직접 쓰지 않고 Effect.ALLOW / Effect.FORBID로 씀.
class Effect(str, Enum):
    ALLOW = "allow"
    FORBID = "forbid"



# 클래스이름: Rule
# 필드:   tool (str) - 규칙이 적용될 도구 이름
#         effect (Effect) - 허용인지 차단인지
#         when (dict) - 인자 이름 -> 조건, 여러 개면 전부 AND로 검사됨
#         fallback_msg (str) - 차단됐을 때 보여줄 메시지
# 기능:   정책 규칙 하나를 표현하는 데이터 구조 (논문 Figure 2b의 Rule).
@dataclass
class Rule:
    tool: str
    effect: Effect
    when: Dict[str, Any] = field(default_factory=dict)  # 인자명 - 조건
    fallback_msg: str = "정책에 의해 이 도구호출이 차단되었습니다."


    # 함수이름: matches (Rule의 메서드)
    # 인자:   args (dict) - 도구 호출 인자들
    # 반환값: True(규칙에 부합함) / False(부합하지 않음)
    # 기능:   when에 적힌 조건들을 인자 하나하나와 비교해서, 전부(AND) 맞으면
    #         True. 하나라도 안 맞으면 즉시 False로 끝낸다.
    def matches(self, args: Dict[str, Any]) -> bool:
        for arg_name, cond in self.when.items():
            if not condition_matches(cond, args.get(arg_name)):
                return False
        return True




# 클래스이름: ToolCallDecision
# 필드:   allowed (bool) - 도구호출이 허용됐는지
#         matched_rule (Rule 또는 None) - 어떤 규칙이 적용됐는지 (없으면 None)
#         message (str) - 이유 설명 메시지
#         source (str) - 어느 정책 층(policy/generic/task-specific 등) 중에서
#                         어떤 결과가 나왔는지 (디버깅/로그용)
# 기능:   Policy.check()나 compose_check()가 판정 결과를 담아 돌려주는 객체.
@dataclass
class ToolCallDecision:
    allowed: bool
    matched_rule: Optional[Rule]
    message: str
    source: str = "policy"  # 어떤 정책 레이어가 판단했는지 (디버깅용/로그용)



# 함수이름: condition_matches
# 인자:   cond (조건, 예: "*" / {"in":[...]} / {"match":"glob"} / {"eq":값} / 그냥 값)
#         value (실제 인자값)
# 반환값: True(조건 만족) / False(불만족)
# 기능:   조건 하나가 실제 값과 맞는지 검사한다 (논문 Algorithm 2의 e_i[v_i/p_i] 부분).
#         "*"면 무조건 True, {"in":[...]}면 목록 안에 있는지, {"match":...}면
#         glob 패턴과 맞는지, {"eq":...}면 정확히 같은지, 그 외엔 그냥 == 비교.
def condition_matches(cond: Any, value: Any) -> bool:
    # 조건이 실제 인자값과 매칭되는지 검사 (런타임 강제, 논문 알고리즘 2)
    if cond == "*":
        return True
    if isinstance(cond, dict):
        if "in" in cond:
            return value in cond["in"]
        if "match" in cond:
            return bool(re.fullmatch(glob_to_regex(cond["match"]), str(value or "")))  # [수정] fullmath -> fullmatch
        if "eq" in cond:
            return value == cond["eq"]
        raise ValueError(f"지원되지 않는 조건: {cond}")
    return value == cond


# 함수이름: glob_to_regex
# 인자:   glob (str): "*"만 와일드카드로 쓰는 단순 패턴 (예: "mock://*")
# 반환값: 진짜 정규식 문자열 (예: "mock://.*")
# 기능:   glob 패턴을 한 글자씩 보면서, "*"는 ".*"(아무거나 0개 이상)로 바꾸고
#         나머지 글자는 re.escape로 이어붙인다.
def glob_to_regex(glob: str) -> str:
    # 단순한 glob을 정규식으로 변환한다.
    return "".join(".*" if ch == "*" else re.escape(ch) for ch in glob)




# 클래스이름: Policy
# 필드:   rules (List[Rule]) - 해당 정책에 들어있는 규칙들의 목록
# 기능:   규칙 여러 개를 담아두고, 도구 호출을 검사(check)하거나, 규칙을
#         추가(add)하거나, 저장용 딕셔너리로 바꾸는(to_dict/from_dict) 객체
@dataclass
class Policy:
    rules: List[Rule] = field(default_factory=list)


    # 함수이름: rules_for (Policy의 메서드)
    # 인자:   tool (str) - 도구 이름
    # 반환값: 해당 도구를 대상으로 하는 규칙들의 리스트 (forbid가 먼저, allow가 나중에 온다)
    # 기능:   전체 규칙 중 이 도구에 해당하는 것만 골라내고, forbid 규칙을
    #         allow 규칙보다 앞에 두도록 순서를 맞춘다 (논문 알고리즘 2: "forbid 규칙이 allow보다 먼저 검사되어야 한다").
    def rules_for(self, tool: str) -> List[Rule]:
        # forbid 규칙이 기본값이어야 하므로 allow보다 먼저 배치한다
        forbid = [r for r in self.rules if r.tool == tool and r.effect == Effect.FORBID]
        allow = [r for r in self.rules if r.tool == tool and r.effect == Effect.ALLOW]
        return forbid + allow


    # 함수이름: check (Policy의 메서드)
    # 인자:   tool (str) - 도구 이름, args (dict) - 실제 호출 인자들
    # 반환값: ToolCallDecision (허용 여부 + 이유)
    # 기능:   논문 알고리즘 2 전체 구현. rules_for()로 정렬된 규칙을 순서대로
    #         보면서, 처음 매치되는 규칙의 판정을 그대로 쓴다(forbid면 차단,
    #         allow면 허용). 해당 도구에 대해 아무런 규칙이 없으면 기본 거부(default-deny)한다.
    def check(self, tool: str, args: Dict[str, Any]) -> ToolCallDecision:
        # 알고리즘2: 도구호출을 정책과 비교한 뒤 결정론적으로 허용/차단한다.
        for rule in self.rules_for(tool):
            if rule.matches(args):
                if rule.effect == Effect.FORBID:
                    return ToolCallDecision(False, rule, rule.fallback_msg)  # [수정] fallback_mag -> fallback_msg
                return ToolCallDecision(True, rule, "허용됨")
        return ToolCallDecision(False, None, f"[Default: 거부] {tool} 호출을 허용하는 규칙이 정책에 정의되어 있지 않습니다.")


    # 함수이름: add (Policy의 메서드)
    # 인자:   rule (Rule) - 추가할 새 규칙
    # 반환값: 새 Policy 객체 (원본은 그대로, 규칙 하나 추가된 사본)
    # 기능:   원본 정책을 복사한 뒤, 그 복사본에만 규칙을 추가해서 반환한다
    def add(self, rule: Rule) -> "Policy":
        new = copy.deepcopy(self)  # [수정] new = copy = copy.deepcopy(self) -> copy 모듈을 안 덮어쓰게 수정
        new.rules.append(rule)
        return new


    # 함수이름: to_dict 
    # 인자:   없음
    # 반환값: 규칙들을 딕셔너리로 바꾼 리스트 (yaml/json으로 저장하기 용이하도록)
    # 기능:   정책 전체에 들어있는 Rule 객체들을 {"tool":..., "effect":..., "when":..., "fallback":...}
    #        형태의 딕셔너리로 변환한 뒤 리스트로 모아서 반환한다.
    def to_dict(self) -> List[Dict]:
        return [
            {"tool": r.tool, "effect": r.effect.value, "when": r.when, "fallback_msg": r.fallback_msg}
            for r in self.rules
        ]



    # 함수이름: from_dict (Policy의 정적 메서드, self 없이 Policy.from_dict(...)로 호출)
    # 인자:   data (List[dict]) - to_dict()가 만든 것과 같은 형태의 딕셔너리 리스트
    # 반환값: 새 Policy 객체
    # 기능:   딕셔너리 리스트(yaml/json에서 읽어온 것)를 다시 Rule 객체들로
    #         복원해서, 그것들을 담은 Policy를 만들어 반환한다 (to_dict의 반대 작업).
    @staticmethod
    def from_dict(data: List[dict]) -> "Policy":
        return Policy(
            [
                Rule(d["tool"], Effect(d["effect"]), d.get("when", {}), d.get("fallback_msg", ""))
                for d in (data or [])
            ]
        )


# 함수이름: compose_check
# 인자:   generic (Policy) - 우선순위가 높은 범용 정책
#         specific (Policy) - 우선순위가 낮은 작업별 정책
#         tool (str), args (dict) - 검사할 도구 호출
# 반환값: ToolCallDecision
# 기능:   논문 Algorithm 4. generic 정책의 규칙을 먼저 보고, 매치되는 게
#         있으면(허용이든 차단이든) 그 결정을 바로 최종 결정으로 쓴다.
#         generic에서 아무 규칙도 안 걸리면, 그때서야 specific(작업별) 정책의
#         check()로 넘겨서 그 결과를 쓴다.
def compose_check(generic: Policy, specific: Policy, tool: str, args: Dict[str, Any]) -> ToolCallDecision:
    # 알고리즘 4: generic 정책을 먼저 적용한 후, task-specific 정책을 적용한다.
    for rule in generic.rules_for(tool):
        if rule.matches(args):
            if rule.effect == Effect.FORBID:
                return ToolCallDecision(False, rule, rule.fallback_msg, source="generic")
            return ToolCallDecision(True, rule, "범용정책에 의해서 허용됨", source="generic")

    decision = specific.check(tool, args)
    decision.source = "task-specific" if decision.matched_rule else "default-deny"
    return decision


# ------------------
# SMT 기반 정책 업데이트 축소/확장 (논문 4.3, 6)
# ------------------


# 클래스이름: UpdateKind
# 필드:   없음 (Enum 값 목록)
# 기능:   정책 갱신 제안이 narrowing(축소, 자동 적용)인지 expansion(확장,
#         승인 필요)인지를 나타내는 값
class UpdateKind(str, Enum):
    NARROWING = "narrowing"
    EXPANSION = "expansion" 




# 함수이름: compare_policies
# 인자:   old (Policy) - 갱신 전 정책
#         new (Policy) - 갱신 제안된 정책
#         tools (List[str]) - 비교해볼 도구 이름들
#         arg_names (dict) - 도구별로 확인할 인자 이름 목록
# 반환값: UpdateKind (NARROWING 또는 EXPANSION)
# 기능:    new가 old보다 허용 범위가 넓어졌는지를 Z3로 확인한다.
#         각 도구마다 new에서는 허용되는데 old에서는 허용 되지 않는 호출이 있는지를
#         Z3에서 확인한 후, 그런 경우가 하나라도 존재하면(sat) 또는
#         판단이 안 되면(unknown) -> EXPANSION으로, 모든 도구에서 반례가 전혀
#         없다고 증명되면(unsat) -> NARROWING으로 판정한다. Z3 자체가 없으면
#         증명을 시도하지 않고 무조건 EXPANSION(안전한 쪽)으로 처리한다.
def compare_policies(
    old: Policy, new: Policy, tools: List[str], arg_names: Dict[str, List[str]]
) -> UpdateKind:
    # new가 old의 축소인지 확장인지 SMT로 증명한다.
    # Z3가 없거나 특정 조건을 SMT로 인코딩할 수 없다면 EXPANSION으로 판정하고 사용자의 승인을 받도록 한다.
    if not Z3_AVAILABLE:
        return UpdateKind.EXPANSION  # [수정] EXPASION -> EXPANSION

    for tool in tools:
        names = arg_names.get(tool, [])
        if not names:
            continue
        solver = z3.Solver()
        svars = {name: z3.String(f"{tool}__{name}") for name in names}

        allowed_new = allowed_formula(new, tool, svars, permissive_on_unknown=True)
        allowed_old = allowed_formula(old, tool, svars, permissive_on_unknown=False)

        # 반례 찾기: new는 허용하면서 old는 허용하지 않는 호출이 존재하는지 확인한다.
        solver.add(z3.And(allowed_new, z3.Not(allowed_old)))
        result = solver.check()
        if result != z3.unsat:
            # sat = 실제 반례 발견 or unknown = 증명 불가 -> expansion으로 판정한다.
            return UpdateKind.EXPANSION
    return UpdateKind.NARROWING



# 함수이름: allowed_formula
# 인자:   policy (Policy) - 논리식을 만들 대상 정책
#         tool (str) - 도구 이름
#         svars (dict) - 인자 이름 -> Z3 문자열 미지수
#         permissive_on_unknown (bool) - 인코딩 못 하는 조건을 만났을 때
#                       True로 볼지 False로 볼지 (allow는 True쪽, forbid는
#                       반대쪽으로 향하게 해서 "불확실하면 항상 expansion으로
#                       판정"되도록 편향시키는 장치)
# 반환값: (의도상) "이 정책이 이 도구 호출을 허용한다"는 Z3 논리식
# 기능:   정책 안의 규칙들을 forbid 그룹/allow 그룹으로 나눠 각각 논리식으로
#         만들고, "forbid 중 어느 것에도 안 걸리면서 동시에 allow 중 하나에는
#         걸린다"는 최종 논리식을 만들어 반환하려는 함수.
def allowed_formula(policy: Policy, tool: str, svars: Dict[str, "z3.SeqRef"], permissive_on_unknown: bool):
    # 해당 정책이 이 도구 호출을 허용한다는 z3 논리식을 구성하는 함수
    # permissive_on_unknown=True  : 인코딩 불가능한 allow 조건 -> True
    # permissive_on_unknown=False : 인코딩 불가능한 forbid 조건 -> False
    # 두 선택 모두 불확실하면 expansion으로 판정하는 방향으로 편향되어 있다.
    forbid_terms, allow_terms = [], []
    for rule in policy.rules_for(tool):
        unknown_default = (
            (not permissive_on_unknown) if rule.effect == Effect.FORBID else permissive_on_unknown
        )
        term = rule_z3(rule, svars, unknown_default)
        (forbid_terms if rule.effect == Effect.FORBID else allow_terms).append(term)
    forbidden = z3.Or(*forbid_terms) if forbid_terms else z3.BoolVal(False)  # [수정] if allow_terms -> if forbid_terms
    allowed = z3.Or(*allow_terms) if allow_terms else z3.BoolVal(False)      # [수정] allowed 정의 누락 -> 추가
    return z3.And(z3.Not(forbidden), allowed)                                 # [수정] return 누락 -> 추가




# 함수이름: rule_z3
# 인자:   rule (Rule) - 논리식으로 바꿀 규칙 하나
#         svars (dict) - 인자 이름 -> Z3 문자열 미지수
#         unknown_default (bool) - 인코딩 불가능한 조건의 기본값
# 반환값: 이 규칙 하나를 나타내는 Z3 논리식
# 기능:   규칙의 when 안에 있는 조건들을 하나씩 condition_z3()로 논리식으로
#         바꾸고, 전부 z3.And로 묶는다 (한 규칙 안 조건들은 AND로 결합된다는
#         논문의 "조건들의 논리곱"이 바로 이 부분).
def rule_z3(rule: Rule, svars: Dict[str, "z3.SeqRef"], unknown_default: bool):
    terms = []
    for arg_name, cond in rule.when.items():
        var = svars.get(arg_name)
        if var is None:
            terms.append(z3.BoolVal(unknown_default))
        else:
            terms.append(condition_z3(cond, var, unknown_default))
    return z3.And(*terms) if terms else z3.BoolVal(True)


GLOB_SAFE_CHARS = set(
    "*abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@._-/: "
)


# 함수이름: condition_z3
# 인자:   cond (조건, "*" / {"in":...} / {"eq":...} / {"match":...} / 값)
#         var (Z3 문자열 미지수) - 비교 대상이 되는 변수
#         unknown_default (bool) - 인코딩 못 할 때 쓸 기본값
# 반환값: 이 조건 하나를 나타내는 Z3 논리식
# 기능:   condition_matches()와 똑같은 조건들을, "실제 값과 비교"가 아니라
#         "Z3 미지수에 대한 논리식"으로 바꿔주는 버전. in은 Or로 여러 값과의
#         등호를 묶고, eq는 등호 하나, match는 glob이 안전한 문자만 쓰였으면
#         정규식 매칭(z3.InRe)으로, 아니면 unknown_default로 보수적 처리.
def condition_z3(cond: Any, var: "z3.SeqRef", unknown_default: bool):
    if cond == "*":  # [수정] cond == "" -> cond == "*"
        return z3.BoolVal(True)
    if isinstance(cond, dict):
        if "in" in cond:
            return z3.Or(*[var == z3.StringVal(str(v)) for v in cond["in"]])
        if "eq" in cond:
            return var == z3.StringVal(str(cond["eq"]))
        if "match" in cond:
            glob = cond["match"]
            if set(glob) <= GLOB_SAFE_CHARS:
                return z3.InRe(var, glob_z3_re(glob))
            return z3.BoolVal(unknown_default)
        return z3.BoolVal(unknown_default)
    return var == z3.StringVal(str(cond))



# 함수이름: glob_z3_re
# 인자:   glob (str) - "*"만 와일드카드로 쓰는 단순 패턴 (예: "mock://*")
# 반환값: 그 패턴과 같은 뜻을 가지는 Z3 정규식 객체
# 기능:   glob 문자열을 한 글자씩 보면서, 고정 글자들은 z3.Re(글자)로,
#         "*"는 z3.Star(z3.AllChar(...))("아무 글자나 0개 이상")로 바꾸고,
#         그 조각들을 z3.Concat으로 순서대로 이어 붙여 하나의 정규식으로 완성한다.
def glob_z3_re(glob: str):
    parts, literal = [], ""
    for ch in glob:
        if ch == "*":
            if literal:
                parts.append(z3.Re(literal))
                literal = ""
            parts.append(z3.Star(z3.AllChar(z3.ReSort(z3.StringSort()))))  # [수정] AllChar(StringSort()) -> AllChar(ReSort(StringSort()))
        else:
            literal += ch

    if literal:
        parts.append(z3.Re(literal))
    if not parts:
        return z3.Star(z3.AllChar(z3.ReSort(z3.StringSort())))  # [수정] 위와 동일
    result = parts[0]
    for p in parts[1:]:
        result = z3.Concat(result, p)
    return result