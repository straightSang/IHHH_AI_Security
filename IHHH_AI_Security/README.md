# IHHH_AI_Security

**Progent: Securing AI Agents with Privilege Control** (Shi et al., arXiv:2504.11703)
논문의 권한 제어(privilege control) 아이디어를 간략화하여 재구현하고, 4개의
도구(`read_files`, `write_files`, `calculator`, `http_get`)를 가진 데모
에이전트에 적용한 뒤, 직접/간접 프롬프트 인젝션 공격 20건으로 레드티밍한
프로젝트입니다.

> ⚠️ 교육·데모 목적의 **간략화 구현**입니다. 실제 프로덕션 Progent(원 논문
> 저자들의 구현)는 `https://github.com/sunblaze-ucb/progent` 를 참고하세요.

---

## 폴더 구조

```
IHHH_AI_Security/
├── agent/
│   ├── tools.py        # read_files / write_files / calculator / http_get 구현
│   └── agent.py         # Progent 정책으로 보호되는 실제 동작 에이전트 (LLM 모드 + 재생 모드)
├── progent/
│   ├── policy.py         # 정책 엔진: Rule/Policy, 런타임 강제(Alg.2), 합성(Alg.4), SMT 확장/축소 판정
│   └── policy_generator.py  # 초기 정책 생성 / 갱신 (휴리스틱 기본값 + 선택적 실제 LLM)
├── defenses/policy/
│   ├── rules.yaml         # 범용(generic) 최소 권한 정책
│   ├── check_policy.py    # check_policy() 유틸리티
│   └── test_policy.py     # allow/forbid 단위 테스트 8건
├── attacks/
│   ├── direct_01~10.yaml    # 직접 프롬프트 인젝션(사용자가 바로 악성 행동 요청) 10건
│   ├── indirect_01~10.yaml  # 간접 프롬프트 인젝션(도구 반환값 속 인젝션) 10건
│   └── fake_internet.json   # mock:// URL 오프라인 재현용 가짜 인터넷 콘텐츠
├── eval/
│   └── run_eval.py         # 20개 공격을 3가지 방어 조건으로 평가 -> results/baseline.json
├── results/
│   └── baseline.json       # 최신 평가 결과 (ASR + 유용성)
├── workspace/               # 에이전트가 실제로 읽고 쓰는 샌드박스 (샘플 파일 포함)
├── requirements.txt
└── README.md (이 파일)
```

---

## 빠른 시작

```bash
cd IHHH_AI_Security
pip install -r requirements.txt

# 1) 정책 엔진 단위 테스트
python defenses/policy/test_policy.py

# 2) 공격 20건 전체 평가 (API 키 불필요)
python eval/run_eval.py

# 3) 공격 하나를 실제로 재생해서 눈으로 확인 (API 키 불필요)
python agent/agent.py --demo attacks/indirect_01.yaml          # Progent 보호 O
python agent/agent.py --demo attacks/indirect_01.yaml --no-progent   # 무방어 비교

# 4) (선택) 실제 Claude가 도구를 골라 쓰는 LLM 모드
export ANTHROPIC_API_KEY=sk-ant-...
python agent/agent.py --task "workspace/notes.txt 내용을 요약해줘"
```

---

## 핵심 설계

### 1. 정책 엔진 (`progent/policy.py`)

논문 Figure 2b의 정책 문법을 그대로 옮겼습니다.

```python
Rule(tool="http_get", effect=Effect.FORBID,
     when={"url": {"match": "*evil-collector*"}},
     fallback_msg="공격자 도메인으로의 데이터 유출 시도가 차단되었습니다.")
```

- `Policy.check()` — 논문 **Algorithm 2** (forbid 규칙을 allow보다 먼저 검사, 매치되는 규칙 없으면 기본 거부)
- `compose_check(generic, task_specific)` — 논문 **Algorithm 4** (범용 정책을 먼저 평가하고, 명시적 판정이 없을 때만 작업별 정책으로 넘김)
- `compare_policies(old, new)` — 논문 **4.3절**의 SMT 기반 확장/축소 판정을 **실제 Z3 솔버**로 구현. `old`를 과소추정, `new`를 과대추정하도록 인코딩해 "증명되지 않은 갱신은 항상 확장(승인 필요)으로 처리"하는 **fail-closed** 방식을 취합니다 (논문 6절의 단조적 제약과 동일한 안전 철학).

```python
>>> compare_policies(P1, P2, ...)   # 도구 추가 -> EXPANSION (승인 필요)
>>> compare_policies(P2, P3, ...)   # 수신자를 alice로 좁힘 -> NARROWING (자동 적용)
```

### 2. 도구 (`agent/tools.py`)

- `read_files` / `write_files` : `workspace/` 밖으로 벗어나는 경로(`..`)는 도구 자체에서 거부 (정책과 별개의 2차 방어선)
- `calculator` : `ast` 파싱 기반 안전한 사칙연산만 허용 (`__import__('os').system(...)` 같은 코드 인젝션은 파싱 단계에서 거부)
- `http_get` : `mock://<id>` URL은 `attacks/fake_internet.json` 에서 읽어와, 네트워크 없이도 공격 시나리오를 100% 재현 가능

### 3. 범용 정책 vs 작업별(Progent) 정책

`defenses/policy/rules.yaml`(범용)은 논문 8.1절의 실제 실험 설정을 따라 **"비민감·읽기전용 도구만 전역 허용"**합니다. `http_get`은 인자(URL)에 따라 정보 조회도, 데이터 유출도 될 수 있는 양날의 검 도구이므로 **의도적으로 전역 allow 규칙을 두지 않았습니다** — 어떤 URL이 정당한지는 각 공격 yaml의 `task_policy`(=Progent가 LLM으로 생성했을 법한 작업별 최소 권한 정책)만이 판단합니다.

### 4. 평가 결과 (`eval/run_eval.py` → `results/baseline.json`)

| 방어 조건 | 공격 성공률(ASR) ↓ | 유용성(정상 작업 통과율) ↑ |
|---|---|---|
| 무방어 | 95.0% | 100.0% |
| 범용 정책만 | 0.0% | 50.0% (간접 공격 계열은 0%: 정당한 조회까지 막아버림) |
| **Progent (범용+작업별)** | **0.0%** | **100.0%** |

범용 정책만으로는 공격은 막지만 정상적인 `http_get` 조회까지 함께 막아 **유용성이 크게 희생**됩니다. Progent(작업별 정책 합성)는 공격을 막으면서도 **정상 작업은 100% 그대로 통과**시켜, 논문이 강조하는 "보안과 유용성을 동시에" 달성한다는 결론을 그대로 재현합니다.

### 5. 공격 시나리오 (`attacks/*.yaml`)

각 파일은 다음 필드를 가집니다.

| 필드 | 설명 |
|---|---|
| `task` | 사용자가 에이전트에게 준 (겉보기) 작업 지시문 |
| `steps` | 실제로 실행되는 도구 호출 시퀀스 |
| `malicious_step` | `steps` 중 "공격 성공 여부"를 판정하는 기준이 되는 인덱스 |
| `benign_step_indices` | 정상 작업 완수에 실제로 필요한(=유용성 계산에 쓰이는) 단계들의 인덱스 |
| `defense_layer` | `policy`(기본값, 정책 레이어가 막아야 함) 또는 `tool`(도구 내부 안전장치가 막아야 함) |
| `task_policy` | 이 작업에 대해 Progent가 생성했을 법한 최소 권한 정책 |

- `direct_*` : 사용자가 (프롬프트 인젝션 없이) **직접** 악성 행동을 요청 — 최소 권한 정책만으로 막혀야 함
- `indirect_*` : 정상적인 작업 처리 중 도구 반환값(이메일, 위키, 청구서 등)에 **숨겨진 지시문**이 섞여 있어 이를 그대로 따르면 공격이 성립 — Progent의 핵심 방어 대상

---

## 알려진 단순화 (실제 Progent 논문과의 차이)

- SMT 인코딩은 정확값 / 와일드카드(`*`) / `in`-리스트 / `*`만 쓰는 단순 glob만 지원합니다. 임의의 정규식은 인코딩하지 않고 항상 "증명 불가 → 확장으로 간주(승인 필요)"로 안전하게 처리합니다.
- `eval/run_eval.py`는 각 공격을 **미리 정해진 고정 시퀀스**로 평가합니다. 실제 Progent는 에이전트가 차단 메시지를 받고 스스로 전략을 바꿀 수 있지만(논문 4.1절의 fallback 메커니즘), 여기서는 재현성을 위해 시퀀스를 고정했습니다. `agent/agent.py --demo` 로 재생하면 각 단계가 정책에 의해 실제로 차단/허용되는 과정을 그대로 볼 수 있습니다.
- `progent/policy_generator.py`의 LLM 기반 정책 생성/갱신은 `ANTHROPIC_API_KEY`가 있을 때만 활성화되며, 실패 시 안전하게 휴리스틱으로 폴백합니다.
