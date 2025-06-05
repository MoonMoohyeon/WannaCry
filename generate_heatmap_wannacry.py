import json
from collections import defaultdict

# 1. STIX JSON 로드
with open("enterprise-attack.json", "r", encoding="utf-8") as f:
    stix_bundle = json.load(f)

objects = stix_bundle.get("objects", [])

# 2. WannaCry 악성코드 ID 찾기
wcry_id = None
for obj in objects:
    if obj.get("type") == "malware" and obj.get("name", "").lower() == "wannacry":
        wcry_id = obj.get("id")
        break

if not wcry_id:
    raise ValueError("WannaCry malware 객체를 STIX에서 찾을 수 없습니다.")

# 3. Attack-Pattern 오브젝트 정보(techniqueID, kill_chain_phases) 매핑
#    attack_pattern_id_to_tid: STIX 내 UUID -> "TXXXX"
#    attack_pattern_id_to_phases: STIX 내 UUID -> [phase_name, ...]
attack_pattern_id_to_tid = {}
attack_pattern_id_to_phases = {}

for obj in objects:
    if obj.get("type") == "attack-pattern":
        ap_id = obj["id"]
        # external_references에서 "mitre-attack" 출처의 external_id
        ext_refs = obj.get("external_references", [])
        tid = None
        for ext in ext_refs:
            if ext.get("source_name") == "mitre-attack" and ext.get("external_id", "").startswith("T"):
                tid = ext["external_id"]
                break
        if not tid:
            continue

        # kill_chain_phases 배열 내부에서 "mitre-attack"의 phase_name들만 추출
        phases = []
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                phases.append(phase.get("phase_name"))
        if not phases:
            # 만약 kill_chain_phases가 없으면 빈 리스트로 두거나 "unknown" 처리를 할 수 있음
            phases = []

        attack_pattern_id_to_tid[ap_id] = tid
        attack_pattern_id_to_phases[ap_id] = phases

# 4. WannaCry가 사용하는 기법 집계
#    동일한 기법을 중복해서 넣지 않기 위해 set() 사용
wcry_techniques = {}

for obj in objects:
    if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses":
        src = obj.get("source_ref")
        tgt = obj.get("target_ref")
        if src == wcry_id and tgt in attack_pattern_id_to_tid:
            tid = attack_pattern_id_to_tid[tgt]
            phases = attack_pattern_id_to_phases.get(tgt, [])
            # kill_chain_phases에 여러 tactic이 있을 수 있으므로 첫 번째만 꺼내거나
            # 아니면 논리적으로 한 기법이 여러 택틱에 걸쳐 있으면 리스트 중 하나를 택해야 함.
            # 가장 첫 번째 phase_name을 tactic으로 사용
            tactic = phases[0] if phases else "unknown"
            wcry_techniques[tid] = tactic

# 5. Navigator Layer JSON 구조 생성

navigator_layer = {
    "name": "layer",
    "versions": {
        "attack": "11",
        "navigator": "5.1.0",
        "layer": "4.5"
    },
    "domain": "enterprise-attack",
    "description": "",
    "filters": {
        "platforms": [
            "Windows",
            "Linux",
            "macOS",
            "PRE",
            "Containers",
            "Network",
            "Office 365",
            "SaaS",
            "Google Workspace",
            "IaaS",
            "Azure AD"
        ]
    },
    "sorting": 0,
    "layout": {
        "layout": "flat",
        "aggregateFunction": "sum",
        "showID": True,
        "showName": True,
        "showAggregateScores": True,
        "countUnscored": False,
        "expandedSubtechniques": "none"
    },
    "hideDisabled": False,
    "techniques": [],
    "gradient": {
        "colors": [
            "#ff6666ff",
            "#ffe766ff",
            "#8ec843ff"
        ],
        "minValue": 0,
        "maxValue": 100
    },
    "legendItems": [],
    "metadata": [],
    "links": [],
    "showTacticRowBackground": False,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": True,
    "selectSubtechniquesWithParent": False,
    "selectVisibleTechniques": False
}

# 6. tactics 이름 매핑 (STIX kill_chain_phases phase_name -> Navigator 내부에서 기대하는 소문자 형태)
for tid, tactic in wcry_techniques.items():
    navigator_layer["techniques"].append({
        "techniqueID": tid,
        "tactic": tactic,      # ex) "impact", "execution" 등
        "score": 100,          # WannaCry 단일 malware이므로 100으로 고정
        "color": "",           # 비워두면 gradient에 따라 자동 지정
        "comment": "",
        "enabled": True,
        "metadata": [],
        "links": [],
        "showSubtechniques": False
    })

# 7. JSON 파일로 저장
with open("wannacry_layer.json", "w", encoding="utf-8") as fout:
    json.dump(navigator_layer, fout, indent=2, ensure_ascii=False)

print("wannacry_layer.json 생성 완료!")
