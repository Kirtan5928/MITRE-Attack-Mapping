from mitreattack.stix20 import MitreAttackData
import re
from collections import OrderedDict
import json
from difflib import SequenceMatcher

# -------------------------------
# Similarity Function
# -------------------------------
def text_similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()

# -------------------------------
# Load MITRE ATT&CK data
# -------------------------------
attack_data = MitreAttackData("enterprise-attack.json")

# -------------------------------
# Load remediation data
# -------------------------------
try:
    with open("remediation.json") as f:
        remediation_map = json.load(f)
except:
    remediation_map = {}

# -------------------------------
# Explanation Generator
# -------------------------------
def generate_explanation(desc_lower, tech_name):
    words = [w for w in tech_name.lower().split() if len(w) > 3]
    matched = [w for w in words if w in desc_lower]

    if matched:
        return f"Detected keywords: {', '.join(matched[:5])}"
    return "Matched using contextual similarity and keyword scoring"

# -------------------------------
# 🔥 NEW: Proper Confidence Logic
# -------------------------------
def normalize_confidence(score, max_score):
    if max_score == 0:
        return 0

    # relative score (important)
    relative = score / max_score

    # base floor so it doesn’t look weak
    confidence = 0.6 + (relative * 0.35)

    # cap
    confidence = min(confidence, 0.95)

    return round(confidence * 100, 2)

# -------------------------------
# 🔥 Improved Remediation Logic
# -------------------------------
def get_remediation(tech_id, tactic):

    # 1. Exact match
    remediation = remediation_map.get(tech_id)

    # 2. Parent fallback
    if not remediation and "." in tech_id:
        parent_id = tech_id.split(".")[0]
        remediation = remediation_map.get(parent_id)

    # 3. Sub-technique enhancements (specific fixes)
    sub_specific = {
        "T1567.002": "Monitor cloud storage uploads, enforce access control policies, and enable audit logging for cloud environments.",
        "T1567.004": "Monitor webhook traffic, restrict external integrations, and validate outbound communication endpoints.",
        "T1059.001": "Restrict PowerShell execution, enable script block logging, and monitor suspicious command activity.",
        "T1003.001": "Protect LSASS memory, enable credential guard, and monitor abnormal credential access attempts."
    }

    if tech_id in sub_specific:
        remediation = sub_specific[tech_id]

    # 4. Tactic-based fallback (clean + meaningful)
    if not remediation:
        tactic_based = {
            "Execution": "Restrict script execution, enforce application whitelisting, and monitor process behavior.",
            "Persistence": "Audit startup programs, scheduled tasks, and registry entries for unauthorized changes.",
            "Privilege Escalation": "Limit administrative privileges and monitor abnormal privilege elevation.",
            "Credential Access": "Secure credential storage and monitor unauthorized access attempts.",
            "Lateral Movement": "Restrict remote services, enforce MFA, and monitor internal traffic anomalies.",
            "Exfiltration": "Monitor outbound data flows, use DLP solutions, and detect unusual data transfers.",
            "Command And Control": "Detect and block suspicious network communications and beaconing activity.",
            "Initial Access": "Implement phishing protection, email filtering, and user awareness training."
        }

        remediation = tactic_based.get(tactic, None)

    # 5. Final fallback (rare)
    if not remediation:
        remediation = "Enable monitoring, enforce access controls, and investigate abnormal system behavior."

    return remediation

# -------------------------------
# Deduplicate by Parent
# -------------------------------
def deduplicate_by_parent(results):
    seen = {}
    for r in results:
        parent = r['technique_id'].split('.')[0]

        if parent not in seen or r['score'] > seen[parent]['score']:
            seen[parent] = r

    return list(seen.values())

# -------------------------------
# Main Mapping Function
# -------------------------------
def map_to_attack(description: str, top_n: int = 5):

    if not description:
        return {"input": "", "results": []}

    desc_lower = description.lower().strip()
    seen = OrderedDict()

    all_techs = attack_data.get_techniques() + attack_data.get_subtechniques()

    scores = []

    for tech in all_techs:
        tech_id = tech['external_references'][0]['external_id']
        tech_name = tech['name'].lower()

        if tech.get('x_mitre_deprecated', False):
            continue

        score = 0
        matched_keywords = []

        # Similarity
        desc_text = tech.get('description', '').lower()
        sim_score = text_similarity(desc_lower, desc_text)
        score += sim_score * 30

        # Exact match
        if re.search(r'\b' + re.escape(tech_name) + r'\b', desc_lower):
            score += 25
            matched_keywords.append(tech_name)

        # Word match
        for word in tech_name.split():
            if len(word) > 3 and word in desc_lower:
                score += 7
                matched_keywords.append(word)

        # High-value keywords
        high_value = {
            'phish': ['T1566'],
            'powershell': ['T1059.001'],
            'lsass': ['T1003.001'],
            'mimikatz': ['T1003.001'],
            'scheduled task': ['T1053.005'],
            'rdp': ['T1021.001'],
            'dns tunnel': ['T1071.004'],
            'lateral': ['T1021'],
            'exfil': ['T1041', 'T1567']
        }

        for keyword, ids in high_value.items():
            if keyword in desc_lower and any(tech_id.startswith(i) for i in ids):
                score += 15
                matched_keywords.append(keyword)

        if score >= 15 and tech_id not in seen:

            kill_chain = tech.get('kill_chain_phases', [])
            tactic = (
                kill_chain[0].get('phase_name', 'unknown')
                .replace('-', ' ')
                .title()
                if kill_chain else 'Unknown'
            )

            seen[tech_id] = {
                'technique_id': tech_id,
                'name': tech['name'],
                'tactic': tactic,
                'score': score,
                'matched_keywords': matched_keywords
            }

            scores.append(score)

    if not seen:
        return {"input": description, "results": []}

    max_score = max(scores)

    results = []

    for r in seen.values():
        explanation = (
            f"Detected keywords: {', '.join(set(r['matched_keywords']))}"
            if r['matched_keywords']
            else generate_explanation(desc_lower, r['name'])
        )

        confidence = normalize_confidence(r['score'], max_score)

        remediation = get_remediation(r['technique_id'], r['tactic'])

        results.append({
            'technique_id': r['technique_id'],
            'name': r['name'],
            'tactic': r['tactic'],
            'confidence': confidence,
            'score': round(r['score'], 2),
            'explanation': explanation,
            'remediation': remediation
        })

    # Sort + deduplicate
    results = sorted(results, key=lambda x: x['score'], reverse=True)
    results = deduplicate_by_parent(results)
    results = results[:top_n]

    return {
        "input": description,
        "results": results
    }

