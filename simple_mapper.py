from mitreattack.stix20 import MitreAttackData
import re
from collections import OrderedDict

print("🚀 CyberShield - Phase 2.5: Clean & Smart ATT&CK Mapper\n")

attack_data = MitreAttackData("enterprise-attack.json")
print("✅ ATT&CK data loaded successfully!\n")

def clean_map_to_attack(description: str, top_n=5):
    """Clean, smart mapper with duplicate removal and better filtering"""
    if not description:
        return []
    
    desc_lower = description.lower().strip()
    seen = OrderedDict()   # To remove duplicates while preserving order
    
    all_techs = attack_data.get_techniques() + attack_data.get_subtechniques()
    
    for tech in all_techs:
        tech_id = tech['external_references'][0]['external_id']
        tech_name = tech['name'].lower()
        
        # Skip deprecated techniques
        if tech.get('x_mitre_deprecated', False):
            continue
        
        score = 0
        
        # Strong matches
        if re.search(r'\b' + re.escape(tech_name) + r'\b', desc_lower):
            score += 25
        
        # Word matches (more weight to longer, meaningful words)
        name_words = [w for w in tech_name.split() if len(w) > 3]
        for word in name_words:
            if word in desc_lower:
                score += 7
        
        # Common high-value keywords
        high_value = {
            'phish': ['T1566'],
            'powershell': ['T1059.001'],
            'lsass': ['T1003.001'],
            'mimikatz': ['T1003.001'],
            'scheduled task': ['T1053.005'],
            'rdp': ['T1021.001'],
            'dns tunnel': ['T1071.004'],
            'lateral': ['T1021', 'T1570'],
            'exfil': ['T1041', 'T1567']
        }
        
        for keyword, good_ids in high_value.items():
            if keyword in desc_lower and tech_id.startswith(tuple(good_ids)):
                score += 15
        
        if score >= 10:
            kill_chain = tech.get('kill_chain_phases', [])
            tactic = kill_chain[0].get('phase_name', 'unknown').replace('-', ' ').title() if kill_chain else 'Unknown'
            
            # Avoid duplicates
            if tech_id not in seen:
                seen[tech_id] = {
                    'technique_id': tech_id,
                    'name': tech['name'],
                    'tactic': tactic,
                    'score': score
                }
    
    # Convert to list and sort
    matches = sorted(seen.values(), key=lambda x: x['score'], reverse=True)
    return matches[:top_n]

# ====================== TEST CASES ======================
test_cases = [
    "The attacker sent a phishing email with a malicious attachment to trick the employee",
    "PowerShell script was used to download and execute malware from the internet",
    "The malware created a scheduled task to run every time the system starts",
    "The attacker dumped credentials from LSASS memory using Mimikatz",
    "The hacker used RDP to move laterally to another server",
    "Data was exfiltrated to an external server using DNS tunneling"
]

print("🔍 Testing Clean Smart Mapper:\n")

for i, text in enumerate(test_cases, 1):
    print(f"Test {i}: \"{text}\"")
    results = clean_map_to_attack(text)
    
    if results:
        for match in results:
            print(f"   → {match['technique_id']} | {match['name']} | Tactic: {match['tactic']} (Score: {match['score']})")
    else:
        print("   No strong matches found.")
    
    print("-" * 85)

print("\n✅ Cleaner mapper is ready!")
print("Next: We will add ATT&CK Navigator Layer generation (the coolest part)")