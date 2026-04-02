from mitreattack.stix20 import MitreAttackData
import os

print("🚀 CyberShield Project - Phase 1")
print("Loading the full MITRE ATT&CK Enterprise Matrix...\n")

file_path = "enterprise-attack.json"

if not os.path.exists(file_path):
    print(f"❌ '{file_path}' not found. Please download it first.")
    exit()

print(f"✅ Found {file_path} – Loading data...\n")

# Load the ATT&CK data
attack_data = MitreAttackData(file_path)

print("✅ Success! The entire ATT&CK Enterprise matrix is now loaded.\n")

# Get statistics
tactics = attack_data.get_tactics()
techniques = attack_data.get_techniques()
subtechniques = attack_data.get_subtechniques()   # ← Fixed: no underscore

print("📊 Current ATT&CK Enterprise Statistics (2026):")
print(f"   • Tactics           : {len(tactics)}")
print(f"   • Techniques        : {len(techniques)}")
print(f"   • Sub-techniques    : {len(subtechniques)}")
print("-" * 70)

# Show sample Tactics
print("Sample Tactics:")
for tactic in tactics[:8]:
    ext_ref = tactic.get('external_references', [{}])[0]
    tactic_id = ext_ref.get('external_id', 'N/A')
    print(f"   • {tactic['name']}  ({tactic_id})")

print("\n" + "="*80 + "\n")

# Show sample Techniques
print("Sample Techniques:")
for tech in techniques[:6]:
    ext_ref = tech.get('external_references', [{}])[0]
    tech_id = ext_ref.get('external_id', 'N/A')
    
    # Get the main tactic name
    kill_chain = tech.get('kill_chain_phases', [])
    tactic_name = kill_chain[0].get('phase_name', 'Unknown') if kill_chain else 'Unknown'
    
    print(f"   → {tech_id} : {tech['name']}")
    print(f"     Tactic → {tactic_name}")
    print("     ───────────────────────────────")

print("\n🎉 Phase 1 is COMPLETE!")
print("You now have the full official MITRE ATT&CK database loaded and ready.")
print("We can now start building the mapping logic in Phase 2.")