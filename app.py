import streamlit as st
from mapper import map_to_attack
from datetime import datetime
import json
import matplotlib.pyplot as plt

# -------------------------------
# Page Config
# -------------------------------
st.set_page_config(page_title="CyberShield", page_icon="🛡️", layout="wide")

# -------------------------------
# Header
# -------------------------------
st.markdown("""
# CyberShield Project 
### MITRE ATT&CK Mapping Framework
""")

st.markdown("Map security logs and threats to ATT&CK techniques in real time.")
st.markdown("---")

# -------------------------------
# Input Section
# -------------------------------
st.subheader("Analyze Threat")

description = st.text_area(
    "Threat Input",
    placeholder="Enter threat description or logs (e.g., phishing email, PowerShell execution, data exfiltration...)",
    height=120,
    label_visibility="collapsed"
)

analyze = st.button("Analyze", use_container_width=True)

st.markdown("---")

# -------------------------------
# Processing
# -------------------------------
if analyze:
    if description.strip():

        with st.spinner("Analyzing threat..."):
            output = map_to_attack(description, top_n=6)
            results = output["results"]

        # -------------------------------
        # Top Detection
        # -------------------------------
        if results:
            top = results[0]
            st.markdown(f"""
            ### Top Detection
            **{top['technique_id']} — {top['name']}**  
            Confidence: **{top['confidence']}%**
            """)
            st.markdown("---")

        # -------------------------------
        # Results Section
        # -------------------------------
        st.subheader("Detected Techniques")

        if results:
            for r in results:
                confidence = r['confidence']

                if confidence > 80:
                    color = "🟢"
                elif confidence > 60:
                    color = "🟡"
                else:
                    color = "🔴"

                with st.container():
                    st.markdown(f"""
                    **{r['technique_id']} — {r['name']}**  
                    `{r['tactic']}` • {color} {confidence}%
                    """)

                    st.progress(confidence / 100)

                    with st.expander("Details"):
                        st.markdown(f"**Explanation:** {r['explanation']}")
                        st.markdown(f"**Remediation:** {r['remediation']}")

                    st.markdown("---")

        else:
            st.warning("No strong matches found.")

        # -------------------------------
        # Summary
        # -------------------------------
        if results:
            st.subheader("📊 Summary")

            col1, col2, col3 = st.columns(3)
            col1.metric("Techniques", len(results))
            col2.metric("Top Confidence", f"{results[0]['confidence']}%")
            col3.metric("Tactics", len(set(r['tactic'] for r in results)))

        # -------------------------------
        # 🔥 Futuristic Dark Graph
        # -------------------------------
        if results:
            st.subheader("📊 Tactic Distribution")

            tactic_counts = {}
            for r in results:
                tactic = r['tactic']
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

            tactics = list(tactic_counts.keys())
            counts = list(tactic_counts.values())

            # Create dark themed plot
            fig, ax = plt.subplots(figsize=(4, 2))

            fig.patch.set_facecolor('#0E1117')
            ax.set_facecolor('#0E1117')

            # Neon-like bars
            bars = ax.bar(tactics, counts)

            for bar in bars:
                bar.set_color('#00FFAA')  # neon green

            # Style text
            ax.set_title("Tactic Distribution", color='white')
            ax.tick_params(axis='x', colors='white')
            ax.tick_params(axis='y', colors='white')

            # Remove spines for clean look
            for spine in ax.spines.values():
                spine.set_visible(False)

            plt.xticks(rotation=30)

            st.pyplot(fig, width='content')

        # -------------------------------
        # JSON Export
        # -------------------------------
        st.subheader("Export Results")

        layer = {
            "name": "CyberShield Layer",
            "version": "4.5",
            "domain": "enterprise-attack",
            "created": datetime.now().isoformat(),
            "techniques": []
        }

        for r in results:
            layer["techniques"].append({
                "techniqueID": r['technique_id'],
                "tactic": r['tactic'].lower().replace(" ", "-"),
                "score": r['confidence']
            })

        json_data = json.dumps(layer, indent=2)

        st.download_button(
            label="Download ATT&CK Navigator JSON",
            data=json_data,
            file_name="cybershield_layer.json",
            mime="application/json",
            use_container_width=True
        )

    else:
        st.error("Please enter a threat description.")

# -------------------------------
# Footer
# -------------------------------
st.markdown("---")
st.caption("CyberShield • MITRE ATT&CK Automation Framework")

