\# 🛡️ CyberShield – MITRE ATT\&CK Mapping Framework



\## 🚀 Overview



CyberShield is an automated threat analysis framework that maps security logs and threat descriptions to \*\*MITRE ATT\&CK techniques, tactics, and sub-techniques\*\*.



It simulates real-world SOC (Security Operations Center) workflows by providing:



\* Intelligent detection

\* Explainable results

\* Actionable remediation

\* Clean visualization dashboard



\---



\## 🎯 Key Features



\* 🔍 \*\*Automated MITRE ATT\&CK Mapping\*\*



&#x20; \* Detects techniques, tactics, and sub-techniques from input logs/descriptions



\* 🧠 \*\*Hybrid Detection Engine\*\*



&#x20; \* Combines keyword-based matching with contextual similarity scoring



\* 📊 \*\*Confidence Scoring System\*\*



&#x20; \* Dynamic, normalized confidence (60–95% realistic range)



\* 💡 \*\*Explainable Results\*\*



&#x20; \* Shows why a technique was detected



\* 🛡️ \*\*Remediation Suggestions\*\*



&#x20; \* Technique-aware and tactic-based security recommendations



\* 📈 \*\*Tactic Distribution Visualization\*\*



&#x20; \* Clean dark-themed graph showing attack phase distribution



\* 📥 \*\*MITRE ATT\&CK Navigator Export\*\*



&#x20; \* Generate JSON layer for visualization in ATT\&CK Navigator



\* 🎨 \*\*Modern Dashboard\*\*



&#x20; \* Built with Streamlit

&#x20; \* Minimal, clean, and user-friendly UI



\---



\## 🧠 How It Works



1\. User inputs a threat description or security log

2\. Text is preprocessed and normalized

3\. Detection engine applies:



&#x20;  \* Keyword matching

&#x20;  \* Contextual similarity (SequenceMatcher)

4\. Techniques are scored and ranked

5\. Duplicate techniques are filtered (parent-level deduplication)

6\. Final output includes:



&#x20;  \* Technique

&#x20;  \* Tactic

&#x20;  \* Confidence

&#x20;  \* Explanation

&#x20;  \* Remediation



\---



## 📊 Dashboard Preview



## 📊 Dashboard Preview

![Input](https://raw.githubusercontent.com/Kirtan5928/MITRE-Attack-Mapping/main/input.png)

![Results](https://raw.githubusercontent.com/Kirtan5928/MITRE-Attack-Mapping/main/results.png)

![Graph](https://raw.githubusercontent.com/Kirtan5928/MITRE-Attack-Mapping/main/graph.png)


\## 🛠️ Tech Stack



\* \*\*Python\*\*

\* \*\*Streamlit\*\* (UI Dashboard)

\* \*\*MITRE ATT\&CK STIX Dataset\*\*

\* \*\*Matplotlib\*\* (Visualization)

\* \*\*JSON\*\*



\---



\## ▶️ How to Run



```bash

pip install -r requirements.txt

streamlit run app.py

```



\---



\## 📁 Project Structure



```

CyberShield/

│

├── app.py                  # Streamlit dashboard

├── mapper.py               # Core detection logic

├── remediation.json        # Remediation mapping

├── enterprise-attack.json  # MITRE ATT\&CK dataset

├── requirements.txt

└── README.md

```



\---



\## 🔮 Future Improvements



\* 📂 Log file upload (real SIEM-style input)

\* 🤖 LLM-based explanation generation

\* 🧠 Advanced NLP (embeddings / transformers)

\* 📊 Attack timeline visualization

\* 🌐 API integration for SOC tools (Splunk, ELK)



\---



\## 📌 Use Cases



\* SOC Analyst training

\* Threat detection simulation

\* Cybersecurity portfolio project

\* MITRE ATT\&CK exploration



\---



\## 👨‍💻 Author



Kirtan J Gowda



\---



