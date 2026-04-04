# 🛡️ CyberShield – MITRE ATT&CK Mapping Framework

## Overview

CyberShield is a simple tool I built to understand how real-world threat descriptions can be mapped to the MITRE ATT&CK framework.

The idea behind the project was to simulate a basic SOC workflow — where logs or alerts come in, and we try to identify what kind of attack techniques are being used.

Given a piece of text (like a security alert or incident description), the system analyzes it and returns:

* Relevant MITRE ATT&CK techniques
* Associated tactics
* A confidence score
* A short explanation of why it was matched
* Suggested remediation steps

---

## Why I built this

While learning cybersecurity, I noticed that the MITRE ATT&CK framework is widely used, but manually mapping alerts to techniques can be repetitive and time-consuming.

I wanted to build something that:

* Automates this mapping process
* Gives a quick overview of an attack scenario
* Is simple enough to experiment with and improve

This project helped me better understand how threat detection and analysis actually works in practice.

---

## How it works

1. The user enters a threat description or log data
2. The text is cleaned and converted to lowercase
3. Each MITRE technique is compared against the input using:

   * Keyword matching
   * Context similarity (using SequenceMatcher)
4. A score is assigned based on how well it matches
5. The top techniques are selected and filtered to avoid duplicates
6. Each result is enriched with:

   * Explanation (matched keywords or similarity reasoning)
   * Remediation (based on technique or tactic)
7. Results are displayed in a dashboard along with a small visualization

---

## Features

* Maps text to MITRE ATT&CK techniques and tactics
* Confidence scoring based on match strength
* Explanation for each detected technique
* Basic remediation suggestions
* Clean Streamlit dashboard
* Tactic distribution graph for quick analysis
* Option to export results as a JSON layer (for ATT&CK Navigator)

---

## Dashboard Preview

![Input](https://raw.githubusercontent.com/Kirtan5928/MITRE-Attack-Mapping/main/input.png)
![Results](https://raw.githubusercontent.com/Kirtan5928/MITRE-Attack-Mapping/main/results.png)
![Graph](https://raw.githubusercontent.com/Kirtan5928/MITRE-Attack-Mapping/main/graph.png)

---

## Tech Stack

* Python
* Streamlit
* MITRE ATT&CK STIX dataset
* Matplotlib

---

## How to run

```bash
pip install -r requirements.txt
streamlit run app.py
```

---

## Project structure

```
CyberShield/
│
├── app.py                  # Streamlit dashboard
├── mapper.py               # Core mapping logic
├── remediation.json        # Remediation data
├── enterprise-attack.json  # MITRE ATT&CK dataset
├── requirements.txt
└── README.md
```

---

## What I learned

* How the MITRE ATT&CK framework is structured and used
* How to design a simple detection pipeline
* Balancing accuracy vs simplicity in rule-based systems
* Building clean dashboards using Streamlit
* Structuring a project so it’s easy to understand and extend

---

## Limitations

* The mapping is rule-based (not ML-based), so it may miss nuanced cases
* Input is manual (no log ingestion yet)
* Confidence scores are heuristic, not probabilistic

---

## Future improvements

* Add log file upload support
* Use embeddings or NLP models for better matching
* Improve remediation with more context-aware suggestions
* Deploy as a web app

---

## Author

Kirtan J Gowda
