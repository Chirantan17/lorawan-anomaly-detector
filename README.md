[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://lorawan-anomaly-detector-ztt8vwhvftlozngfbhjfut.streamlit.app)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![XGBoost](https://img.shields.io/badge/Model-XGBoost%20%7C%20iForest-green)
![Status](https://img.shields.io/badge/Deployment-Production--Ready-brightgreen)

# Real-Time LoRaWAN Physical-Layer Intrusion & Anomaly Detection System (IDS)

An end-to-end Machine Learning pipeline and interactive Streamlit web application for real-time detection and explainability of physical-layer cyberattacks in LoRaWAN IoT networks.

---

## 📌 Project Overview & Lab Progression

* **Lab 1 — Real-Time Pipeline & Streaming Dashboard:** Synthesized 100,000 LoRaWAN physical-layer telemetry frames ($\text{RSSI}$, $\text{SNR}$, Spreading Factor, Inter-Arrival Time) and deployed continuous streaming analytics.
* **Lab 2 — Multi-Model Engine & Signal Separability:** Benchmark comparison between Supervised (XGBoost, Random Forest) and Unsupervised (Isolation Forest) models paired with 3D physical-layer cluster separation plots ($\text{RSSI}$ vs $\text{SNR}$ vs $\text{SF}$).
* **Lab 3 — Multi-Vector Attack Simulator & Explainable AI (SHAP):** Integrated specific physical/MAC attack models and integrated SHAP TreeExplainer waterfall plots for sample-level root-cause threat attribution.

---

## 🛡️ Multi-Vector Attack Signatures

* **Distance / RF Spoofing:** Detects path-loss anomalies where high $\text{RSSI}$ is paired with unnaturally low $\text{SNR}$ values.
* **Replay Attacks:** Flags duplicate or out-of-sequence Frame Counters ($\text{FCnt}$) transmitted outside valid window bounds.
* **DoS / Jamming Flooding:** Detects anomalous burst packet arrival rates exceeding expected duty cycle limits ($\Delta t < 0.05\text{s}$).

---

## 📊 Benchmark Model Performance

| Model Engine | Paradigm | Precision | Recall | F1-Score | Latency / Packet | Primary Role |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **XGBoost Classifier** | Supervised | **98.8%** | **99.2%** | **99.0%** | 2.1 ms | Known Signature Detection |
| **Random Forest** | Supervised | 97.9% | 98.4% | 98.1% | 4.8 ms | Baseline Benchmark |
| **Isolation Forest** | Unsupervised | 89.1% | 84.5% | 86.7% | **1.2 ms** | Zero-Day Anomaly Detection |

---

## 🔍 Explainable AI (SHAP XAI)

To eliminate black-box opacity in security alerting, the system computes additive feature attributions using SHAP TreeExplainer:

$$\phi_i(x) = \sum_{S \subseteq F \setminus \{i\}} \frac{|S|!(|F|-|S|-1)!}{|F|!} \left[ f_x(S \cup \{i\}) - f_x(S) \right]$$

Every flagged frame generates a dynamic waterfall attribution plot isolating the exact RF metric driving the security alert.

---

## ⚡ Quick Start (Local Setup)

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/Chirantan17/lorawan-anomaly-detector.git](https://github.com/Chirantan17/lorawan-anomaly-detector.git)
   cd lorawan-anomaly-detector