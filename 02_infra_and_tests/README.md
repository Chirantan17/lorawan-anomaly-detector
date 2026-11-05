# 📡 Real-Time LoRaWAN Intrusion & Anomaly Detection System

An end-to-end Machine Learning pipeline and real-time dashboard designed to detect spoofing, node rogue injection, and physical-layer anomalies in LoRaWAN IoT networks.

## 📌 Architecture Overview
- **Data Engineering:** Synthesized 100,000 LoRaWAN packet records capturing physical layer metrics: RSSI (Received Signal Strength Indicator), SNR (Signal-to-Noise Ratio), Spreading Factor (SF), Inter-Arrival Time, and Frame Counter (`FCnt`).
- **Model Engine:** Benchmarked supervised models (**XGBoost**, **Random Forest**) alongside unsupervised anomaly detectors (**Isolation Forest**).
- **Real-Time Telemetry Dashboard:** Streamlit UI simulating live gateway packet streaming, threat metrics, and physical-layer signal cluster separability.

## 🚀 Key Features
- **Live Intrusion Stream:** Real-time metrics tracking clean vs. malicious traffic batches with conditional log highlighting.
- **Signal Separability Analytics:** 3D cluster visualizations (RSSI vs. SNR vs. SF) proving physical signal separation.
- **Multi-Model Selector:** Dynamic engine toggling between supervised classifiers and unsupervised isolation algorithms.

## 🛠️ Tech Stack
- **Language:** Python 3.11
- **Machine Learning:** XGBoost, Scikit-Learn
- **Data Engineering:** Pandas, NumPy, Joblib
- **Visualization & UI:** Streamlit, Plotly Express, Matplotlib
- **Explainability:** SHAP

---

## ⚡ Quick Start (Local Setup)

### 1. Clone & Setup Environment
```bash
git clone [https://github.com/Chirantan17/lorawan-anomaly-detector.git](https://github.com/Chirantan17/lorawan-anomaly-detector.git)
cd lorawan-anomaly-detector

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt