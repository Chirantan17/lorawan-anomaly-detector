# 📡 Real-Time LoRaWAN Intrusion & Anomaly Detection System

An end-to-end Machine Learning pipeline and real-time dashboard designed to detect spoofing, node rogue injection, and physical layer anomalies in LoRaWAN IoT networks.

## 📌 Architecture Overview
- **Data Engineering:** Synthesized 100,000 LoRaWAN packet records capturing physical layer metrics: RSSI (Received Signal Strength Indicator), SNR (Signal-to-Noise Ratio), Spreading Factor (SF), and Inter-Arrival Times.
- **Model Training Engine:** Implemented and benchmarked supervised models (**XGBoost**, **Random Forest**) and unsupervised anomaly detectors (**Isolation Forest**).
- **Real-Time Stream Processing:** Built a interactive Streamlit dashboard featuring live telemetry simulation, threat rate tracking, and interactive signal separability visuals.

## 🚀 Key Features
- **Live Intrusion Stream:** Real-time metrics on clean vs. malicious traffic batches with dynamic alert highlighting.
- **Feature Separability Analytics:** 3D cluster visualizations proving ground-truth physical signal separation.
- **Multi-Model Engine:** Toggle between supervised classifiers and unsupervised anomaly models on the fly.

## 🛠️ Tech Stack
- **Language:** Python 3.10+
- **Machine Learning:** XGBoost, Scikit-Learn
- **Data Processing:** Pandas, NumPy, Joblib
- **Visualization & UI:** Streamlit, Plotly Express
- **Deployment:** Streamlit Cloud

## ⚡ Quick Start (Local Setup)

1. **Clone Repository:**
   ```bash
   git clone [https://github.com/Chirantan17/lorawan-anomaly-detector.git](https://github.com/Chirantan17/lorawan-anomaly-detector.git)
   cd lorawan-anomaly-detector