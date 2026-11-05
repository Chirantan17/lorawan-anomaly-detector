# app.py
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import joblib
import time
from pathlib import Path
from database import init_db, get_recent_alerts, get_blacklisted_devices, remove_blacklisted_device
from gateway_socket import simulate_udp_stream
from soc_copilot import generate_soc_analysis

st.set_page_config(page_title="AI Network Threat Intelligence Engine", page_icon="🛡️", layout="wide")
init_db()

FILE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = FILE_DIR.parent

MODEL_PATH = PROJECT_ROOT / "03_artifacts_and_data" / "lorawan_models_bundle.pkl"
if not MODEL_PATH.exists():
    MODEL_PATH = PROJECT_ROOT / "models" / "lorawan_models_bundle.pkl"
if not MODEL_PATH.exists():
    MODEL_PATH = FILE_DIR / "lorawan_models_bundle.pkl"

DATA_PATH = PROJECT_ROOT / "03_artifacts_and_data" / "phase1_lorawan_100k.csv"
if not DATA_PATH.exists():
    DATA_PATH = PROJECT_ROOT / "data" / "phase1_lorawan_100k.csv"
if not DATA_PATH.exists():
    DATA_PATH = FILE_DIR / "phase1_lorawan_100k.csv"

@st.cache_resource
def load_bundle():
    return joblib.load(MODEL_PATH)

@st.cache_data
def load_data():
    return pd.read_csv(DATA_PATH)

try:
    bundle = load_bundle()
    dataset = load_data()
except Exception as e:
    st.error(f"Initialization error: {e}. Ensure 03_artifacts_and_data contains your dataset and model bundle.")
    st.stop()

st.sidebar.title("🛡️ SOC Control Engine")

model_choice = st.sidebar.selectbox(
    "Active ML Classifier",
    ["XGBoost (Supervised)", "Random Forest (Supervised)", "Isolation Forest (Unsupervised)"]
)

stream_mode = st.sidebar.radio("Ingestion Source", ["Live Gateway UDP Feed", "Historical Telemetry Stream"])
batch_size = st.sidebar.slider("Packets per Evaluation Window", 10, 100, 25)

if st.sidebar.button("🚀 Trigger UDP Gateway Packet Burst"):
    simulate_udp_stream(num_packets=10)
    st.sidebar.success("Dispatched 10 UDP packets to port 9999!")

if "stream_idx" not in st.session_state:
    st.session_state.stream_idx = 0

st.title("📡 AI-Powered Real-Time Network Security & Packet Analytics Engine")
st.caption(f"Pipeline: `Python Sockets -> Async Feature Aggregator -> {model_choice} -> GenAI SOC Agent`")

tab1, tab2, tab3 = st.tabs(["⚡ Live Network Telemetry", "🤖 GenAI SOC Copilot & Alerts", "🔬 Model Separability & Purity"])

def predict_batch(batch_df, choice):
    features = bundle["feature_names"]
    X_input = batch_df[features]
    
    if "XGBoost" in choice:
        preds = bundle["xgboost"].predict(X_input)
    elif "Random Forest" in choice:
        preds = bundle["random_forest"].predict(X_input)
    else:
        raw_preds = bundle["isolation_forest"].predict(X_input)
        preds = np.array([1 if p == -1 else 0 for p in raw_preds])
        
    batch_df["Prediction"] = preds
    batch_df["Status"] = batch_df["Prediction"].map({0: "🟢 CLEAN", 1: "🚨 ROGUE ALERT"})
    batch_df["Classification"] = batch_df["Prediction"].map({0: "Normal Traffic", 1: "Rogue Attack"})
    return batch_df

current_idx = st.session_state.stream_idx
stream_df = dataset.iloc[: current_idx + batch_size].copy()
processed_df = predict_batch(stream_df, model_choice)
st.session_state.stream_idx += batch_size

with tab1:
    k1, k2, k3, k4 = st.columns(4)
    total_pkts = len(processed_df)
    clean_pkts = len(processed_df[processed_df["Prediction"] == 0])
    rogue_pkts = len(processed_df[processed_df["Prediction"] == 1])
    threat_pct = (rogue_pkts / total_pkts * 100) if total_pkts > 0 else 0.0

    k1.metric("Analyzed Stream Count", total_pkts)
    k2.metric("Verified Clean Frames", clean_pkts)
    k3.metric("Anomalies Flagged", rogue_pkts, delta=f"{threat_pct:.1f}% Threat Ratio", delta_color="inverse")
    k4.metric("Gateway Ingress", "UDP 127.0.0.1:9999", "Active")

    c1, c2 = st.columns([6, 4])
    with c1:
        st.subheader("📊 RF Feature Space (RSSI vs SNR)")
        plot_df = processed_df.tail(400).copy()
        fig = px.scatter(
            plot_df, x="rssi", y="snr", color="Classification",
            color_discrete_map={"Normal Traffic": "#00CC96", "Rogue Attack": "#EF553B"},
            hover_data=["device_id", "sf", "inter_arrival_time", "fcnt"],
            labels={"rssi": "RSSI (dBm)", "snr": "SNR (dB)"}
        )
        fig.update_layout(margin=dict(l=20, r=20, t=30, b=20), height=350)
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        st.subheader("🚨 Traffic Proportions")
        counts = processed_df["Classification"].value_counts().reset_index()
        counts.columns = ["Traffic Type", "Count"]
        fig_donut = px.pie(
            counts, names="Traffic Type", values="Count", hole=0.45,
            color="Traffic Type", color_discrete_map={"Normal Traffic": "#00CC96", "Rogue Attack": "#EF553B"}
        )
        fig_donut.update_layout(margin=dict(l=20, r=20, t=30, b=20), height=350)
        st.plotly_chart(fig_donut, use_container_width=True)

    st.subheader("📑 Stream Log Buffer")
    st.dataframe(
        processed_df.tail(10)[["device_id", "rssi", "snr", "sf", "inter_arrival_time", "fcnt", "Status"]].iloc[::-1],
        use_container_width=True
    )

with tab2:
    st.header("🤖 GenAI SOC Copilot & Autonomous Threat Remediation")
    st.caption("Automated incident investigation, root-cause diagnostics, and dynamic edge firewall generation.")

    alerts = get_recent_alerts(limit=10)
    blacklisted = get_blacklisted_devices()

    col_soc1, col_soc2 = st.columns([7, 3])
    
    with col_soc1:
        st.subheader("📋 Live Incident Investigation Feed")
        if alerts:
            for alert in alerts[:5]:
                with st.expander(f"🚨 {alert['threat_category']} — Node: `{alert['device_id']}` ({alert['severity']})", expanded=True):
                    st.write(f"**Root Cause Diagnosis:** {alert['recommendation']}")
                    st.code(f"# Dynamic Mitigation Enforcement\n{alert['recommendation']}", language="bash")
        else:
            # Fallback mock diagnostic based on latest detected anomaly in stream
            rogue_records = processed_df[processed_df["Prediction"] == 1]
            if not rogue_records.empty:
                sample_alert = rogue_records.iloc[-1].to_dict()
                diag = generate_soc_analysis(sample_alert, model_name=model_choice)
                st.info(f"**Latest Incident Flagged:** `{diag['incident_id']}` on device `{diag['device_id']}`")
                st.markdown(f"**Threat Category:** `{diag['threat_category']}` | **Severity:** `{diag['severity']}`")
                st.markdown(f"**Forensic Summary:** {diag['root_cause_summary']}")
                st.code(f"# Automated Linux iptables Drop Rule\n{diag['recommended_iptables_rule']}\n\n# LoRa MAC Gateway Enforcement\n{diag['gateway_mac_command']}", language="bash")
            else:
                st.success("No active anomalies detected in current sliding buffer.")

    with col_soc2:
        st.subheader("🚫 Quarantined Devices")
        if blacklisted:
            for item in blacklisted:
                st.warning(f"**{item['device_id']}**\nReason: {item['reason']}")
                if st.button(f"Unblock {item['device_id']}", key=f"unblock_{item['device_id']}"):
                    remove_blacklisted_device(item['device_id'])
                    st.rerun()
        else:
            st.info("No nodes currently quarantined.")

with tab3:
    st.header("🔬 Feature Distribution & Signal Separability")
    sample_df = dataset.sample(n=min(2500, len(dataset)), random_state=42).copy()
    sample_df["Node Type"] = sample_df["is_rogue"].map({0: "Benign Node", 1: "Rogue Node"})
    
    f1, f2 = st.columns(2)
    with f1:
        st.subheader("3D PHY Cluster Separation")
        fig_3d = px.scatter_3d(
            sample_df, x="rssi", y="snr", z="sf", color="Node Type",
            color_discrete_map={"Benign Node": "#00CC96", "Rogue Node": "#EF553B"}
        )
        fig_3d.update_layout(margin=dict(l=0, r=0, b=0, t=20), height=380)
        st.plotly_chart(fig_3d, use_container_width=True)
    with f2:
        st.subheader("Inter-Arrival Timing Anomalies")
        fig_box = px.box(
            sample_df, x="Node Type", y="inter_arrival_time", color="Node Type",
            color_discrete_map={"Benign Node": "#00CC96", "Rogue Node": "#EF553B"}
        )
        fig_box.update_layout(margin=dict(l=20, r=20, t=20, b=20), height=380)
        st.plotly_chart(fig_box, use_container_width=True)
