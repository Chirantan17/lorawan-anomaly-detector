import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import joblib
import time

st.set_page_config(page_title="LoRaWAN Security Dashboard", page_icon="🛡️", layout="wide")

@st.cache_resource
def load_bundle():
    return joblib.load("models/lorawan_models_bundle.pkl")

@st.cache_data
def load_data():
    return pd.read_csv("data/phase1_lorawan_100k.csv")

try:
    bundle = load_bundle()
    dataset = load_data()
except Exception as e:
    st.error(f"Initialization error: {e}. Ensure data and model files exist by running src/generate_data.py and src/train.py.")
    st.stop()

# Sidebar Controls
st.sidebar.title("🛡️ Network Control Panel")
st.sidebar.markdown("**Phase 1 Setup:** 1 Rogue Node vs 5 Benign Nodes")

model_choice = st.sidebar.selectbox(
    "Active AI Model Engine",
    ["XGBoost (Supervised)", "Random Forest (Supervised)", "Isolation Forest (Unsupervised)"]
)

stream_speed = st.sidebar.slider("Stream Interval Delay (s)", 0.1, 2.0, 0.5)
batch_size = st.sidebar.slider("Packets per Batch", 10, 100, 25)

if "stream_idx" not in st.session_state:
    st.session_state.stream_idx = 0

if st.sidebar.button("Reset Simulation Stream"):
    st.session_state.stream_idx = 0

st.title("📡 Real-Time LoRaWAN Intrusion & Anomaly Detector")
st.caption(f"Engine: `{model_choice}` | Gateway: Star Topology (BPHC Lab)")

# Tab Navigation
tab1, tab2 = st.tabs(["⚡ Live Network Stream", "🔬 Dataset Purity & Separability Analysis"])

# Predict Function
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

# Stream Slice Logic
current_idx = st.session_state.stream_idx
stream_df = dataset.iloc[: current_idx + batch_size].copy()
processed_df = predict_batch(stream_df, model_choice)
st.session_state.stream_idx += batch_size

# TAB 1: LIVE STREAM DASHBOARD
with tab1:
    # Top KPIs
    k1, k2, k3, k4 = st.columns(4)
    total_pkts = len(processed_df)
    clean_pkts = len(processed_df[processed_df["Prediction"] == 0])
    rogue_pkts = len(processed_df[processed_df["Prediction"] == 1])
    threat_pct = (rogue_pkts / total_pkts * 100) if total_pkts > 0 else 0.0

    k1.metric("Total Packets Analyzed", total_pkts)
    k2.metric("Clean Packets", clean_pkts)
    k3.metric("Rogue Packets Flagged", rogue_pkts, delta=f"{threat_pct:.1f}% Threat Rate", delta_color="inverse")
    k4.metric("Active Attacker", "Rogue_X1" if rogue_pkts > 0 else "None Detected")

    # Visuals
    c1, c2 = st.columns([6, 4])

    with c1:
        st.subheader("📊 Signal Separation Scatter (RSSI vs SNR)")
        plot_df = processed_df.tail(500).copy()
        
        fig = px.scatter(
            plot_df, x="rssi", y="snr", color="Classification",
            color_discrete_map={"Normal Traffic": "#00CC96", "Rogue Attack": "#EF553B"},
            hover_data=["device_id", "sf", "inter_arrival_time", "fcnt"],
            labels={"rssi": "RSSI (dBm)", "snr": "SNR (dB)"}
        )
        fig.update_layout(margin=dict(l=20, r=20, t=40, b=20), height=380)
        st.plotly_chart(fig, use_container_width=True)

    with c2:
        st.subheader("🚨 Threat Distribution")
        counts = processed_df["Classification"].value_counts().reset_index()
        counts.columns = ["Traffic Type", "Count"]
        
        fig_donut = px.pie(
            counts, names="Traffic Type", values="Count", hole=0.4,
            color="Traffic Type", color_discrete_map={"Normal Traffic": "#00CC96", "Rogue Attack": "#EF553B"}
        )
        fig_donut.update_layout(margin=dict(l=20, r=20, t=40, b=20), height=380)
        st.plotly_chart(fig_donut, use_container_width=True)

    # Packet Stream Table
    st.subheader("📑 Live Gateway Packet Stream")
    recent_logs = processed_df.tail(15)[["device_id", "rssi", "snr", "sf", "inter_arrival_time", "fcnt", "Status"]].iloc[::-1]

    def highlight_rogue(val):
        return f'background-color: {"#ffdddd" if "ROGUE" in str(val) else "#ddffdd"}'

    # Updated from applymap -> map to remain compatible with pandas 2.1+
    st.dataframe(recent_logs.style.map(highlight_rogue, subset=["Status"]), use_container_width=True)

# TAB 2: DATASET PURITY & SEPARABILITY ANALYSIS
with tab2:
    st.header("🔬 Ground Truth Dataset Purity Analysis")
    st.markdown("""
    This view demonstrates the physical layer **feature separability** of the 100,000 LoRaWAN packet dataset. 
    It proves to instructors/evaluators that benign network nodes and rogue spoofing nodes exhibit distinct 
    RF signal profiles, making them mathematically identifiable.
    """)
    
    # Sample subset for fast visualization rendering
    sample_size = st.slider("Select Sample Size for Purity Plots", 1000, 10000, 3000)
    sample_df = dataset.sample(n=sample_size, random_state=42).copy()
    sample_df["Node Type"] = sample_df["is_rogue"].map({0: "Benign Node", 1: "Rogue Node (Rogue_X1)"})
    
    col_a, col_b = st.columns(2)
    
    with col_a:
        st.subheader("1. 3D Cluster Purity (RSSI vs SNR vs SF)")
        fig_3d = px.scatter_3d(
            sample_df,
            x="rssi", y="snr", z="sf",
            color="Node Type",
            symbol="Node Type",
            opacity=0.7,
            color_discrete_map={"Benign Node": "#00CC96", "Rogue Node (Rogue_X1)": "#EF553B"},
            labels={"rssi": "RSSI (dBm)", "snr": "SNR (dB)", "sf": "Spreading Factor"}
        )
        fig_3d.update_layout(margin=dict(l=0, r=0, b=0, t=30), height=450)
        st.plotly_chart(fig_3d, use_container_width=True)

    with col_b:
        st.subheader("2. Inter-Arrival Time Anomalies")
        fig_box = px.box(
            sample_df,
            x="Node Type",
            y="inter_arrival_time",
            color="Node Type",
            points="outliers",
            color_discrete_map={"Benign Node": "#00CC96", "Rogue Node (Rogue_X1)": "#EF553B"},
            labels={"inter_arrival_time": "Inter-Arrival Time (sec)"}
        )
        fig_box.update_layout(margin=dict(l=20, r=20, t=30, b=20), height=450)
        st.plotly_chart(fig_box, use_container_width=True)

# Loop stream rerun logic
if st.session_state.stream_idx < len(dataset):
    time.sleep(stream_speed)
    st.rerun()