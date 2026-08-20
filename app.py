import streamlit as st
import pandas as pd
import numpy as np
import joblib
import time
import random

st.set_page_config(
    page_title="Machine Learning IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# Custom Styling
st.markdown("""
    <style>
    .main { background-color: #0e1117; color: #ffffff; }
    .stMetric { background-color: #1a1c24; padding: 15px; border-radius: 10px; border: 1px solid #30363d; }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ Machine-Learning Network Intrusion Detection System (IDS)")
st.markdown("Real-time network traffic anomaly detection powered by **Random Forest** and the **UNSW-NB15** dataset benchmark.")

# Sidebar controls
st.sidebar.header("Control Panel")
model_path = "ids_random_forest.pkl"

@st.cache_resource
def load_ids_model():
    try:
        model, feature_columns = joblib.load(model_path)
        return model, feature_columns, True
    except Exception as e:
        return None, None, False

model, feature_columns, model_loaded = load_ids_model()

if not model_loaded:
    st.sidebar.error("⚠️ Model not found! Please run `train_ids.py` first.")
    st.warning("⚠️ Trained model `ids_random_forest.pkl` not detected. Please run `python train_ids.py` in your terminal to generate the model before running the dashboard simulation.")
else:
    st.sidebar.success("✅ Model Loaded Successfully")
    st.sidebar.info(f"Features: {len(feature_columns)}")

simulation_speed = st.sidebar.slider("Simulation Interval (seconds)", 0.5, 3.0, 1.0)
run_simulation = st.sidebar.toggle("Start Live Traffic Monitor", value=False)

# Main metrics overview
col1, col2, col3, col4 = st.columns(4)
with col1:
    total_flows_metric = st.empty()
with col2:
    normal_flows_metric = st.empty()
with col3:
    attacks_metric = st.empty()
with col4:
    threat_level_metric = st.empty()

st.markdown("---")
st.subheader("Live Network Flow Log")
log_container = st.empty()

# Initialize session state for tracking stats
if 'total_flows' not in st.session_state:
    st.session_state.total_flows = 0
    st.session_state.normal_flows = 0
    st.session_state.attack_flows = 0
    st.session_state.history = []

total_flows_metric.metric("Total Flows Analyzed", st.session_state.total_flows)
normal_flows_metric.metric("Benign Traffic", st.session_state.normal_flows)
attacks_metric.metric("Intrusions Detected", st.session_state.attack_flows)
threat_level_metric.metric("Current Threat Status", "SECURE" if st.session_state.attack_flows == 0 else "ALERT")

if run_simulation and model_loaded:
    # Generate one sample per rerun
    flow_data = {
        'dur': random.uniform(0.01, 3.0),
        'proto': random.choice(['tcp', 'udp', 'arp']),
        'service': random.choice(['-', 'http', 'dns', 'ftp']),
        'state': random.choice(['CON', 'INT', 'FIN']),
        'spkts': random.randint(2, 100),
        'dpkts': random.randint(0, 80),
        'sbytes': random.randint(200, 20000),
        'dbytes': random.randint(0, 15000),
        'rate': random.uniform(10, 10000),
        'sttl': random.choice([32, 64, 254]),
        'dttl': random.choice([0, 32, 64]),
        'sload': random.uniform(1000, 1000000),
        'dload': random.uniform(0, 500000),
        'sloss': random.randint(0, 5),
        'dloss': random.randint(0, 5),
        'sinpkt': random.uniform(0.1, 100.0),
        'dinpkt': random.uniform(0.0, 50.0),
        'sjit': random.uniform(0.0, 10.0),
        'djit': random.uniform(0.0, 10.0),
        'swin': random.choice([255, 512, 65535]),
        'stcpb': random.randint(0, 1000000),
        'dtcpb': random.randint(0, 1000000),
        'dwin': random.choice([0, 255, 65535]),
        'tcprtt': random.uniform(0.0, 0.5),
        'synack': random.uniform(0.0, 0.2),
        'ackdat': random.uniform(0.0, 0.3),
        'smean': random.randint(40, 1500),
        'dmean': random.randint(0, 1500),
        'trans_depth': 0,
        'response_body_len': 0,
        'ct_srv_src': random.randint(1, 10),
        'ct_state_ttl': random.randint(1, 5),
        'ct_dst_ltm': random.randint(1, 10),
        'ct_src_dport_ltm': random.randint(1, 5),
        'ct_dst_sport_ltm': random.randint(1, 5),
        'ct_dst_src_ltm': random.randint(1, 10),
        'is_ftp_login': 0,
        'ct_ftp_cmd': 0,
        'ct_flw_http_mthd': 0,
        'ct_src_ltm': random.randint(1, 10),
        'ct_srv_dst': random.randint(1, 10),
        'is_sm_ips_ports': 0
    }

    if random.random() < 0.3:
        flow_data['rate'] = random.uniform(30000, 90000)
        flow_data['sbytes'] = random.randint(40000, 100000)
        flow_data['state'] = 'INT'

    input_df = pd.DataFrame([flow_data])
    input_encoded = pd.get_dummies(input_df)
    input_final = input_encoded.reindex(columns=feature_columns, fill_value=0)

    prediction = model.predict(input_final)[0]
    probability = model.predict_proba(input_final)[0]

    src_ip = f"192.168.1.{random.randint(10, 200)}"
    dst_ip = f"10.0.0.{random.randint(1, 5)}"
    
    st.session_state.total_flows += 1
    if prediction == 1:
        st.session_state.attack_flows += 1
        status = "🚨 INTRUSION ALERT"
        conf = probability[1] * 100
    else:
        st.session_state.normal_flows += 1
        status = "✅ SAFE"
        conf = probability[0] * 100

    log_entry = {
        "Time": time.strftime("%H:%M:%S"),
        "Source IP": src_ip,
        "Dest IP": dst_ip,
        "Protocol": flow_data['proto'].upper(),
        "Rate": f"{flow_data['rate']:.1f}",
        "Status": status,
        "Confidence": f"{conf:.1f}%"
    }

    st.session_state.history.insert(0, log_entry)
    if len(st.session_state.history) > 15:
        st.session_state.history.pop()

    total_flows_metric.metric("Total Flows Analyzed", st.session_state.total_flows)
    normal_flows_metric.metric("Benign Traffic", st.session_state.normal_flows)
    attacks_metric.metric("Intrusions Detected", st.session_state.attack_flows)
    threat_level_metric.metric("Current Threat Status", "SECURE" if st.session_state.attack_flows == 0 else "ALERT")

    history_df = pd.DataFrame(st.session_state.history)
    log_container.dataframe(history_df, use_container_width=True)

    time.sleep(simulation_speed)
    st.rerun()
else:
    if st.session_state.history:
        history_df = pd.DataFrame(st.session_state.history)
        log_container.dataframe(history_df, use_container_width=True)
    else:
        st.info("Toggle 'Start Live Traffic Monitor' in the sidebar to begin real-time traffic simulation.")
