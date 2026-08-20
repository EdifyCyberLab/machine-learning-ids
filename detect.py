import os
import time
import random
import pandas as pd
import numpy as np
import joblib

def main():
    print("=" * 60)
    print("Machine Learning Intrusion Detection System (IDS) - Live Simulation")
    print("Dataset: UNSW-NB15 Benchmark")
    print("=" * 60)

    model_filename = "ids_random_forest.pkl"
    if not os.path.exists(model_filename):
        print(f"[!] Error: Trained model '{model_filename}' not found.")
        print("Please run 'python train_ids.py' first after training your model.")
        return

    print(f"[+] Loading trained model and feature metadata from '{model_filename}'...")
    model, feature_columns = joblib.load(model_filename)
    print(f"[+] Model loaded successfully. Expecting {len(feature_columns)} encoded features.")

    print("\n[+] Starting live network traffic simulation...")
    print("[+] Press Ctrl+C to stop the simulation at any time.\n")

    try:
        for i in range(1, 11):
            time.sleep(1.2)
            
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

            if i % 3 == 0:
                flow_data['rate'] = random.uniform(20000, 80000)
                flow_data['sbytes'] = random.randint(30000, 90000)
                flow_data['state'] = 'INT'

            input_df = pd.DataFrame([flow_data])
            input_encoded = pd.get_dummies(input_df)
            input_final = input_encoded.reindex(columns=feature_columns, fill_value=0)

            prediction = model.predict(input_final)[0]
            probability = model.predict_proba(input_final)[0]

            src_ip = f"192.168.1.{random.randint(10, 200)}"
            dst_ip = f"10.0.0.{random.randint(1, 5)}"
            
            if prediction == 1:
                status_str = "🚨 [ALERT] INTRUSION DETECTED!"
                conf = probability[1] * 100
            else:
                status_str = "✅ [SAFE]   NORMAL TRAFFIC"
                conf = probability[0] * 100

            print(f"Flow #{i:02d} | Src: {src_ip} -> Dst: {dst_ip} | Proto: {flow_data['proto']} | Rate: {flow_data['rate']:.1f} | {status_str} (Conf: {conf:.1f}%)")

    except KeyboardInterrupt:
        print("\n[+] Simulation stopped by user.")

    print("\n" + "=" * 60)
    print("Simulation completed successfully!")
    print("=" * 60)

if __name__ == "__main__":
    main()
