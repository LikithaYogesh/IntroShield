import os
import json
import requests
import pandas as pd
from scapy.all import sniff
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt

# Configuration for SIEM (Splunk)
SPLUNK_URL = "your url"
SPLUNK_TOKEN = "your token"
INTERFACE = "eth0"  # Network interface to monitor
CONTAMINATION_RATE = 0.01  # Anomaly contamination rate for Isolation Forest

# Function to send alerts to Splunk
def send_alert_to_splunk(alert_data):
    headers = {
        "Authorization": f"Splunk {SPLUNK_TOKEN}",
        "Content-Type": "application/json"
    }
    event = {
        "event": alert_data,
        "sourcetype": "json",
        "index": "main"
    }
    response = requests.post(SPLUNK_URL, headers=headers, data=json.dumps(event), verify=False)
    if response.status_code == 200:
        print("Alert sent to Splunk successfully.")
    else:
        print(f"Failed to send alert: {response.text}")

# Function to block malicious IP using iptables
def block_ip(ip_address):
    command = f"sudo iptables -A INPUT -s {ip_address} -j DROP"
    os.system(command)
    print(f"Blocked IP: {ip_address}")

# Function for real-time packet sniffing and monitoring
def packet_callback(packet):
    if packet.haslayer("IP"):
        ip_src = packet["IP"].src
        ip_dst = packet["IP"].dst
        print(f"Packet from {ip_src} to {ip_dst}")
        
        # Check if the source IP is suspicious
        if ip_src in suspicious_ips:
            print(f"Suspicious IP detected: {ip_src}")
            send_alert_to_splunk({"message": "Suspicious IP detected", "ip_address": ip_src})
            block_ip(ip_src)

# Anomaly detection using Isolation Forest
def detect_anomalies(data):
    # Drop non-numeric columns for anomaly detection
    numeric_data = data.select_dtypes(include=['number'])  # Keep only numeric columns

    # Handle case when there are no numeric columns
    if numeric_data.empty:
        print("No numeric data available for anomaly detection.")
        return pd.DataFrame()  # Return an empty DataFrame

    model = IsolationForest(contamination=CONTAMINATION_RATE)
    model.fit(numeric_data)

    # Create a new DataFrame to hold the anomalies
    data['anomaly'] = model.predict(numeric_data)

    # Identify anomalies (1 for normal, -1 for anomalous)
    anomalies = data[data['anomaly'] == -1]

    # Save detected anomalies to CSV
    if not anomalies.empty:
        anomalies.to_csv('detected_anomalies.csv', index=False)
        print("Anomalies detected and saved to detected_anomalies.csv.")
        
    return anomalies

# Example function to visualize anomaly detection results
def visualize_anomalies(data):
    plt.scatter(data.index, data['some_feature'], c=data['anomaly'])
    plt.xlabel('Time')
    plt.ylabel('Network Feature')
    plt.title('Anomaly Detection in Network Traffic')
    plt.show()

# Initialize list of suspicious IPs (can be populated from a threat feed)
suspicious_ips = ["192.168.1.100", "10.0.0.5"]

def main():
    # Load or simulate network traffic data for anomaly detection (example CSV)
    try:
        data = pd.read_csv('network_traffic_data.csv')
        # Ensure 'time' column is converted to datetime
        if 'time' in data.columns:
            data['time'] = pd.to_datetime(data['time']).astype(int) / 10**9  # Convert to Unix timestamp
        anomalies = detect_anomalies(data)
        if not anomalies.empty:
            print("Anomalies detected:")
            print(anomalies)
            send_alert_to_splunk({"message": "Anomalies detected in network traffic", "details": anomalies.to_dict()})
    except FileNotFoundError:
        print("Network traffic data file not found, proceeding with real-time monitoring.")

    # Start sniffing network traffic
    print(f"Starting packet sniffing on {INTERFACE}...")
    sniff(iface=INTERFACE, prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
