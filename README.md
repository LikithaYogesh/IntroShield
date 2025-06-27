# IntroShield:  Automated Threat Detection System for Real-Time Network Monitoring

**IntroShield** is a powerful network monitoring tool designed to analyze network traffic in real-time and detect anomalies or suspicious activities. It uses machine learning, specifically the Isolation Forest algorithm, to identify potential threats. The system integrates seamlessly with SIEM tools like Splunk for logging and alerting and can automatically block suspicious IPs using `iptables`.  

---

## Features  

- **Real-Time Packet Sniffing:** Utilizes Scapy for monitoring network traffic in real-time.  
- **Anomaly Detection:** Leverages the Isolation Forest algorithm from scikit-learn to identify suspicious patterns.  
- **SIEM Integration:** Supports integration with Splunk for comprehensive logging and alerting.  
- **Automatic Blocking:** Blocks suspicious IP addresses using `iptables`.  
- **Anomaly Logging:** Detected anomalies are saved in a CSV file (detected_anomalies.csv) for later review or audit.  

---

## Prerequisites  

Ensure you have the following installed before running the project:  

- **Python 3.x**  
- **Pip** (Python package installer)  
- **Required Python Libraries:**  
  - `scapy`  
  - `pandas`  
  - `requests`  
  - `scikit-learn`  
  - `matplotlib`  

You can install all dependencies by running:  

       pip install scapy pandas requests scikit-learn matplotlib  
---

## Configuration

1. Splunk Integration
Set the Splunk server URL and token in automated_threat_detection.py:

        SPLUNK_URL = "https://your-splunk-server:8088"
        SPLUNK_TOKEN = "your-splunk-hec-token"
   
3. Network Interface
Specify the interface to monitor (e.g., eth0, wlan0):

        INTERFACE = "eth0"
3. Anomaly Sensitivity
Define the contamination rate (proportion of expected anomalies):

        CONTAMINATION_RATE = 0.01
---

## Usage

Step 1: Run the Detection System

    python automated_threat_detection.py
    
Step 2: Monitor Alerts


Real-time alerts are visible in the terminal and sent to Splunk. Anomalies are stored in the detected_anomalies.csv file in the project root.

Step 3: Automated IP Blocking
IPs identified as suspicious are automatically blocked using:

    sudo iptables -A INPUT -s <ip_address> -j DROP

---

## Contributions

Contributions to improve IntroShield are welcome! To contribute:

1. Fork the repository.
2. Create a new branch:

       git checkout -b feature-name  
3. Commit your changes:

       git commit -m "Add new feature"  
4. Push your branch and create a pull request.

---

## License
This project is licensed under the MIT License.
© 2025 Likitha Yogesh

---

## Disclaimer
This tool is intended for ethical and educational purposes only. Use responsibly and always ensure proper authorization before monitoring or modifying network traffic. The developers are not responsible for misuse of this tool.


