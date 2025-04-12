# IntroShield:  Automated Threat Detection System for Real-Time Network Monitoring

**IntroShield** is a powerful network monitoring tool designed to analyze network traffic in real-time and detect anomalies or suspicious activities. It uses machine learning, specifically the Isolation Forest algorithm, to identify potential threats. The system integrates seamlessly with SIEM tools like Splunk for logging and alerting and can automatically block suspicious IPs using `iptables`.  

---

## Features  

- **Real-Time Packet Sniffing:** Utilizes Scapy for monitoring network traffic in real-time.  
- **Anomaly Detection:** Leverages the Isolation Forest algorithm from scikit-learn to identify suspicious patterns.  
- **SIEM Integration:** Supports integration with Splunk for comprehensive logging and alerting.  
- **Automatic Blocking:** Blocks suspicious IP addresses using `iptables`.  
- **Data Storage:** Saves detected anomalies in a CSV file for future analysis.  

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

##Configuration

1.Splunk Configuration:
  Update the SPLUNK_URL and SPLUNK_TOKEN variables in the script with your Splunk server URL and HTTP Event Collector (HEC) token.
2. Network Interface:
   Set the INTERFACE variable to the network interface you want to monitor (e.g., eth0, wlan0).
3. Anomaly Contamination Rate:
   Adjust the CONTAMINATION_RATE variable in the script to define the expected proportion of outliers in the data.

---

## Usage

1. Start the Threat Detection System:
   Run the script using Python:


       python introsheild.py  

2. Monitor Alerts:
   View real-time logs and alerts in your configured Splunk instance.
   Anomalies are logged in the CSV file named anomalies.csv in the project directory.

3. IP Blocking:
   Suspicious IPs detected by the system will be automatically blocked using iptables.

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

---

## Disclaimer
This tool is intended for ethical and educational purposes only. Use responsibly and always ensure proper authorization before monitoring or modifying network traffic. The developers are not responsible for misuse of this tool.


