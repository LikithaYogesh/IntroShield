Automated Threat Detection System

Overview
The Automated Threat Detection System is a network monitoring tool that analyzes network traffic in real-time to detect anomalies and suspicious activities. It leverages machine learning techniques, specifically the Isolation Forest algorithm, to identify potential threats. Detected anomalies can be sent to a SIEM (Security Information and Event Management) system like Splunk for further analysis, and suspicious IPs can be blocked using iptables.

Features
Real-time packet sniffing using Scapy.
Anomaly detection using Isolation Forest from scikit-learn.
Integration with Splunk for logging and alerting.
Automatic blocking of suspicious IP addresses.
Storage of detected anomalies in a CSV file for future reference.
Prerequisites
Before running the project, ensure you have the following installed:

Python 3.x
Pip
Required Python libraries:
scapy
pandas
requests
scikit-learn
matplotlib

You can install the required libraries using:
pip install scapy pandas requests scikit-learn matplotlib

Configuration
Splunk Configuration:

Update the SPLUNK_URL and SPLUNK_TOKEN variables in the script with your Splunk server URL and HTTP Event Collector (HEC) token.
Network Interface:

Set the INTERFACE variable to the network interface you want to monitor (e.g., eth0, wlan0).
Anomaly Contamination Rate:

Adjust the CONTAMINATION_RATE variable to define the expected proportion of outliers in the data.

