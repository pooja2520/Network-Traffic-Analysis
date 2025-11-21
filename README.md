**Network Traffic Analysis (Kali Linux, Wireshark, tcpdump, Snort IDS)**

This project demonstrates complete Network Traffic Analysis (NTA) using Kali Linux.
It includes packet capture, protocol analysis, and intrusion detection using:

tcpdump

Wireshark

Snort IDS

The goal is to capture ICMP traffic, analyze it visually, write a custom Snort rule, and generate real-time alerts. This project is structured like a professional cybersecurity portfolio piece.

📁 Project Structure (Detailed Explanation)
Network-Traffic-Analysis/
│── README.md
│── captures/
│    └── traffic.pcap
│── snort-rules/
│    └── icmp-alert.rules
│── alerts/
│    └── alert.fast
│── screenshots/

✔ README.md

Explains the entire project:

Tools used

Commands executed

Folder structure

Findings and screenshots

📂 captures/

Contains raw packet capture files created using tcpdump.

Upload files such as:

traffic.pcap → captured ICMP echo request/reply packets

This file is later analyzed in Wireshark.

📂 snort-rules/

Contains custom Snort IDS detection rules.

You should upload:

icmp-alert.rules

Example rule:

alert icmp any any -> any any (
    msg:"ICMP Ping Detected";
    sid:10001;
    rev:1;
)


This rule generates alerts whenever ICMP traffic is detected on the monitored interface.

📂 alerts/

Contains Snort alert logs generated during real-time monitoring.

Upload:

alert.fast

snort_output.txt (optional)

These files show that IDS alerts were triggered by your ICMP traffic.

📂 screenshots/

Contains all screenshots used for evidence of your practical work.

Examples:

wireshark-start.png

wireshark-icmp.png

tcpdump-output.png

snort-running.png

alert-file.png

Screenshots prove you performed the analysis yourself — important for academic or internship evaluation.

🛠 Tools Used
Tool	Purpose
tcpdump	Command-line packet capture
Wireshark	Deep packet inspection & visualization
Snort 3 IDS	Real-time detection of suspicious traffic
Kali Linux	Security testing OS
VirtualBox	Virtual environment
Metasploitable 2	Target machine used to generate traffic
🔍 1. Environment Setup & Host Discovery

Before capturing traffic, confirm that the target is reachable.

✔ Ping Command
ping -c 4 192.168.1.107


Expected result:

ICMP echo-reply is received

Confirms both VMs are communicating

Screenshot saved in:

screenshots/ping-test.png

📡 2. Packet Capture using tcpdump

Command used to capture traffic:

sudo tcpdump -i eth1 -w captures/traffic.pcap


Steps performed:

Start tcpdump listening on interface eth1

Generate ICMP traffic from Metasploitable2

Capture packets

Save them to traffic.pcap

Screenshot:

screenshots/tcpdump-output.png

🧪 3. Wireshark Traffic Analysis

Open captured file:

wireshark captures/traffic.pcap


Analysis included:

Identification of ICMP Echo Request

ICMP Echo Reply

TTL values

IP headers

Round trip times

Screenshots:

wireshark-start.png

wireshark-icmp.png

This demonstrates visual traffic inspection.

🚨 4. Snort IDS Setup & Rule Creation

Custom rule stored in:

snort-rules/icmp-alert.rules


Rule:

alert icmp any any -> any any (
    msg:"ICMP Ping Detected";
    sid:10001;
    rev:1;
)


Snort run command:

sudo snort -c /etc/snort/snort.lua -R snort-rules/icmp-alert.rules -i eth1 -A alert_fast


Snort monitors real-time traffic on interface eth1.

⚠ 5. Snort Alert Generation

When ICMP ping traffic was sent, Snort generated alerts.

Alert file saved as:

alerts/alert.fast


Example alert:

[**] ICMP Ping Detected [**]


Screenshot:

snort-alert.png

📝 6. Summary of Findings

This project demonstrates:

✔ Observed Network Behaviors

Continuous ICMP Echo Requests from Metasploitable2

Echo Replies from Kali Linux

Normal network traffic patterns

✔ IDS Detection Capabilities

Snort successfully detected ICMP-based communication

Custom rule triggered alerts for each ping

Real-time monitoring was validated

🛡 7. Recommendations

To improve network security:

Restrict ICMP where unnecessary

Use firewall rules (UFW/iptables)

Enable IDS/IPS for monitoring

Log all external connections

Monitor unusual traffic spikes

Segment networks to reduce attack surface

🎯 Conclusion

This Network Traffic Analysis project demonstrates practical cybersecurity skills:

Packet sniffing

Protocol analysis

Rule-based detection

IDS alerting

Documentation and evidence collection
