# 🛡️ SOC-in-a-Box: Virtual Network Lab with Suricata IDS & EveBox

> **Tagline:** Build a complete corporate network simulation, configure a Linux Router, deploy an Intrusion Detection System (IDS), and monitor attacks with a SOC Dashboard—all inside your computer.

---

## 📖 1. Introduction

Welcome to the **SOC-in-a-Box** project.

In the real world, companies don't connect their sensitive servers directly to the internet. Instead, they put them behind a **Gateway** (Router/Firewall) that inspects traffic for hackers.

**This project recreates that exact architecture.**

You will build a "Network within a Network" using VirtualBox. You will configure a Kali Linux machine to act as a Router, forcing all traffic to pass through it. Then, you will install **Suricata** (an industry-standard IDS) to watch that traffic and **EveBox** (a web dashboard) to visualize attacks in real-time.

**What problem does this solve?**
It allows you to practice Blue Team (Defense) and Red Team (Offense) skills safely. You can attack your own server and immediately see *exactly* what the attack looks like to a security analyst.

---

## 🛠 2. Prerequisites

Before you start, ensure you have the following:

### Knowledge
- **Zero.** We explain everything.
- Basic familiarity with typing commands in a terminal helps.

### Software
- **VirtualBox** (Free virtualization software).
- **Kali Linux ISO** (The operating system we will use for all machines).

### Hardware
- A computer with at least **16GB RAM** (Ideal) or **8GB RAM** (Minimum).
- 50GB of free disk space.

---

## 🧠 3. Core Concepts (Theory)

Before typing commands, let's understand the *lingo*.

| Concept | Simple Definition | Analogy |
| :--- | :--- | :--- |
| **Virtual Machine (VM)** | A computer running inside your computer. | Like a picture-in-picture mode on your TV. |
| **Gateway** | A device that connects two different networks (e.g., your home and the internet). | The security guard at the front gate of a building. |
| **NAT (Masquerading)** | A technique that hides internal IP addresses when talking to the outside world. | The security guard receiving a package for you and handing it to you, so the delivery driver never knows your specific desk number. |
| **IDS (Suricata)** | **I**ntrusion **D**etection **S**ystem. It inspects network traffic for malicious patterns. | A security camera that screams when it sees someone picking a lock. |
| **Logs (JSON)** | Files where the computer writes down what happened. | A diary or police report. |
| **GUI Dashboard (EveBox)** | A visual website to read logs easily. | Turning a pile of police reports into a neat graph on a screen. |

---

## 🏗️ 4. System Architecture

We are building a **Gateway Architecture**.

```text
                     [ INTERNET ]
                          |
                  (VirtualBox NAT)
                          |
              +-----------------------+
              |   KALI MAIN (Gateway) | <--- WE ARE HERE
              |   Suricata & EveBox   |
              |   eth0: 10.0.2.x      |
              |   eth1: 192.168.1.1   |
              +-----------+-----------+
                          |
        -------------------------------------
        |                 |                 |
  [ Kali Server ]   [ Attacker 1 ]    [ Attacker 2 ]
   192.168.1.10      192.168.1.20      192.168.1.30
```

1.  **Traffic Flow:** The "Server" and "Attackers" have **no direct internet access**. They must send traffic to the **Gateway** (192.168.1.1).
2.  **Inspection Point:** Because all traffic *must* go through the Gateway, Suricata sits on `eth1` and sees everything.

---

## ⚙️ 5. Installation & Setup

### Phase 1: VirtualBox Hardware Config

**Do this before turning on the VMs.**

1.  **Gateway VM (Kali Main)**
    *   **Adapter 1:** "NAT" (Access to Internet).
    *   **Adapter 2:** "Internal Network". Name it: `lab-net`.

2.  **Client VMs (Server & Attackers)**
    *   **Adapter 1:** "Internal Network". Name it: `lab-net`.
    *   **Adapter 2,3,4:** Disabled.

---

### Phase 2: Gateway Configuration (Kali Main)

Turn on **Kali Main**. Open a terminal.

**Step 1: Configure the Internal Interface (eth1)**
We need to give the gateway a static IP address on the internal side.

```bash
# Set IP to 192.168.1.1 manually
sudo nmcli con add type ethernet con-name "LAN-Gate" ifname eth1 ipv4.method manual ipv4.addresses 192.168.1.1/24

# Turn the connection on
sudo nmcli con up "LAN-Gate"
```

**Step 2: Enable Routing (IP Forwarding)**
By default, Linux blocks traffic not meant for itself. We must tell it to act like a router.

```bash
# Enable forwarding in the kernel
sudo sysctl -w net.ipv4.ip_forward=1

# Make it permanent (so it survives reboot)
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
```

**Step 3: Enable NAT (Internet Access for Clients)**
This allows the internal machines to share the Gateway's internet connection.

```bash
# Tell the firewall to masquerade (hide) traffic leaving eth0
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

---

### Phase 3: Client Configuration (Server & Attackers)

Turn on your **Server VM** (and Attackers).

**Step 1: Set Static IP & Default Gateway**
Run this on the **Server VM**:

```bash
# Set IP to .10 and point Gateway to .1
sudo nmcli con mod "Wired connection 1" ipv4.addresses 192.168.1.10/24 ipv4.gateway 192.168.1.1 ipv4.dns "8.8.8.8" ipv4.method manual

# Apply changes
sudo nmcli con up "Wired connection 1"
```
*Note: For Attacker VMs, change the IP to `192.168.1.20` or `.30`.*

**Step 2: Test Connectivity**
From the Server VM, run:
```bash
ping 8.8.8.8
```
*If it replies, congratulations! You have built a functional router.*

---

### Phase 4: Setting up Suricata (The IDS)

Go back to **Kali Main (Gateway)**.

**Step 1: Install Suricata**
```bash
sudo apt update
sudo apt install suricata -y
```

**Step 2: Configure the Network Variables**
We need to tell Suricata which IP belongs to our "Crown Jewel" server so it can focus on it.

Open the config file:
```bash
sudo nano /etc/suricata/suricata.yaml
```

Find the `vars` section and change `HOME_NET`:
```yaml
vars:
  address-groups:
    # We focus specifically on the Server IP
    HOME_NET: "[192.168.1.10]"
    
    # Everything else is "External" (including attackers)
    EXTERNAL_NET: "!$HOME_NET"
```
*Save and exit (Ctrl+O, Enter, Ctrl+X).*

**Step 3: Add Custom Rules**
Let's create a rule to detect Nmap scans against our server.

```bash
sudo nano /etc/suricata/rules/server.rules
```
Paste this rule:
```text
alert tcp any any -> 192.168.1.10 any (msg:"[ALERT] Port Scan Detected against Server"; flags:S; sid:100001; rev:1;)
```

**Step 4: Load the New Rules**
Edit the main config again (`sudo nano /etc/suricata/suricata.yaml`). Scroll to `rule-files:` and add your new file:
```yaml
rule-files:
  - suricata.rules
  - server.rules  # <--- Add this line
```

**Step 5: Start Suricata**
We bind it to `eth1` (Internal) to see the raw traffic.
```bash
sudo pkill suricata
sudo suricata -i eth1 -D
```

---

### Phase 5: Visualizing with EveBox (The SOC Dashboard)

Reading raw text logs is hard. EveBox makes it look like a professional SOC.

**Step 1: Install EveBox**
On **Kali Main**:
```bash
sudo apt install evebox -y
```

**Step 2: Run EveBox Server**
This command connects EveBox to the logs generated by Suricata.
```bash
sudo evebox server \
  --input /var/log/suricata/eve.json \
  --database sqlite \
  --host 0.0.0.0 \
  --port 5636 \
  --no-auth \
  --no-tls
```

**Step 3: Open the Dashboard**
Open Firefox on Kali Main and visit:
👉 **http://localhost:5636**

---

## 🎮 6. Usage Guide (Running a Simulation)

Now that everything is running, let's simulate a cyber attack.

1.  **Check the Dashboard:** Ensure EveBox is open on **Kali Main**.
2.  **Launch Attack:**
    *   Go to **Attacker VM** (192.168.1.20).
    *   Run a port scan against the server:
        ```bash
        nmap -sS 192.168.1.10
        ```
3.  **Watch the Dashboard:**
    *   Look at EveBox on Kali Main.
    *   You will see alerts pop up: `[ALERT] Port Scan Detected against Server`.
    *   You will see the Source IP (Attacker) and Destination IP (Server).

---

## 🔍 7. Internal Working (Deep Dive)

**How does the packet flow?**

1.  **Origin:** The Attacker sends a packet to `192.168.1.10`.
2.  **Switching:** Since they are on the same virtual network (`lab-net`), the packet travels to the Server.
3.  **Monitoring:** Suricata is listening on `eth1` of the Gateway, which is plugged into the same virtual switch. It uses "promiscuous mode" to make a copy of that packet.
4.  **Analysis:** Suricata compares the packet against `server.rules`. It matches the "SYN flag" rule we created.
5.  **Logging:** Suricata writes the alert details into `/var/log/suricata/eve.json` in JSON format.
6.  **Visualization:** EveBox constantly watches `eve.json`. When a new line is added, it parses the JSON and updates the web graph.

---

## 🔧 8. Troubleshooting

**"I can't ping 8.8.8.8 from the Server."**
*   Check Gateway: Run `cat /proc/sys/net/ipv4/ip_forward`. It must be `1`.
*   Check Gateway: Run `sudo iptables -t nat -L`. You must see a `MASQUERADE` rule.
*   Check Server: Run `route -n`. The Gateway must be `192.168.1.1`.

**"EveBox isn't showing alerts."**
*   Did you restart Suricata after adding rules? (`sudo pkill suricata && sudo suricata -i eth1 -D`)
*   Is the attack actually hitting the server IP?
*   Refresh the EveBox browser tab.

---

## 🎓 9. Learning Outcomes

By completing this project, you have learned:
1.  **Network Engineering:** Configuring Static IPs, NAT, and Linux Routing tables.
2.  **IDS Tuning:** Understanding `HOME_NET` and writing custom Snort/Suricata signatures.
3.  **SOC Operations:** Using a SIEM-like tool (EveBox) to monitor assets.
4.  **Log Analysis:** Understanding the structure of `eve.json`.

---

## 🔮 10. Future Improvements

*   **Block Traffic:** Change Suricata to "IPS Mode" (Intrusion Prevention) to actually *drop* the malicious packets.
*   **Log Forwarding:** Send these logs to ElasticSearch (ELK Stack) for long-term storage.
*   **More Rules:** Download the "Emerging Threats" rule set for real-world virus detection.

---

## 📚 11. References

*   [Suricata Documentation](https://suricata.io/documentation/)
*   [EveBox Documentation](https://evebox.org/)
*   [VirtualBox Networking Modes](https://www.virtualbox.org/manual/ch06.html)
---
