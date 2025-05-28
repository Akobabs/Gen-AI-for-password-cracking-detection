---

# Gen-AI-for-Password-Cracking-Detection

A real-time AI-enhanced system to detect and mitigate password cracking attempts via a user-friendly web dashboard. Developed as part of an undergraduate thesis project, this prototype identifies brute force, credential stuffing, and behavioral anomalies, then simulates mitigation by blocking suspicious IPs.

---

## 🔍 Project Overview

This system demonstrates **Anomaly Detection and Mitigation** (Thesis Section 1.4), built and tested on **May 28, 2025, at 07:44 AM WAT**.

### ✨ Key Features

* **Real-Time Monitoring**: Displays system metrics, security alerts, and model predictions.
* **Threat Detection**: Uses rule-based logic to catch common attack patterns.
* **Mitigation Simulation**: Blocks IPs with high-confidence threat activity.
* **User Feedback**: Displays alerts and logs via the dashboard interface.

---

## 📁 Directory Structure

```
Gen-AI-for-password-cracking-detection/
├── app.py                      # Flask backend
├── password_defense_poc.html  # Dashboard frontend
├── data/
│   └── rockyou.txt            # Subset of RockYou dataset (1000 passwords)
├── README.md                  # Project documentation
└── venv/                      # Python virtual environment (excluded from repo)
```

---

## 🛠️ Prerequisites

* **Python** 3.7+
* **RockYou Dataset**: Place a subset (1000 passwords) as `data/rockyou.txt`.
* **OS**: Tested on Windows (`C:\Users\Akoba\Desktop\START up\Gen-AI-for-password-cracking-detection`).

---

## 🚀 Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/Akobabs/Gen-AI-for-password-cracking-detection.git
cd Gen-AI-for-password-cracking-detection
```

### 2. Prepare the Dataset

Ensure `rockyou.txt` (1000 passwords) is placed in:

```
data/rockyou.txt
```

Passwords must be:

* 2–20 characters long
* ASCII characters only

### 3. Create and Activate Virtual Environment

```bash
python -m venv venv
```

Activate the environment:

* **Windows**: `venv\Scripts\activate`
* **Linux/Mac**: `source venv/bin/activate`

### 4. Install Dependencies

```bash
pip install flask pandas numpy python-Levenshtein
```

---

## ▶️ Running the App

### 1. Start the Flask Server

```bash
python app.py
```

The app runs at [http://localhost:5000](http://localhost:5000)

> If port 5000 is unavailable, edit `app.py` to use a different port.

### 2. Access the Web Dashboard

Visit [http://localhost:5000](http://localhost:5000) to:

* View real-time status (blocked threats, detection rate, response time).
* Monitor live security events and alerts.
* Observe AI confidence levels for brute force, credential stuffing, and anomalies.

### 3. Simulate Attacks

Use the dashboard buttons to test the system:

* **Brute Force**: Rapid login failures from one IP
* **Credential Stuffing**: Multiple RockYou passwords from one IP
* **Advanced Threat**: Repetitive pattern simulation

> If threat confidence exceeds 50%, the attack IP (e.g., `192.168.1.99`) is blocked and logged.

### 4. Reset System

Click **“Reset System”** to:

* Clear logs and predictions
* Unblock all IPs
* Restart fresh monitoring

---

## 📊 Expected Behavior

| Scenario                        | Description                                                               |
| ------------------------------- | ------------------------------------------------------------------------- |
| **Initial State**               | 0 threats blocked, \~67ms response, 94.7% detection, 1.3% false positives |
| **Post Brute Force Simulation** | Confidence \~60%, HIGH threat level, IP `192.168.1.99` blocked            |
| **After Reset**                 | State returns to baseline                                                 |

---

## 🧰 Troubleshooting

* **FileNotFoundError**: Ensure `rockyou.txt` is in `data/`. Update the `txt_path` in `app.py` if needed.
* **Port Conflict**: Modify port in `app.py`, then access via new port.
* **No Notifications**: Check browser console and ensure notification div is present in the HTML file.
* **IP Not Blocked**: Blocking is simulated; local IPs (e.g., `192.168.130.253`) are not affected.

---

## ⚠️ Limitations

* **Rule-Based Only**: No ML/AI currently integrated. May miss complex attacks.
* **Simulated Blocking**: Doesn’t affect real network traffic.
* **Dataset Size**: Uses a small subset of RockYou.

---

## 🔐 Ethical Considerations

* Only anonymized, non-sensitive password data is used.
* Deployment in real environments should include ethical safeguards to prevent misuse.

---

## 🚧 Future Improvements

* Integrate ML-based threat detection (e.g., SVM, LSTM).
* Use actual firewall APIs for real IP blocking.
* Add charts and visual analytics to the dashboard.

---

## 📚 References

* **Ali, 2024**. *Advancements in Machine Learning for Cybersecurity*. *Journal of Cybersecurity Research*.
* **Malik et al., 2024**. *Ethical Considerations in AI-Driven Security Systems*. *Ethics in Technology Conference*.

---

## 📎 License

This project is for educational and research purposes only. No license is currently assigned.

---