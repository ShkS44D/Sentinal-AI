# 🛡️ Sentinel AI | Network Intrusion Detection System (IDS)

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B.svg)
![Scikit-Learn](https://img.shields.io/badge/Machine%20Learning-Scikit--Learn-F7931E.svg)
![Security](https://img.shields.io/badge/Security-Network%20Analysis-success.svg)

**Sentinel AI** is a high-performance, machine-learning-driven security command center designed to monitor network traffic and identify anomalies in real-time.

Built for Security Operations Centers (SOC) and network administrators, it leverages a highly tuned **Random Forest classification model** to achieve near-perfect accuracy in distinguishing between normal, benign traffic and potential network breaches, such as DDoS attacks or port scanning.

## 🚀 Key Features

* **AI-Powered Threat Detection:** Utilizes a trained Random Forest model with an outstanding **99.8% precision** rate to accurately identify malicious network patterns.
* **Real-Time SOC Dashboard:** A professional "Command Center" interface built with **Streamlit** for live monitoring of system load, active network sensors, and mitigated threats.
* **Live Threat Analysis & Triage:** Simulate or verify incoming network packets against the AI engine to receive instant "Normal" or "Anomaly" classifications backed by confidence scores.
* **Explainable AI (XAI) & Deep Analytics:** Visualizes feature importance (e.g., `src_bytes`, `dst_bytes`, connection duration) using **Plotly** to transparently explain the AI's decision-making process to security analysts.

## 🧪 Tech Stack

* **Backend & Logic:** Python
* **Machine Learning:** Scikit-learn, Pandas, NumPy
* **Frontend UI:** Streamlit
* **Data Visualization:** Plotly Express
* **Security Focus:** Network Traffic Analysis, Anomaly Detection, Intrusion Detection Systems (IDS)

## 📋 Prerequisites

Before installing Sentinel AI, ensure your system has:

* **Python 3.8+**
* A package manager like `pip`
* Git (optional, for cloning)

## 🛠️ Installation & Setup

It is highly recommended to use a virtual environment to avoid dependency conflicts.

**1. Clone the Repository**

```bash
git clone https://github.com/ShkS44D/Sentinal-AI.git
cd Sentinel-AI
```

**2. Create & Activate a Virtual Environment**

Windows:

```powershell
python -m venv venv
.\venv\Scripts\activate
```

Mac/Linux:

```bash
python3 -m venv venv
source venv/bin/activate
```

**3. Install Dependencies**

```bash
pip install -r requirements.txt
```

## 💻 Usage

**1. Start the Command Center**

With your virtual environment activated, launch the Streamlit dashboard:

```bash
streamlit run app.py
```

**2. Analyze Traffic**

* Your default web browser will automatically open to `http://localhost:8501`.
* Navigate the sidebar to view the dashboard, run live network packet simulations, or explore the model's feature importance charts.

## 📂 Project Structure

Ensure your directory is organized exactly as follows so the Streamlit application can locate the necessary ML artifacts:

```text
Sentinel-AI/
│
├── app.py                 # Main Streamlit command center application
├── requirements.txt       # Project dependencies
└── models/                # Directory for ML artifacts and encoders
    ├── RandomForest_model.pkl
    ├── scaler.pkl
    ├── label_encoders.pkl
    ├── feature_names.pkl
    └── validation_with_labels.csv
```

## 📊 Model Performance

The underlying Random Forest model analyzes key network indicators such as source bytes, destination bytes, and connection duration. Sudden spikes or irregular ratios in these specific features act as strong indicators of DoS (Denial of Service) or reconnaissance patterns, which the model flags with high confidence, minimizing false positives.

## 👨‍💻 Author

**Muhammad Saad Ahmed**

* **Focus:** Cybersecurity, Offensive Security, Penetration Testing, & Bug Bounty Hunting.
* **Academic Background:** B.S. Cyber Security, CASE Sir Syed Institute of Technology, Islamabad.
* **LinkedIn:** [S44D](https://www.linkedin.com/in/shsaadahmed/)
