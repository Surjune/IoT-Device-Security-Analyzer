
# 🔐 IoT Device Security Analyzer

An IoT security analysis system that automatically discovers devices on a local Wi-Fi/LAN network, analyzes them for common security vulnerabilities, assigns risk scores, and provides actionable security recommendations through a clean dashboard.

---

## 🚀 Features

- Automatic discovery of IoT devices on local networks  
- Detection of open ports and insecure services  
- Identification of weak or default credentials  
- Device-wise risk scoring and prioritization  
- Continuous monitoring for suspicious behavior  
- Admin alerts with clear security recommendations  
- Simple and easy-to-understand dashboard  

---

## 🛠️ Tech Stack

- **Backend:** Python, FastAPI  
- **Network Scanning:** Nmap, Scapy  
- **Database:** PostgreSQL  
- **Frontend:** HTML, CSS, JavaScript / React  
- **Scheduling & Monitoring:** APScheduler  
- **Deployment:** Docker (optional)  

---

## 📋 Prerequisites

- Python 3.10 or higher  
- Nmap installed on the system  
- PostgreSQL (local or cloud)  
- (Optional) Docker & Docker Compose  

---

## 🖥️ Local Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/iot-device-security-analyzer.git
cd iot-device-security-analyzer

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Update database credentials and settings

# Start the FastAPI server
uvicorn main:app --reload
```
---

## ⚙️ How It Works
- Scans the local network to discover connected devices  
- Identifies IoT devices using fingerprinting techniques  
- Analyzes security issues such as open ports and weak configurations  
- Assigns a risk score to each device  
- Continuously monitors device behavior and sends alerts  

---

## 📁 Folder Structure
```text
IoT Device Security Analyzer/
│
├── .env.example            # Environment variable template
├── .firebaserc             # Firebase project configuration
├── firebase.json           # Firebase hosting settings
├── manifest.txt            # Project dependencies / metadata
├── README.md               # Project documentation
├── .gitignore              # Files & folders ignored by Git
│
├── .firebase/              # Firebase hosting cache (auto-generated)
│
├── .vscode/                # VS Code workspace settings
│   └── settings.json
│
├── backend/                # Backend (FastAPI)
│   ├── app.py              # Main FastAPI application
│   └── __pycache__/        # Python cache files
│
├── frontend/               # Frontend (HTML, CSS, JavaScript)
│   ├── index.html          # Main UI page
│   └── assets/
│       ├── app.js          # Frontend logic
│       └── styles.css      # Styling
│
├── data/                   # Application data
│   └── iot_data.db         # SQLite database
│
└── logs/                   # Application logs

```


## 🌐 Deployment
### Option 1: Docker (Recommended)
docker-compose up --build

### Option 2: Cloud Deployment

Deploy the backend on Render, Railway, or AWS

Use a managed PostgreSQL database

Expose the API securely using HTTPS

## 🔮 Future Enhancements

AI-based anomaly detection

Mobile notifications

Cloud-based monitoring dashboard

CVE intelligence integration

## 📄 License

This project is developed for educational, research, and hackathon purposes.
