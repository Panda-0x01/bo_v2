# 🧠 API Abuse Detection Dashboard

A lightweight simulation-based **API Abuse Detection Dashboard** built using **Python (Backend)** and **HTML, CSS, JavaScript (Frontend)**.  
This project detects, monitors, and visualizes potential **API abuse patterns** such as abnormal request rates, malformed payloads, and unauthorized access — all simulated for testing and demonstration.

---

## 🚀 Features

### 🔍 Detection Simulation
- Simulates real-world API abuse scenarios such as:
  - **Rate Limiting Violations**
  - **Malformed JSON Requests**
  - **Unauthorized Token Access**
  - **Suspicious IP Activities**
- Backend generates fake logs to mimic real detection results for visualization.

### 🧪 API Generation
- One-click **“Generate Demo API”** button creates a random API endpoint.
- The system continuously monitors this endpoint and simulates request traffic.
- Helps visualize abuse detection in real-time through charts and logs.

### 🌐 Add Real APIs
- Option to **add your own real API** for monitoring.
- System tracks request frequency, response time, and abnormal usage patterns.

### 📊 Dashboard Visualization
- Interactive dashboard built with **HTML, CSS, JS** showing:
  - Live abuse detection alerts
  - Request frequency graphs
  - Error rate trends
  - Status summaries for APIs

### ⚙️ Tech Stack
**Frontend:**
- HTML5  
- CSS3  
- JavaScript (Vanilla)  
- Chart.js (for data visualization)

**Backend:**
- Python (Flask)  
- Simulated detection engine 
- JSON-based data handling

---

## 🧩 How It Works

1. **Backend (Python/Flask)**
   - Simulates API traffic and randomly generates abuse patterns.
   - Provides REST endpoints for:
     - `/generate_api` → Create demo API
     - `/monitor_api` → Simulate and fetch monitoring data
     - `/add_real_api` → Register external API for observation
     - `/get_logs` → Retrieve abuse log data for dashboard display

2. **Frontend (HTML/CSS/JS)**
   - Connects to backend endpoints using Fetch API.
   - Displays data visually using **Chart.js** graphs and real-time alerts.

3. **Simulation Flow**
   - User clicks **“Generate Demo API”** → Backend creates a fake API.
   - Backend begins simulating requests and detections.
   - Frontend dashboard updates in real-time.

---

## ⚡ Installation & Usage

### 1️⃣ Clone the Repository

git clone https://github.com/Panda-0x01/bo_v2.git <br>
cd api-abuse-detection

### 2️⃣ Install Dependencies
`pip install flask`

### 3️⃣ Run the Backend

`cd backend`  <br>
`python app.py`


### 4️⃣ Open the Dashboard

Open frontend/index.html in your browser.
It connects automatically to the backend running on http://localhost:5000.

📈 Future Improvements

- Integrate real-time database (MongoDB or SQLite)

- Add ML-based anomaly detection

- Enable user authentication for secure API management

- Deploy to cloud platforms
