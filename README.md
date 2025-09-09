# ThreatX AI Security Dashboard

An advanced cybersecurity threat detection system using machine learning and dataset integration.

## Features

- Real-time threat detection using NSL-KDD and CICIDS datasets
- Advanced ML models (Random Forest, Gradient Boosting, Isolation Forest)
- DoS, Probe, R2L, U2R attack detection
- UNKNOWN THREAT DETECTION (Zero-day capabilities)
- Behavioral anomaly detection
- Statistical anomaly analysis
- Threat intelligence integration
- Real-time risk assessment
- Interactive dashboard with visualizations

## Technologies Used

- Python 3
- Flask (Web Framework)
- Scikit-learn (Machine Learning)
- Chart.js (Data Visualization)
- Bootstrap 5 (Frontend Framework)
- Font Awesome (Icons)

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   ```

2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the server:
   ```bash
   python test_server.py
   ```

## Usage

1. Start the server by running `python test_server.py`
2. Access the dashboard at `http://localhost:5000`
3. Use the API endpoints for threat detection:
   - POST `/api/detect-threat` - Main threat detection endpoint
   - GET `/api/threat-statistics` - Get threat statistics
   - GET `/api/user-risk-profile/<user_id>` - Get user risk profile
   - GET `/health` - System health check

## API Endpoints

- `POST /api/detect-threat` - Submit log data for threat analysis
- `GET /api/threat-statistics` - View threat statistics dashboard
- `GET /api/user-risk-profile/<user_id>` - Get specific user's risk profile
- `GET /api/suspicious-ips` - Get list of suspicious IPs
- `GET /api/recent-threats` - Get recent threats
- `GET /api/user-profiles` - Get all user profiles
- `GET /health` - System health check

## Project Structure

```
ThreatX/
├── ai-engine/              # AI engine with ML models
│   ├── src/                # Source code
│   ├── data/               # Datasets
│   ├── models/             # Trained models
│   └── requirements.txt    # AI engine dependencies
├── test_server.py          # Main Flask server
├── README.md               # This file
└── requirements.txt        # Project dependencies
```

## Dataset Integration

This project integrates with cybersecurity datasets including:
- NSL-KDD dataset for network intrusion detection
- CICIDS dataset for modern intrusion detection

## Machine Learning Models

The system uses multiple ML models for enhanced detection:
- Random Forest Classifier
- Gradient Boosting Classifier
- Isolation Forest for anomaly detection

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- NSL-KDD dataset for providing the foundation for network intrusion detection research
- CICIDS dataset for modern intrusion detection scenarios