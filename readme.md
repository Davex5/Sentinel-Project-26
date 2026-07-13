🛡️Sentinel Login Anomaly Detection System

Project Overview

Sentinel Login Anomaly Detection System is a cybersecurity application designed to monitor user login activities and detect suspicious login behavior. The system uses machine learning techniques to identify abnormal login patterns that may indicate unauthorized access attempts.

The application records login activities such as login time, IP address, device information, and user behavior. These activities are analyzed to detect possible anomalies and generate security alerts.

Features

* User authentication and secure login system
* Password hashing for user security
* Login activity monitoring
* Detection of unusual login behavior
* Machine learning-based anomaly detection
* Storage of login records and anomaly reports
* Security alert generation
* User activity tracking dashboard

Technologies Used

Frontend

* HTML
* CSS
* JavaScript

Backend

* Python
* Flask Framework

Database

* SQLite / SQL Database

Machine Learning

* Scikit-learn
* Anomaly detection algorithms

Security Tools

* Password hashing
* User session management
* Login monitoring

System Requirements

Before running the project, ensure you have:

* Python 3.x installed
* Flask installed
* Required Python libraries installed

Installation Guide

1. Clone or download the project.
2. Open the project folder.
3. Install the required dependencies:

pip install -r requirements.txt

4. Run the application:

python app.py

5. Open your browser and visit:

http://127.0.0.1:5000

Project Structure

Sentinel-Login-Anomaly-Detection/
│
├── app.py
├── database.py
├── requirements.txt
│
├── templates/
│   ├── login.html
│   ├── dashboard.html
│
├── static/
│   ├── style.css
│   ├── script.js
│
└── README.md

How The System Works

1. A user logs into the system.
2. The system records login details.
3. User behavior data is analyzed.
4. The machine learning model checks for unusual patterns.
5. Suspicious activities are flagged as anomalies.
6. Security administrators can review detected threats.

Future Improvements

* Real-time threat notifications
* Integration with SIEM platforms
* More advanced machine learning models
* Multi-factor authentication support
* Cloud deployment

Author

Lasisi David Adebayo

Department of Cybersecurity
Caleb University
:::

You can save this file as README.md inside your project folder.
