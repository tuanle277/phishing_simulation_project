# Phishing Simulator

A simple educational phishing simulator for cybersecurity awareness training.

## Overview

This tool creates a fake login page that mimics popular websites to demonstrate how phishing attacks work. It captures submitted credentials and user information for educational purposes only.

## ⚠️ DISCLAIMER

**FOR EDUCATIONAL PURPOSES ONLY**

This tool is designed strictly for cybersecurity education and awareness training. Using this tool to collect real credentials without explicit consent is illegal and unethical. The authors assume no liability for misuse of this software.

## Features

- Realistic login page template
- Credential capture (username/password)
- User metadata collection (IP, browser, OS)
- Geolocation tracking (when available)
- Session tracking
- Detailed logging

## Requirements

- Python 3.6+
- Flask
- user-agents
- geoip2

## Installation

1. Clone the repository

```bash
git clone https://github.com/letuanminh2707/phishing-simulator.git
```

2. Install the required dependencies

```bash
pip install -r requirements.txt
```

3. Run the application

```bash
python app.py
```

## Usage

1. Access the fake login page at http://127.0.0.1:5000/
2. Enter your credentials and submit
3. View captured data in the console
