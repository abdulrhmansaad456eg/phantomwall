# PhantomWall WAF

**PhantomWall (PW)** is an educational Web Application Firewall prototype designed for teaching students about HTTP traffic inspection, attack detection, and web security fundamentals.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-Educational-orange)

## Features

- **Real-time Attack Detection**: SQL Injection, XSS, Command Injection, Path Traversal, CSRF, File Inclusion
- **Interactive Dashboard**: Live monitoring with charts and statistics
- **Multilingual Support**: English, Korean (한국어), Arabic (العربية)
- **Simulated Backend**: Safe testing environment with vulnerable endpoints
- **Comprehensive Logging**: SQLite-based persistent storage with export capabilities
- **Configurable Rules**: Adjustable sensitivity and custom rule support
- **Rate Limiting**: Automatic protection against brute force attacks
- **IP Whitelist/Blacklist**: Fine-grained access control

## Quick Start

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Installation

1. Clone or download the PhantomWall repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

### Running PhantomWall

Start the WAF dashboard and simulated backend:

```bash
python main.py
```

The application will be available at:
- **Dashboard**: http://127.0.0.1:8080
- **Simulated Backend**: http://127.0.0.1:8080/backend

### Command Line Options

```bash
python main.py --port 9000                    # Custom port
python main.py --host 0.0.0.0                 # Allow external connections
python main.py --config custom.json           # Custom config file
python main.py --debug                        # Debug mode
```

## Using PhantomWall

### Dashboard

The main dashboard provides:
- Real-time traffic statistics
- Attack distribution charts
- Recent threat events
- System health monitoring

### Testing Attacks

Navigate to the **Test WAF** page to simulate various attacks:
- SQL Injection patterns
- XSS payloads
- Command injection attempts
- Path traversal sequences

Or use the quick presets for instant testing.

### Simulated Backend Endpoints

The simulated backend provides safe targets for testing:

| Endpoint | Description |
|----------|-------------|
| `/backend/login` | Login form (SQL injection vulnerable) |
| `/backend/search` | Search endpoint (XSS vulnerable) |
| `/backend/cmd` | Command execution endpoint |
| `/backend/download` | File download (path traversal vulnerable) |
| `/backend/users` | User management API |
| `/backend/config` | Configuration exposure |

### Configuration

Settings are stored in `phantomwall.json` and include:

- **WAF Enabled**: Turn protection on/off
- **Blocking Mode**: Block threats or just log them
- **Sensitivity**: Low, Medium, or High detection level
- **Rate Limit**: Requests per minute per IP
- **Language**: Interface language (en/ko/ar)
- **IP Lists**: Whitelist and blacklist management

## Running Tests

### Automated Test Suite

Run the comprehensive detection tests:

```bash
python tests/test_waf.py
```

### Attack Simulation Demo

```bash
python tests/test_waf.py --demo
```

### Traffic Generation

Generate sample traffic for dashboard visualization:

```bash
python tests/generate_traffic.py --duration 60
```

## Project Structure

```
phantomwall/
├── core/
│   └── engine.py           # WAF core engine
├── detection/
│   └── rules.py            # Attack detection rules
├── web/
│   ├── app.py              # Flask dashboard
│   └── simulated_backend.py # Test backend
├── utils/
│   ├── i18n.py             # Multilingual support
│   ├── logger.py           # Database logging
│   └── config.py           # Configuration manager
├── locales/
│   ├── en.json             # English translations
│   ├── ko.json             # Korean translations
│   └── ar.json             # Arabic translations
├── templates/              # HTML templates
├── static/css/             # Stylesheets
├── tests/                  # Test scripts
├── main.py                 # Entry point
├── requirements.txt        # Dependencies
└── README.md              # This file
```

## Attack Detection Capabilities

| Attack Type | Patterns Detected | Severity |
|-------------|-------------------|----------|
| SQL Injection | Union-based, Error-based, Time-based, Boolean-based | Critical |
| XSS | Script tags, Event handlers, JavaScript protocols | High |
| Command Injection | Shell operators, Command chaining | Critical |
| Path Traversal | Directory traversal, Null bytes, Encoding | High |
| CSRF | Missing protection headers (configurable) | Medium |
| File Inclusion | LFI/RFI patterns, PHP wrappers | High |

## API Endpoints

### Dashboard API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Current statistics |
| `/api/events/recent` | GET | Recent security events |
| `/api/event/<id>` | GET | Event details |
| `/api/logs/export` | GET | Export logs (JSON/CSV) |
| `/api/test` | POST | Test request inspection |
| `/api/simulate/<type>` | GET | Simulate attack type |
| `/api/whitelist` | POST/DELETE | Manage whitelist |
| `/api/blacklist` | POST/DELETE | Manage blacklist |

## Educational Use

PhantomWall is designed for:
- **Students**: Learning about web security and WAF operation
- **Instructors**: Demonstrating attack patterns and defenses
- **Security Teams**: Testing WAF rule effectiveness
- **Developers**: Understanding secure coding practices

### Teaching Scenarios

1. **Introduction to WAFs**: Show how requests are intercepted and analyzed
2. **Attack Pattern Recognition**: Demonstrate common attack signatures
3. **Defense Strategies**: Configure rules and observe effectiveness
4. **Logging and Forensics**: Analyze attack timelines and sources

## Configuration Reference

Default configuration (`phantomwall.json`):

```json
{
  "enabled": true,
  "blocking_mode": true,
  "sensitivity": "medium",
  "rate_limit": 100,
  "language": "en",
  "whitelist": [],
  "blacklist": [],
  "log_retention_days": 30
}
```

## Troubleshooting

### Port Already in Use
```bash
python main.py --port 9000  # Use different port
```

### Database Locked
Stop the application and remove `phantomwall_logs.db`, then restart.

### No Events Showing
- Verify WAF is enabled in settings
- Check that requests are being sent to the backend
- Ensure logging is enabled

## Security Notice

**Important**: PhantomWall is an educational tool. While it implements real detection patterns:

- It should not be used in production environments
- Detection patterns are simplified for teaching purposes
- Always use established WAF solutions (ModSecurity, AWS WAF, Cloudflare) for real protection
- The simulated backend intentionally contains vulnerabilities for testing

## Contributing

This is an educational project. Suggestions for improvements are welcome, particularly:
- Additional attack detection patterns
- More language translations
- Enhanced visualization options
- Extended testing scenarios

## License

Educational Use License - For teaching and learning purposes only.

## Credits

Developed as an educational resource for web security training.

---

**Happy Learning And Stay Secure Thank You**
