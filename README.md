# SSRFBlind 🔍
A powerful and automated SSRF (Server-Side Request Forgery) blind validation tool designed for penetration testers and security researchers. This tool streamlines the process of testing for SSRF vulnerabilities through multiple input methods and intelligent parameter detection.

![](https://github.com/Mr-r00t11/SSRFBlind/blob/main/img/SSRFBlind.png?raw=true)

## 🚀 Features
- **🔧 Multiple Input Methods**: Support for Burp Suite files, single URLs, and URL lists
- **🎯 Smart Parameter Detection**: Automatically identifies injectable parameters
- **📊 Batch Processing**: Test multiple targets efficiently with bulk operations
- **⚡ Customizable Injection**: Target specific parameters or test all detected ones
- **🛡️ Safe Testing**: Configurable delays and timeout handling

## 📦 Installation
### Prerequisites
- Python 3.8 or higher
- pip package manager

### Dependencies
```bash
pip install requests colorama urllib3
```

### Clone Repository
```bash
git clone [https://github.com/yourusername/blind-ssrf-hunter.git](https://github.com/Mr-r00t11/SSRFBlind)
cd SSRFBlind
```

## 🎯 Usage
### Basic Syntax
```bash
python3 SSRFBlind.py -c YOUR_CALLBACK_DOMAIN [INPUT_OPTION]
```

### Input Options
#### 1. Single Burp Suite File
```bash
python3 SSRFBlind.py -r request.txt -c your-callback.net
```
#### 2. Single URL
```bash
python3 SSRFBlind.py -u "https://api.example.com/webhook?url=test" -c your-callback.net
```
#### 3. URL List File
```bash
python3 SSRFBlind.py -l urls.txt -c your-callback.net
```

### Advanced Options
#### Target Specific Parameters
```bash
# Single parameter
python3 SSRFBlind.py -l urls.txt -c your-callback.net -p url

# Multiple parameters
python3 SSRFBlind.pyy -l urls.txt -c your-callback.net -p url,redirect,endpoint

# Multiple -p flags
python3 SSRFBlind.py -l urls.txt -c your-callback.net -p url -p redirect
```

#### HTTP Method and Data
```bash
# POST request with data
python3 SSRFBlind.py -u "https://example.com/api" -c your-callback.net -m POST -d "url=test&action=process"

# Custom headers
python3 SSRFBlind.py -u "https://example.com/api" -c your-callback.net --headers "Authorization: Bearer token" --headers "Content-Type: application/json"
```

#### Rate Limiting Control
```bash
# Add delay between requests
python3 SSRFBlind.py -l urls.txt -c your-callback.net --delay 2
```

## 📁 File Formats
### Burp Suite Request File
Save your request from Burp Suite as a text file:
```bash
POST /api/webhook HTTP/1.1
Host: api.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 27

url=https://internal&token=abc
```

### URL List File (`urls.txt`)
```bash
https://api.example.com/webhook?url=test&token=abc
https://example.com/api/redirect?target=internal
# Comments are supported
https://app.test.com/processor?endpoint=local&callback=internal
```

**Happy Hunting!** 🔍
_Remember: With great power comes great responsibility. Always test ethically._
