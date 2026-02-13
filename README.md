# 🔍 Port Scanner

Fast asynchronous port scanner built with Python's `asyncio`.

## Features

- ⚡ Async scanning (1000+ ports/sec)
- 🌐 CIDR range support (e.g. `192.168.1.0/24`)
- 🔎 Service/banner detection
- 📊 JSON/CSV output formats
- 🎨 Colorized terminal output

## Install

`bash
pip install -r requirements.txt
`

## Usage

`bash
# Scan common ports
python scanner.py 192.168.1.1

# Scan port range
python scanner.py 10.0.0.0/24 -p 1-1024

# Output as JSON
python scanner.py target.com -p 80,443,8080 -o json
`

## License

MIT