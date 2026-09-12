# Dynamic Bandwidth Allocation

A small Flask-based dashboard and script for measuring and experimenting with dynamic bandwidth allocation using Speedtest and Scapy-based network measurements.

## Features
- Web dashboard to visualize measurements (runs on localhost:5000)
- Uses speedtest-cli to measure throughput
- Uses Scapy for packet-level probing (may require root privileges)

## Requirements
- Python 3.8+
- Root/Administrator privileges for Scapy operations (raw sockets)
- Internet access for speed tests

Main Python dependencies:
- flask
- scapy
- speedtest-cli

(Prefer installing via a requirements file: `requirements.txt`)

## Quick setup (local)
1. Clone the repo
   ```bash
   git clone https://github.com/chaudharykeshavraj/dynamic-allocation.git
   cd dynamic-allocation
   ```

2. Create and activate a virtual environment
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install dependencies
   - If a requirements file exists:
     ```bash
     pip install -r requirements.txt
     ```
   - Otherwise:
     ```bash
     pip install flask scapy speedtest-cli
     ```

## Run (development)
Scapy may require root access for packet capture/send. Use sudo when necessary.

```bash
# If you used a virtualenv and need root for Scapy:
sudo .venv/bin/python main.py
```

The dashboard is available at: http://localhost:5000

Notes:
- Running with sudo will run the Python process as root — be careful with untrusted code or files.
- If you only need speedtest-based throughput (no Scapy), you can run without sudo.

## Configuration
- If the project exposes any configuration (e.g., port, measurement interval), place it in a config file or environment variables. Add documentation here if you add config options.

## Troubleshooting
- PermissionError / socket errors: Ensure you run with sufficient privileges for Scapy (root on Linux/macOS, Administrator on Windows).
- No internet / speedtest failures: Confirm outbound connectivity and DNS resolution.
- Port conflict on 5000: Either stop the process using that port or set the Flask port via environment variable or code change.

## Development / Contributing
- Add tests and a CI workflow for automated checks.
- Consider adding a `requirements.txt` (pip freeze > requirements.txt) to lock dependencies.
- If you change Scapy code or add raw socket logic, document required privileges and safety precautions.

## Deployment suggestions
- For production usage, run the Flask app behind a WSGI server (gunicorn) and reverse-proxy with nginx.
- Consider running measurement tasks as a separate service with limited privileges and communicating results to the dashboard over an internal API.

## License
Add a LICENSE file to this repository (for example, MIT) to make the intended license explicit.

## Author / Contact
Repository: chaudharykeshavraj/dynamic-allocation
For questions or improvements, open an issue or a pull request in this repo.
