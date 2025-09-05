# InsightLog

InsightLog is a Python script for extracting and analyzing data from server log files (Nginx, Apache2, and Auth logs). It provides tools to filter, parse, and analyze common server log formats.

## Features

- Filter log files by date, IP, or custom patterns
- Extract web requests and authentication attempts from logs
- Analyze logs from Nginx, Apache2, and system Auth logs

## Installation

1. Clone this repository:
   ```bash
    git clone https://github.com/dennisasare1978-ops/InsightLog-Project_4_Group_D.git
    cd InsightLog-Project_4_Group_D
   ```
2. (Optional) Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install requirements:
   ```bash
   pip3 install -r requirements.txt
   ```

## Quickstart

```bash
# optional: create venv
python3 -m venv .venv && source .venv/bin/activate

# install dependencies
pip install -r requirements.txt

# run tests
python -m pytest -q
```

## Usage Example (as a Python module)
```python
from insightlog.lib import InsightLogAnalyzer

analyzer = InsightLogAnalyzer('nginx', filepath='logs-samples/nginx1.sample')
analyzer.add_filter('192.10.1.1')
requests = analyzer.get_requests()
print(requests)
```

## Command Line Usage

You can also run the analyzer as a script from the project root:

```bash
python3 main.py --service nginx --logfile logs-samples/nginx1.sample --filter 192.10.1.1
```

More examples:

- Analyze Apache2 logs for a specific IP:
  ```bash
  python3 main.py --service apache2 --logfile logs-samples/apache1.sample --filter 127.0.1.1
  ```

- Analyze Auth logs for a specific string:
  ```bash
  python3 main.py --service auth --logfile logs-samples/auth.sample --filter root
  ```

- Analyze all Nginx log entries (no filter):
  ```bash
  python3 main.py --service nginx --logfile logs-samples/nginx1.sample
  ```

## Known Bugs

See [KNOWN_BUGS.md](KNOWN_BUGS.md) for a list of current bugs and how to replicate them.

## Planned Features

See [ROADMAP.md](ROADMAP.md) for planned features and improvements.

## What we changed

- Fixed error handling for empty input and missing files (explicit exceptions).
- Standardized web request output keys and added validation through tests.
- Improved filter functions (better error messages, fixed index handling).
- Added edge case tests for file parsing and malformed inputs.
- Clarified usage in README for team’s fork.

## Running Tests

We use `pytest` for testing. To run the tests:
```bash
pip3 install pytest
python3 -m pytest
```

## License

This repository is provided under the Apache-2.0 License. See [LICENSE](LICENSE) for details.