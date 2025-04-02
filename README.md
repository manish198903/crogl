# GitHub Security Advisory Report Generator

This script generates a comprehensive report of security vulnerabilities from the GitHub Advisory Database, categorized by severity levels (low, medium, high, critical). It also cross-references these vulnerabilities with CISA's Known Exploited Vulnerabilities (KEV) Catalog.

## Description

The script performs the following functions:

- Fetches security advisories from GitHub's Advisory Database for Python packages (pip ecosystem)
- Downloads CISA's KEV catalog for cross-referencing
- Categorizes vulnerabilities by severity level
- Generates CSV files containing detailed information about each vulnerability
- Creates a zip archive containing all CSV reports

## Prerequisites

- Python 3.x
- GitHub Personal Access Token with appropriate permissions
- Internet connection to access GitHub API and CISA's KEV database

## Required Python Packages

```bash
pip install PyGithub requests
```

## Environment Setup

Set your GitHub authentication token as an environment variable:

```bash
export GITHUB_AUTH_TOKEN='your-github-token'
```

## Usage

Run the script using:

```bash
python assessment.py
```

## Output

The script generates a `vulnerability_report.zip` file containing four CSV files:

- `low.csv`: Low severity vulnerabilities
- `medium.csv`: Medium severity vulnerabilities
- `high.csv`: High severity vulnerabilities
- `critical.csv`: Critical severity vulnerabilities

### CSV Format

Each CSV file contains the following columns:

- `KEV`: Boolean indicating if the vulnerability is in CISA's KEV catalog
- `CVE-ID`: The CVE identifier
- `GHSA-ID`: GitHub Security Advisory identifier
- `HTML-URL`: Link to the advisory on GitHub
- `SUMMARY`: Description of the vulnerability
- `TYPE`: Type of the vulnerability
- `UPDATED-AT`: Last update timestamp
- `WITHDRAWN-AT`: Withdrawal date (if applicable)

## Error Handling

The script includes error handling for:

- Failed API requests
- Missing authentication token
- JSON parsing errors
- File operations

## Data Sources

- GitHub Advisory Database: https://github.com/advisories
- CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

## License

Apache License 2.0

Copyright 2024

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
