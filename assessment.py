from github import Github
from github import Auth
from github import GithubException
import requests
import json
import csv
import zipfile
import os


KEV_URI = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CSV_HEADER_ROW = [
  "KEV",
  "CVE-ID",
  "GHSA-ID",
  "HTML-URL",
  "SUMMARY",
  "TYPE",
  "UPDATED-AT",
  "WITHDRAWN-AT"
]

LOW_VULNERABILITY_FILENAME = "low.csv"
MEDIUM_VULNERABILITY_FILENAME = "medium.csv"
HIGH_VULNERABILITY_FILENAME = "high.csv"
CRITICAL_VULNERABILITY_FILENAME = "critical.csv"

LOW_VULNERABILITY_ID = "low"
MEDIUM_VULNERABILITY_ID = "medium"
HIGH_VULNERABILITY_ID = "high"
CRITICAL_VULNERABILITY_ID = "critical"

ADVISORY_ECOSYSTEM = "pip"

def get_json_data(url:str) -> dict | list | None:
  """
  Retrieves JSON data from a specified URL.

  Args:
    url: The URL to fetch JSON data from.

  Returns:
    A Python dictionary or list representing the JSON data, or None if an error occurs.
  """
  try:
    response = requests.get(url)
    response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
    return response.json()
  except requests.exceptions.RequestException as e:
    print(f"Request failed: {e}")
    return None
  except json.JSONDecodeError as e:
      print(f"JSON decode failed: {e}")
      return None


def get_github_instance(githubauth_token:str) -> Github:
  """
  Creates a Github instance using the provided authentication token.

  Args:
    auth_token: The authentication token for the Github API.

  Returns:
    A Github instance.
  """
  auth = Auth.Token(githubauth_token)
  github = Github(auth=auth)
  return github


def get_global_advisories(github:Github) -> list:
  """
  Retrieves global advisories from the Github instance.

  Args:
    github: The Github instance.

  Returns:
    A list of global advisories.
  """
  advisories = github.get_global_advisories(ecosystem=ADVISORY_ECOSYSTEM)
  return advisories


def get_kev_cve_ids():
  """
  Retrieves KEV CVE IDs from the CISA website.

  Returns:
    A set of KEV CVE IDs.
  """
  data = get_json_data(KEV_URI)
  kev_cve_ids = set()

  if data:
    for vulnerabilities in data['vulnerabilities']:
      kev_cve_ids.add(vulnerabilities['cveID'])
  else:
    raise RuntimeError("Failed to retrieve KEV data from uri: " + KEV_URI)
    
  return kev_cve_ids

def generate_vulnerability_report(github_auth_token:str) -> None:
  """
  Generates a vulnerability report which is a zip archive containing 4 csv files
    - low.csv
    - medium.csv
    - high.csv
    - critical.csv  

  Each of these files contains a list of advisories that are associated with the
  specified severity.
  The report is saved in the current working directory.
  The report is named "vulnerability_report.zip"
  The report contains the following columns:
    - KEV (boolean) - whether the advisory is a KEV
    - CVE-ID (string) - the CVE ID of the advisory
    - GHSA-ID (string) - the GHSA ID of the advisory
    - HTML-URL (string) - the HTML URL of the advisory
    - SUMMARY (string) - the summary of the advisory
    - TYPE (string) - the type of the advisory
    - UPDATED-AT (string) - the updated at date of the advisory
    - WITHDRAWN-AT (string) - the withdrawn at date of the advisory

  Args:
    github_auth_token: The authentication token for the Github API.
  """
  github = get_github_instance(github_auth_token)
  advisories = get_global_advisories(github)
  kev_cve_ids = get_kev_cve_ids()

  low_advisories_file = open(LOW_VULNERABILITY_FILENAME, "w")
  medium_advisories_file = open(MEDIUM_VULNERABILITY_FILENAME, "w")
  high_advisories_file = open(HIGH_VULNERABILITY_FILENAME, "w")
  critical_advisories_file = open(CRITICAL_VULNERABILITY_FILENAME, "w")

  low_advisories_writer = csv.writer(low_advisories_file)
  medium_advisories_writer = csv.writer(medium_advisories_file)
  high_advisories_writer = csv.writer(high_advisories_file)
  critical_advisories_writer = csv.writer(critical_advisories_file)

  low_advisories_writer.writerow(CSV_HEADER_ROW)
  medium_advisories_writer.writerow(CSV_HEADER_ROW)
  high_advisories_writer.writerow(CSV_HEADER_ROW)
  critical_advisories_writer.writerow(CSV_HEADER_ROW)
  

  for advisory in advisories:
    if advisory.cve_id in kev_cve_ids:
      kev = True
    else:
      kev = False

    if advisory.severity == LOW_VULNERABILITY_ID:
      low_advisories_writer.writerow([kev, advisory.cve_id, advisory.ghsa_id, advisory.html_url, advisory.summary, advisory.type, advisory.updated_at, advisory.withdrawn_at])
    elif advisory.severity == MEDIUM_VULNERABILITY_ID:
      medium_advisories_writer.writerow([kev, advisory.cve_id, advisory.ghsa_id, advisory.html_url, advisory.summary, advisory.type, advisory.updated_at, advisory.withdrawn_at])
    elif advisory.severity == HIGH_VULNERABILITY_ID:
      high_advisories_writer.writerow([kev, advisory.cve_id, advisory.ghsa_id, advisory.html_url, advisory.summary, advisory.type, advisory.updated_at, advisory.withdrawn_at])
    elif advisory.severity == CRITICAL_VULNERABILITY_ID:
      critical_advisories_writer.writerow([kev, advisory.cve_id, advisory.ghsa_id, advisory.html_url, advisory.summary, advisory.type, advisory.updated_at, advisory.withdrawn_at])


  low_advisories_file.close()
  medium_advisories_file.close()
  high_advisories_file.close()
  critical_advisories_file.close()

  zip_file = zipfile.ZipFile("vulnerability_report.zip", "w")
  zip_file.write(LOW_VULNERABILITY_FILENAME)
  zip_file.write(MEDIUM_VULNERABILITY_FILENAME)
  zip_file.write(HIGH_VULNERABILITY_FILENAME)
  zip_file.write(CRITICAL_VULNERABILITY_FILENAME)
  zip_file.close()

  os.remove(LOW_VULNERABILITY_FILENAME)
  os.remove(MEDIUM_VULNERABILITY_FILENAME)
  os.remove(HIGH_VULNERABILITY_FILENAME)
  os.remove(CRITICAL_VULNERABILITY_FILENAME)


if __name__ == "__main__":
  github_auth_token = os.getenv("GITHUB_AUTH_TOKEN")
  if github_auth_token is None:
    raise RuntimeError("GITHUB_AUTH_TOKEN is not set")
  generate_vulnerability_report(github_auth_token)






