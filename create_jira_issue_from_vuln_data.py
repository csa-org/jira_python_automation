from laceworksdk import LaceworkClient
import json
from jira import JIRA

# Open the lacework creds file
with open('api_key.json', 'r') as f:
    # Load the JSON data
    data = json.load(f)

# Open the Jira creds file
with open('jira_config.json', 'r') as f:
    jira_config = json.load(f)

# Lacework API Creds
lw_keyId = data['keyId']
lw_secret = data['secret']
lw_account = data['account']

# Jira API Creds
JIRA_BASE_URL = jira_config["JIRA_BASE_URL"]
USERNAME = jira_config["USERNAME"]
API_TOKEN = jira_config["API_TOKEN"]
PROJECT_KEY = jira_config["PROJECT_KEY"]

# Connect to Jira
jira_options = {'server': JIRA_BASE_URL}
jira = JIRA(options=jira_options, basic_auth=(USERNAME, API_TOKEN))

lw = LaceworkClient(account=lw_account,
                    api_key=lw_keyId,
                    api_secret=lw_secret)
print("Lacework Client Authenticated Successfully")

# Query the Lacework vulnerabilities endpoint for all critical vulnerabilities
def get_host_vuln_data():
    '''
    # Use this Lacework API query to get all critical vulnerabilities with a fix available
    host_vulns = lw.vulnerabilities.hosts.search(json={
    "filters": [
        {
        "field": "severity",
        "expression": "eq",
        "value": "Critical"
        },
        {
        "field": "fixInfo.fix_available",
        "expression": "eq",
        "value": "1"
        }
    ]
    })
    '''
    host_vulns = lw.vulnerabilities.hosts.search(json={
    "filters": [
        {
        "field": "severity",
        "expression": "eq",
        "value": "Critical"
        }
    ]
    })
    return host_vulns

# Function to get all issues in a project
def get_all_open_issues(project_key):
    jql_str = f'project={project_key} AND status NOT in ("Done", "Closed")'
    #jql_str = f'project={project_key} AND status in (Open, "In Progress")'
    issues = jira.search_issues(jql_str, maxResults=1000)  # Adjust maxResults as needed
    return issues

# Function to get all non-closed/done issues in a project with pagination
def get_all_issues_pagination(project_key):
    #jql_str = f'project={project_key}'
    jql_str = f'project={project_key} AND status NOT in ("Done", "Closed")'
    start_at = 0
    max_results = 100
    all_issues = []

    while True:
        issues = jira.search_issues(jql_str, startAt=start_at, maxResults=max_results)
        if not issues:
            break
        all_issues.extend(issues)
        start_at += len(issues)
        if len(issues) < max_results:
            break

    return all_issues

# Function to check if any issue contains the search string
def check_issues_for_string(issues, search_string):
    for issue in issues:
        if search_string in (issue.fields.description or ''):
            return True
    return False

# Function to create a new issue
def create_new_issue(project_key, summary, description):
    issue_dict = {
        'project': {'key': project_key},
        'summary': summary,
        'description': description,
        'issuetype': {'name': 'Task'},  # Adjust issue type as needed
    }
    new_issue = jira.create_issue(fields=issue_dict)
    print(f"New issue created successfully: {new_issue.key}")

# Main logic - loops through all open issues and all lacework host vulnereabilities.  
# If a vuln is found that is not in the non-done/closed jira issues, a new issue is created
def main():
    issues = get_all_issues_pagination(PROJECT_KEY)
    host_vuln_data = get_host_vuln_data()
    for page in host_vuln_data:
        for vuln in page['data']:
            # Create a fingerprint for each vulnerability based on the vulnId, name, version_installed, and mid
            fingerprint = str(vuln['vulnId'])+'_'+str(vuln['featureKey']['name'])+"_"+str(vuln['featureKey']['version_installed'])+"_"+str(vuln['mid'])
            issues = get_all_issues_pagination(PROJECT_KEY)
            # Check if any issue contains the fingerprint
            if not check_issues_for_string(issues, fingerprint):
                # Create a new issue if the fingerprint is not found in any existing non-closed/done issue
                print(f"creating new issue {fingerprint}")
                Description = f"{fingerprint}\nPackage Name:{vuln['featureKey']['name']}\nPackage Namespace:{vuln['featureKey']['namespace']}\nCurrent Version:{vuln['featureKey']['version_installed']}\nFix Version:{vuln['fixInfo']['fixed_version']}\nVulnerability ID:{vuln['vulnId']}\nVulnerability Severity:{vuln['severity']}\nHost:{vuln['machineTags']['Hostname']}\nVulnerability Description:{vuln['cveProps']['description']}"
                Summary = f"Fix {vuln['vulnId']}:{vuln['featureKey']['name']} {vuln['featureKey']['namespace']}"
                create_new_issue(PROJECT_KEY, Summary, Description)
            else:
                print(f"An issue already contains the string '{fingerprint}'.")

if __name__ == '__main__':
    main()
