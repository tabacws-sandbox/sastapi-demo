import requests
from termcolor import colored
import sys


if __name__ == '__main__':
    SASTCLI_TOKEN = sys.argv[1]
    MEND_SAST_URL = "https://saas-eu.mend.io/sast"
    MEND_API_URL = MEND_SAST_URL+'/api'
    SCANS = '/scans'
    SCANS_SUMMARY = SCANS+'?summary=true'
    HEADERS = {'X-Auth-Token': '{}'.format(SASTCLI_TOKEN)}

    r = requests.get(MEND_API_URL + SCANS_SUMMARY, headers=HEADERS).json()
    SCAN_ID = r[0]['id']

    r2 = requests.get(MEND_API_URL + SCANS + '/{}/prioritizedfindings'.format(SCAN_ID), headers=HEADERS)
    if r2.status_code != 200:
        raise Exception("Error")
    findings = r2.json()
    print("[+] High Alert Findings:\n")
    for i,item in enumerate(findings):
        if item["risk"] == "High":
            print(colored("[+] Item #{}".format(i+1), 'green'))
            print(colored("[!] Language: {}".format(item["language"], 'red')))
            print(colored("[!] Flow Name: {}".format(item["type"]["name"]),'red'))
            print(colored("[!] Sink call: {}".format(item["sink"]),'yellow'))
            print(colored("[!] Sink file: {}\n\n".format(item["sinkFile"]),'blue'))


