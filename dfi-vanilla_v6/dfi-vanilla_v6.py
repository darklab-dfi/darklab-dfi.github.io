#!/usr/bin/env python
# coding: utf-8

# # Automation for DFI (v2)
# ### V2 Introducing- batching process - & Higher Level Automation(Mar), Updated Free API
# ### V1.4 Additional Features:(Mar)
# ### Domain Squatting, Cert Crypto Analysis, SPF , DNSSEC Records, Renamed Screenshots, Consolidated WorkSheet
#
# ### v 1.3 Additional Features: (Mar)
# ### Botnet, IP Blocking list, Screencap, Structured Folders
# ##### Created Date: March 2020
#
# ### Remark
# #### If you restart the kernel, please run the section 0 after any operations!
# ## Before You Start
#
# <details>
# <summary> Please run following command to initalise the dashboards</summary>
#     <code>
# pip install dnsdumpster --user
# pip install panda
# pip install request
# pip install validator
# pip install termcolor
# pip install urllib3
# pip install xmltodict
# pip install ipinfo
# pip install shodan
# pip install urlscan-py --user
# pip install checkdmarc
# pip install pandas
# pip install lxml
# pip install pillow
# pip install urlscanio
# pip install ipywidgets
#     </code>
#
# Install curl if Windows 10 build < 17063
# Add new folder "result" in same directory where dfi-vanilla.py is saved
# </details>
#
# ---

# ###  Section 0. Imported Libraries

# In[12]:


# Libraries Imported
from __future__ import print_function
from ipywidgets import interact, interactive, fixed, interact_manual
import ipywidgets as widgets
from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
from itertools import combinations
import json
import csv
import requests
import pandas
import socket
import pandas.io.formats.style
import xmltodict
import urllib
import lxml.etree as ET
import ipinfo
from IPython.display import clear_output
import os
import time
from PIL import Image
import PIL
import glob
import sys
import argparse
from IPy import IP
import subprocess

# ### Section 0. Configuration
# ##### (Please Ensure this cell items fulfilled your needs)
# This is just a test
# This is another test
# if len(sys.argv) != 4:
#     print("Usage: python dfi.py [enttiyName] [searchDomains] [keyword]")
#     print("Example: python dfi-vanilla.py PricewaterhouseCoopers pwc1.com,pwc2.com,pwc3.com pwc")
#     sys.exit('Invalid Command')
# In[16]:

parser = argparse.ArgumentParser()
parser.add_argument('--entityname', '-e', help='entityName, like PricewaterhouseCoopers', required=True)
parser.add_argument('--keyword', '-k', help='keyword, like pwc', required=True)

group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--searchdomains', '-s', help='searchDomains, like pwc1.com,pwc2.com,pwc3.com',default=None)
group.add_argument('--ip', '-i', help='IP, like 8.8.8.8, 172.21.0.32/27, 172.21.0.32-172.21.0.63',default=None)
group.add_argument('--ipfile', '-f', help='searchDomains, like IPlist.txt',default=None)

args = parser.parse_args()



entityName = args.entityname
try:
    os.makedirs('result/' + entityName + '/IPresult')
except:
    print("The Entity Folder Created Before")


def vscan():
    ## Run Shodan.py & Censys.py to collect
    ShodanAPI = "oraTHZ3twsfOJFjQf4Qlv2lvrt08qD3K"  # ShodanAPI
    CENSYS_API_KEY = "dcd4fda2-c32c-4d07-a410-20d488d744a1"  # Censys API KEY
    CENSYS_API_SECRET = "crrszvYrg6v4zE6JqoGWFLg1GIz6Qdq4"  # Censys API Secret
    ZOOMEYE_API_USERNAME = "lazcrag23@gmail.com"  # zoomeye username
    ZOOMEYE_API_PASSWORD = "S9CvUbbsny"  # zoomeye password

    outS13 = []

    IPListsLocation = 'result/' + entityName + '/IPresult/' + 'IPList.txt'
    outputlocation = 'result/' + entityName + '/IPresult/' + 'output.txt'
    print("Connecting to Shodan API")
    os.system('python Shodan.py ' + IPListsLocation + '> ' + outputlocation)

    print("Connecting to Zoomeye API")
    # check = os.system('python Zoomeye.py ' + IPListsLocation)
    # if check == 0:
    #     print("zoomeye no data")
    cmd2 = 'python Zoomeye.py ' + IPListsLocation
    pipe2 = subprocess.Popen(cmd2, shell=True, stdout=subprocess.PIPE).stdout
    print(pipe2.read().decode())
    if pipe2.read().decode() == "":
        print("zoomeye no data")
    else:
        os.system('python Zoomeye.py ' + IPListsLocation + '>> ' + outputlocation)


    print("Connecting to Censys API")
    try:
        os.system(
            'python censys_v1.py ' + IPListsLocation + ' ' + CENSYS_API_KEY + ' ' + CENSYS_API_SECRET + ' >> ' + outputlocation)
    except:
        print("Censys API No Response")
        # errLog.write('Not Found: CenSys API @' + searchDomain + "\\n")
    print("Transanction Done")
    dfShodan = pandas.read_csv(filepath_or_buffer=outputlocation,
                               sep="\t", header=0, error_bad_lines=False, encoding="ISO-8859–1")
    dfShodan.drop_duplicates
    dfShodan.to_csv('result/' + entityName + '/IPresult' + '/vul_server.csv')
    outS13.append(dfShodan)
    dfShodan["No. Cve"] = pandas.to_numeric(dfShodan["No. Cve"], errors='ignore', downcast="integer")
    dfShodan["Highest CVSS"] = pandas.to_numeric(dfShodan["Highest CVSS"], downcast="float", errors='ignore')
    print(dfShodan)
    dfShodan.astype({'No. Cve': 'float', 'Port': 'float', 'Highest CVSS': 'float'}, errors='ignore')
    print("The result is sorted according to number of CVE, please view the details in IPresult/vul_server.csv")
    dfResultShodan = dfShodan[dfShodan['No. Cve'] > 0].sort_values(by="No. Cve", ascending=False,
                                                                   na_position='last').filter(
        items=['Host', 'Port', 'Portocol', 'Website Title', 'No. Cve', 'Highest CVSS',
               'Corresponding CVE']).style.hide_index()
    print(
        "==========Section 1.3 Vulnerability Scanning Finished, located in /result/" + entityName + "/IPresult" + '/output/vul_server.csv')

    try:
        df13Display = pandas.concat(outS13)
        df13Display
    except:
        print("No Findings - Vulnerable Servers")


if args.searchdomains != None:
    pass
elif args.ip != None:
    fw = open('result/' + entityName + '/IPresult/' + 'IPList.txt', "w")
    iplist = args.ip.split(',')
    for x in iplist:
        ip = IP(x)
        for i in ip:
            fw.write(str(i))
            fw.write("\n")
    fw.close()
    vscan()
    exit()
elif args.ipfile != None:
    fr = open(args.ipfile, "r")
    fw = open('result/' + entityName + '/IPresult/' + 'IPList.txt', "w")
    for line in fr:
        ip = IP(line)
        for i in ip:
            fw.write(str(i))
            fw.write("\n")
    fr.close()
    fw.close()
    vscan()
    exit()
else:
    print("impossible")











try:
    print(
        "Hi! Welcome to the Digital Footprint Intelligence Automation")
    print("Let's scan some stuff, shall we?")

    # entityName = sys.argv[1]  # The folder name
    entityName = args.entityname

    # pre_searchDomains = sys.argv[2]
    pre_searchDomains = args.searchdomains

    # searchDomains = sys.argv[2].split(',')
    searchDomains = args.searchdomains.split(',')

    print("[Confirmed] Entity: " + entityName)
    print("[Confirmed] Total" + str(len(searchDomains)) + " :" + str(searchDomains))
except:
    print("Did you run command via ipython instead of python? Ipynb is necessary for the scripts! ")
    print("Usage: python dfi.py [enttiyName] [searchDomains]")
    print("Example: python dfi.py PricewaterhouseCoopers pwc1.com,pwc2.com,pwc3.com pwc")

# Section 1.1 Subdomain servers listing (output/MergedDomainLists.csv)
# Extracted subdomains from dnsTrail and scrapper
# To-do: Utilize with virustotal API to expore more subdomains info.
# There's no offical API for dunsdumpster, an online scrapper is being utilized for this case
# dnsTrailAPI = "hNYumOsunacVhonaenlTHs7Z5veZamg7" #DNS Trail API
dnsTrailAPI = "4DadzqmouOQhTfGDFKh1tnvMoWWvTe91"

ipinfoAPI = "b3f54ca780db8a"  # IPInfo API
os.environ["URLSCAN_API_KEY"] = "e379464f-4bab-4c4f-82aa-5cc6177c69d5"  # URLScan API Key

# Section 1.2 Non produnction entry points and Login Portal exposure
# Determine whether the website can be logined.
keyWordList = ['login', 'password', 'credentials', 'username', 'pwd', '密碼', 'pass']  # list for login portal
# Determine whether the website is non-proudunction entry point through URL
nonProdEntryPointList = "dev|uat|qa|test|stag|temp|tmp"  # Reg-Exp for determing whether link's non-produnction entry point

# Section 1.3 Subdoamin servers scanning and vulnerability check from banner
ShodanAPI = "RifB5RHIyi80O3BZsz3V8yUHEupjRu1T"  # ShodanAPI
CENSYS_API_KEY = "dcd4fda2-c32c-4d07-a410-20d488d744a1"  # Censys API KEY
CENSYS_API_SECRET = "crrszvYrg6v4zE6JqoGWFLg1GIz6Qdq4"  # Censys API Secret
ZOOMEYE_API_USERNAME = "lazcrag23@gmail.com"  # zoomeye username
ZOOMEYE_API_PASSWORD = "S9CvUbbsny"  # zoomeye password




# Section 1.6 Blocklist Checked
print("Updating Malicious & Botnet Database")
botnet = pandas.read_csv('https://feodotracker.abuse.ch/downloads/ipblocklist.csv', skiprows=8)
maliciousLinks = pandas.read_csv('https://urlhaus.abuse.ch/downloads/csv_recent/', skiprows=9,
                                 names=["id", "dateadded", "url", "url_status", "threat", "tags", "urlhaus_link",
                                        "reporter"], encoding="ISO-8859-1")
print("Successfully Updated")

# Section 2 Email Address Exposure
# Extracted information from hunterIO and run emailHarvest to scrape the email and the info of extraction.
# To-do: haveibeenpawned API integration to determine the vulnerability from email
HunterIOAPI = "22850ea6e4f33099e48217886b978b65c82db488"  # HunterIO API Key

# Section 3 Cloud Bucket Exposeure
# There's 2 ways of judgement:
# 1) Find the buckets that matched the keyword
# 2) Find the filename contained the keyword and read in file bias to determine whether the contents contained dubious data
# To-do: Multithreading optimisation
# keyword = sys.argv[3]  # keyword means the info related to the target entity
keyword = args.keyword


bucketsAPI = "bd44761391bfe57754976fd24172f289"  # GaryHatWatFare API
keyBucketWordList = ['htaccess', 'conf', 'secret', 'credntial', 'password', 'broker', 'py', 'cert', 'sh',
                     'log']  # dubious file name in (1)
keyFileWorldList = ['secret', 'confidential', 'htaccess', 'password', 'reset', 'procedure', 'policy',
                    'config']  # For file-bias scanning in (2)
removeTLDForShodan = [x.split('.')[0] for x in searchDomains]
print("Reminder: If error encounters in afterward sessions, try to ensure you don't reach the API key limit")
outS11 = []
outS12 = []
outS13 = []
outS14 = []
outS15 = []
outS16 = []
outS17 = []
outS18 = []
outS19 = []
outS110 = []
outS2 = []

# ### Folder Structures

# In[4]:


# try:
#     os.mkdir('result/' + entityName)
# except:
#     print("The Entity Folder Created Before")
for searchDomain in searchDomains:
    try:
        os.mkdir('result/' + entityName + '/' + searchDomain)
        os.mkdir('result/' + entityName + '/' + searchDomain + '/output')
        os.mkdir('result/' + entityName + '/' + searchDomain + '/temp')
        os.mkdir('result/' + entityName + '/' + searchDomain + '/logs')
        os.mkdir('result/' + entityName + '/' + searchDomain + '/output/screenshots')
    except:

        print(
            "Folder Created Before, We recommend you to delete the whole result" + entityName + "if you want to re-do.")
clear_output(wait=True)


# For styling in tables
def make_clickable_both(val):
    return f'<a href="{"http://" + str(val)}">{str(val)}</a>'


def critical(val):
    color = 'red' if val > 7 else 'white'
    color = 'yellow' if val > 4 else 'white'
    color = 'green' if val > 0 else 'white'
    return f'<p color:"{color}">{float(val)}</p>'


def path_to_image_html(path):
    return '<img src="' + path + '" width="200" >'


# ### Section 1

# In[5]:


folder = os.getcwd() + '\\result\\'
print(folder)
if not os.path.exists(folder):
    os.makedirs(folder)

# errLog = open('result/'+entityName+'/error_log.txt','w')
# Debug: Note_1
errLog_dir = os.path.join('result', entityName)
if not os.path.exists(errLog_dir):
    os.makedirs(errLog_dir)
errLog = open(os.path.join(errLog_dir, 'error_log.txt'), 'w')
# Debug: Note_1 end











for index, searchDomain in enumerate(searchDomains):
    print("Starting:" + searchDomain)
    print("==========Section 1 DNS Enumeration===========")
    print("Extraction Initalised. This may take a few minutes. Go grab a coffee..")
    results = DNSDumpsterAPI().search(searchDomain)  # Unoffical grabbing from dnsdumpster
    processed_Records = []
    try:
        for item in results['dns_records'].items():
            if (item[0] != 'txt'):
                for sub_item in item[1]:
                    sub_item.update({'Record Type': item[0]})
                    processed_Records.append(sub_item)
    except:
        print("DNS Dumpster Failed")
    url = "https://api.securitytrails.com/v1/domain/" + searchDomain + "/subdomains"
    headers = {
        'accept': "application/json",
        'apikey': dnsTrailAPI
    }
    dfDomain = pandas.DataFrame({'Result': []})
    try:
        response = requests.request("GET", url, headers=headers)
        # API for subdomain (from DNS Trail)
        handler = ipinfo.getHandler(access_token='b3f54ca780db8a')

        # dfDomain = pandas.read_json(response.text)
        tmpRes = json.loads(response.text)
        dfDomain = pandas.DataFrame(tmpRes["subdomains"])

        dfDomain['IP'] = ''
        dfDomain['ISP'] = 'Not Provided from Security Trail'
        dfDomain['Record Type'] = 'host'
        dfDomain['hostname'] = ''
        IPLists = []
        for x in range(len(dfDomain)):
            if (dfDomain.iloc[x, 0] != ''):
                dfDomain.iloc[x, 0] = dfDomain.iloc[x, 0] + "." + searchDomain
            else:
                dfDomain.iloc[x, 0] = searchDomain
            try:
                dfDomain.iloc[x, 2] = socket.gethostbyname(dfDomain.iloc[x, 0])
                try:
                    details = handler.getDetails(dfDomain.iloc[x, 2])
                    dfDomain.iloc[x, 3] = details.org + details.country
                    # dfDomain.iloc[x,5] = details.hostname
                    dfDomain.iloc[x, 4] = details.hostname
                except:
                    dfDomain.iloc[x, 3] = "No Info"
                    # dfDomain.iloc[x,5] = "No Info"
                    dfDomain.iloc[x, 4] = "No Info"
            except socket.error:
                dfDomain.iloc[x, 2] = "No Info"
        # dfDomain.columns = ["Domain","NA","IP","ISP","Record Type","Host Name"]
        dfDomain.columns = ["Domain", "IP", "ISP", "Record Type", "Host Name"]
        dfDomain.filter(items=['Domain', 'IP', 'ISP', 'Host Name']).style.hide_index().format(
            {'Domain': make_clickable_both})
    except:
        print(response)
        print("Extracted from DNS Trail Failed, please check its API!!!!")
        errLog.write("Extraction from DNS Trail Failed @ " + searchDomain + "\\n")
    dfDnsdumpster = pandas.DataFrame(processed_Records)
    dfDnsdumpster = dfDnsdumpster.rename(columns={'domain': 'Domain', 'ip': 'IP', 'reverse_dns': 'Host Name'})
    print("Extracted from dnsdumpster completed.")
    print("Process Completed")
    # mreged Data frames from dnsdumpster & DNS trail
    df = pandas.concat([dfDomain.filter(items=['Domain', 'IP', 'ISP', 'Record Type', 'Host Name']),
                        dfDnsdumpster.filter(items=["Domain", "IP", "ISP", "Host Name", "Record Type"])], axis=0,
                       sort=True)

    # Debug: Note_2
    to_csv_dir = os.path.join('reuslt', entityName, searchDomain, 'output')
    if not os.path.exists(to_csv_dir):
        os.makedirs(to_csv_dir)
    # df.to_csv('result/'+entityName+'/'+searchDomain+'/output/MergedDomainLists.csv', index = False)
    df.to_csv(os.path.join(to_csv_dir, 'MergedDomainLists.csv'), index=False)
    # Debug: Note_2 end

    outS11.append(df)
    print(
        "==========Section 1.1 DNS Enumration Finished, located in /result/" + entityName + "/" + searchDomain + '/output/MergedDomainLists.csv')
    print("==========Section 1.2 Non-Produnction Entry Point ===========")
    # df = df.drop_duplicates(subset=['IP','Domain'], keep='first')
    g = open("result/" + entityName + '/' + searchDomain + "/temp/IPList.txt", "w")
    pendingToScan = []
    for x in range(len(df)):
        if (df.iloc[x, 2] != "No Info"):
            g.write(str(df.iloc[x, 2]))
            pendingToScan.append(df.iloc[x, 2])
            g.write("\n")
    g.close()
    print("After Removing duplicates IPs, there're ( " + str(
        len(pendingToScan)) + " ) items to be screen, the list of IP can be reviewed on temp/IPList.txt")
    # note4
    if 'Domain' in df:
        df = df.dropna(subset=['Domain'])
    if 'IP' in df:
        df = df.dropna(subset=['IP'])
    # note4 end
    # df=df.dropna(subset=['Domain','IP'])
    dfSection1Display = df.reset_index(drop=False).style.hide_index().format({'Domain': make_clickable_both})

    # note5
    if 'Domain' in df:
        dfLogin = df[df['Domain'].str.contains(nonProdEntryPointList)]  # Reg Exp in .contain()
    # note5 end

    # dfLogin = df[df['Domain'].str.contains(nonProdEntryPointList)]#Reg Exp in .contain()
    dfLogin = dfLogin.filter(items=['Domain', 'IP', 'ISP', 'Host Name'])
    dfLogin.to_csv('result/' + entityName + '/' + searchDomain + '/output/nonprod.csv')
    print(
        "==========Section 1.2 Non-Produnction Entry Point, located in /result/" + entityName + "/" + searchDomain + '/output/nonprod.csv')
    dfLogin = dfLogin.reset_index()
    del dfLogin['index']
    dfLoginDisplay = dfLogin.style.format({'Domain': make_clickable_both}).hide_index()
    outS12.append(dfLogin)
    print("==========Section 1.3 Vulnerability Scanning===========")
    ## Run Shodan.py & Censys.py to collect
    IPListsLocation = 'result/' + entityName + '/' + searchDomain + '/temp/IPList.txt'
    outputlocation = 'result/' + entityName + '/' + searchDomain + '/temp/output.txt'
    print("Connecting to Shodan API")
    os.system('python Shodan.py ' + IPListsLocation + '> ' + outputlocation)

    print("Connecting to Zoomeye API")
    check = os.system('python Zoomeye.py ' + IPListsLocation)
    if check == 0:
        print("zoomeye no data")

    os.system('python Zoomeye.py ' + IPListsLocation + '>> ' + outputlocation)

    print("Connecting to Censys API")
    try:
        os.system(
            'python censys_v1.py "result/' + entityName + '/' + searchDomain + '/temp/IPList.txt" ' + CENSYS_API_KEY + ' ' + CENSYS_API_SECRET + ' >> "result/' + entityName + '/' + searchDomain + '/temp/output.txt"')
    except:
        print("Censys API No Response")
        errLog.write('Not Found: CenSys API @' + searchDomain + "\\n")
    print("Transanction Done")
    dfShodan = pandas.read_csv(filepath_or_buffer='result/' + entityName + '/' + searchDomain + '/temp/output.txt',
                               sep="\t", header=0, error_bad_lines=False, encoding="ISO-8859–1")
    dfShodan.drop_duplicates
    dfShodan.to_csv('result/' + entityName + '/' + searchDomain + '/output/vul_server.csv')
    outS13.append(dfShodan)
    dfShodan["No. Cve"] = pandas.to_numeric(dfShodan["No. Cve"], errors='ignore', downcast="integer")
    dfShodan["Highest CVSS"] = pandas.to_numeric(dfShodan["Highest CVSS"], downcast="float", errors='ignore')
    print(dfShodan)
    dfShodan.astype({'No. Cve': 'float', 'Port': 'float', 'Highest CVSS': 'float'}, errors='ignore')
    print("The result is sorted according to number of CVE, please view the details in output/vul_server.csv")
    dfResultShodan = dfShodan[dfShodan['No. Cve'] > 0].sort_values(by="No. Cve", ascending=False,
                                                                   na_position='last').filter(
        items=['Host', 'Port', 'Portocol', 'Website Title', 'No. Cve', 'Highest CVSS',
               'Corresponding CVE']).style.hide_index()
    print(
        "==========Section 1.3 Vulnerability Scanning Finished, located in /result/" + entityName + "/" + searchDomain + '/output/vul_server.csv')
    print("==========Section 1.4 RDP/FTP/SSH Checking==============")
    dfShodan = pandas.read_csv(filepath_or_buffer='result/' + entityName + '/' + searchDomain + '/temp/output.txt',
                               sep="\t", header=0, error_bad_lines=False, encoding="ISO-8859–1")
    dfShodan.drop_duplicates
    dfShodan = dfShodan[dfShodan['Protocol'].str.contains("ssh|ftp|rdp", na=False)]
    dfShodan = dfShodan[~dfShodan['Retrieve Time'].str.contains("Not Found", na=False)]

    dfShodan["No. Cve"] = pandas.to_numeric(dfShodan["No. Cve"], errors='ignore', downcast="integer")
    dfShodan["Highest CVSS"] = pandas.to_numeric(dfShodan["Highest CVSS"], downcast="float", errors='ignore')
    dfShodan["Host Name"] = ''
    for x in range(len(dfShodan)):
        try:
            dfShodan.iloc[x, 43] = socket.gethostbyaddr(dfShodan.iloc[x, 0])[0]
        except:
            dfShodan.iloc[x, 43] = "Could Not Resolved"
    print("The result is sorted according to number of CVE, please view the details in ftpssh_server.csv")
    dfShodan.sort_values(by="No. Cve", ascending=False, na_position='last')
    dfShodan3 = dfShodan2 = dfShodan.filter(
        items=['Host Name', 'Host', 'Port', 'Protocol', 'Organization', 'Service', 'Common Platform Enumeration("CPE")',
               "Vulberability Details", "No. Cve", "Highest CVSS", "Corresponding CVE"])
    dfShodan3 = dfShodan2.style.hide_index().format({'Host Name': make_clickable_both})
    dfShodan2.to_csv('result/' + entityName + '/' + searchDomain + '/output/ftpsshrdp_server.csv')
    dfShodan3
    outS14.append(dfShodan3)
    print(
        "==========Section 1.4 RDP/FTP/SSH Checking Finished, located in" + 'result/' + entityName + '/' + searchDomain + '/output/ftpsshrdp_server.csv')
    print("==========Section 1.5 Exposed Login Portals==============")
    result = df
    result['Login Portal'] = ""
    result['ScreenShot'] = ""
    for i in range(len(result)):
        PlanedDomain = 'http://' + result.iloc[i, 0]
        print("Scanning: " + PlanedDomain)
        clear_output(wait=True)
        os.system(
            'curl -i -L -m 2 ' + PlanedDomain + ' > "result/' + entityName + '/' + searchDomain + '/temp/temporaryIP.txt"')
        f = open('result/' + entityName + '/' + searchDomain + '/temp/temporaryIP.txt', 'r', encoding='gb18030',
                 errors='ignore')
        if any(s in f.read() for s in keyWordList):
            print("Login Portal Extracted, Screen capturing... ")
            result.iloc[i, 5] = "(1) Detected"
            print("Saving urlscanio result to result/" + entityName + '/' + searchDomain + '/temp/tempPIC.txt')
            try:
                os.system(
                    'urlscanio -i ' + PlanedDomain + ' > "result/' + entityName + '/' + searchDomain + '/temp/tempPIC.txt"')
                # Debug: Note_3
                x_dir = os.path.join('result', entityName, searchDomain, 'temp')
                if not os.path.exists(x_dir):
                    os.makedirs(x_dir)
                # import pdb;pdb.set_trace()
                x = open(os.path.join(x_dir, "tempPIC.txt")).read()
                if len(x) != 0:
                    x = x.split("\n")[2].split("\t")[1].rstrip()
                    # x = open(os.path.join(x_dir,"tempPIC.txt")).read().split("\n")[2].split("\t")[1].rstrip() #Extract URL from ScanIO
                    # Debug: Note_3 end
                    Image.open(x).save(
                        "result/" + entityName + '/' + searchDomain + "/output/screenshots/" + result.iloc[
                            i, 0] + ".png")
                    result.iloc[i, 6] = x
                    Image.close()
                else:
                    result.insert(6, 'Screenshots', 1000)
                    result.iloc[i, 6] = "Failed to extract portal screenshots"
                    errLog.write('Failed: Screenshots @' + searchDomain + "\\n")
            except:
                result.insert(6, 'Screenshots', 1000)
                result.iloc[i, 6] = "Failed to extract portal screenshots"
                errLog.write('Failed: Screenshots @' + searchDomain + "\\n")
        else:
            result.iloc[i, 5] = "(0) Not Detected/Time Out"
    df.sort_values(by="Login Portal", ascending=False)
    dfDetected = df[df['Login Portal'].str.contains("1", na=False)]
    dfDetected = dfDetected.reset_index()
    del dfDetected['index']
    dfDetected.to_csv('result/' + entityName + '/' + searchDomain + '/output/PotentialPortal.csv')
    dfDetected.style.format({'Domain': make_clickable_both, 'ScreenShot': path_to_image_html})
    outS15.append(dfDetected)
    print(
        "==========Section 1.5 Exposed Login Portal Finished=======,located in" + 'result/' + entityName + '/' + searchDomain + 'output/PotentialPortal.csv')
    print("==========Section 1.6 Blocking List Checking =========")
    dfBotNet = df.filter(items=['Domain', 'IP'])
    dfBotNet['Botnet'] = ''
    dfBotNet['Botnet_Details'] = 'N/A'
    dfBotNet['MaliciousURL'] = ''
    dfBotNet['Malicious SURBL Blacklist'] = 'N/A'
    dfBotNet['Malicious Spamhaus Blacklist'] = 'N/A'
    dfBotNet['Malicious SURBL Blacklist'] = 'N/A'
    dfBotNet['Details'] = 'N/A'
    try:
        for i in range(len(dfBotNet)):
            Botnetbool = dfBotNet.iloc[i, 2] in botnet
            dfBotNet.iloc[i, 2] = Botnetbool
            myobj = {'url': 'http://' + dfBotNet.iloc[i, 0]}
            URLHaus = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data=myobj)
            dfBotNet.iloc[i, 4] = json.loads(URLHaus.text)['query_status']
            if json.loads(URLHaus.text)['query_status'] == 'OK':
                dfBotNet.iloc[i, 5] = json.loads(URLHaus.text)['blacklists']['surbl']
                dfBotNet.iloc[i, 6] = json.loads(URLHaus.text)['blacklists']['spamhaus_dbl']
                dfBotNet.iloc[i, 7] = json.loads(URLHaus.text)['blacklists']['threat']
        dfBotNet.to_csv('result/' + entityName + '/' + searchDomain + '/output/BL.csv')
        outS16.append(dfBotNet)
    except:
        print("URLHaus API Rejected")
        errLog.write('Failed: Blocking List Checking @' + searchDomain + "\\n")
    print(
        "==========Section 1.6 Blocking List Checking Finished , located in result/" + entityName + '/' + searchDomain + 'output/BL.csv')
    print("==========Section 1.7/1.8 SPF/DKIM/DMARC Record  ==========")
    os.system('checkdmarc ' + searchDomain + ' > "result/' + entityName + '/' + searchDomain + '/temp/DMARC.json"')
    dmarc = open('result/' + entityName + '/' + searchDomain + '/temp/DMARC.json', 'r')
    try:
        dmarcJson = json.load(dmarc)
    except:
        print("No DMARC Record Found")
    try:
        spfRecord = pandas.DataFrame(dmarcJson['spf']['parsed']['pass'])
        spfRecord['validation'] = dmarcJson['spf']['valid']
    except:
        spfRecord = pandas.DataFrame(["No SPF Record Found", "N/A"])

    if (dmarcJson['dmarc']['record'] != 'None'):
        dfDm = pandas.DataFrame([{'DMARC RECORD': dmarcJson['dmarc']['record']}])
    else:
        dfDm = pandas.DataFrame(["No DMARC Record Found", "N/A"])
    spfRecord.rename(columns={'value': ' SPF on', 'mechanism': 'Record Type'})
    spfRecord.to_csv('result/' + entityName + '/' + searchDomain + '/output/spfRecord.csv')
    outS17.append(spfRecord)
    dfDm.to_csv('result/' + entityName + '/' + searchDomain + '/output/dfDm.csv')
    outS18.append(dfDm)
    print(
        "==========Section 1.7/1.8 SPF/DKIM/DMARC Record ==========, located in result/" + entityName + '/' + searchDomain + '/output/dfDM.csv')
    print(
        "==========Section 1.7/1.8 SPF/DKIM/DMARC Record ==========, located in result/" + entityName + '/' + searchDomain + '/output/spfRecord.csv')
    print("==========Section 1.9 Domain Squatting ==========")
    try:
        UNIXStamp = int(time.time())
        # New Test , Proxy set up to prevent IP Ban, which is considered unstable
        req1 = {'a': 'scan', 'domain': searchDomain, 'no_limit': 0, 'dnsr': True}

        print("https://www.immuniweb.com/radar/api/v1/scan/" + str(UNIXStamp) + '.html')
        DomainSquat = requests.post("http://www.immuniweb.com/radar/api/v1/scan/" + str(UNIXStamp) + '.html', data=req1)

        print(DomainSquat.text)
        while json.loads(DomainSquat.text)['status_id'] != '3':
            print("The API Scanner for DNS Squatting is still running, please wait...")
            # os.system('cls')
            time.sleep(10000)  # sleep(10000)
            DomainSquat = requests.post("https://www.immuniweb.com/radar/api/v1/scan/" + str(UNIXStamp) + '.html',
                                        data=req1)
        req2 = {'id': json.loads(DomainSquat.text)['test_id']}
        DomainSquat = requests.post("https://www.immuniweb.com/radar/api/v1/get_result/" + str(UNIXStamp) + '.html',
                                    data=req2)
        DomainS = json.loads(DomainSquat.text)
    except:
        print("The domain squatting failed because of API limit")
        errLog.write('Failed: Domain Squatting Checking @' + searchDomain + "\\n")
    print("==========Section 1.9 Domain Squatting, pending authorized API===== ")
    print("==========Section 1.10 TLS/SSL Certificate Analysis==== ")
    try:
        dfCert = pandas.read_csv(filepath_or_buffer='result/' + entityName + '/' + searchDomain + '/temp/output.txt',
                                 sep="\t", header=0, error_bad_lines=False, encoding="ISO-8859–1")
        dfCert = dfCert[dfCert['SSL Chain'].str.contains('None') == False].filter(
            items=['Host', 'Protocol', 'Organization', 'SSL Cert Issuer Common Name', 'Website Title',
                   'SSL Cert Signature Algorithm', 'No. Cve', 'Highest CVSS', 'Corresponding CVE'])
        dfCert.to_csv('result/' + entityName + '/' + searchDomain + '/output/SSLCertAnalysis.csv')
        outS110.append(dfCert)
    except:
        print("As Vulnerability Testing Failed, Certificate was not captured")
        errLog.write("Failed Cert: " + searchDomain + "\\n")
    print(
        "==========Section 1.10 TLS/SSL Certificate Analysis finished, located in result/" + entityName + '/' + searchDomain + 'output/SSLCertAnalysis.csv')
# Section 2 Email for Social Engineering.

emailFrame = []
for searchDomain in searchDomains:
    url = "https://api.hunter.io/v2/domain-search?domain=" + searchDomain + "&api_key=52a64f7e45e2bd234bc8dd03e56f23d2b5edd674&limit=100000"

    headers = {
        'accept': "application/json",
        'apikey': HunterIOAPI
    }
    print("Calling API")
    emailResponse = requests.request("GET", url, headers=headers)
    print("Running EmailHarvester, this may take minutes")
    # Null the Emailharvester.py
    file1 = open('result/' + entityName + '/' + searchDomain + '/temp/emails.txt', "w")
    file1.write('')
    file1.close()
    # !python EmailHarvester.py -d $searchDomain -e all -l 2000 -s result/$searchDomain/temp/emails.txt #diabled
    print("Done EmailHarvester")
    a = json.loads(emailResponse.text)
    if not 'data' in a.keys():
        print("No Email found on " + searchDomain)
    elif 'data' in a.keys():
        # import pdb;pdb.set_trace()
        # Retrive from API & theEmailHarvester
        dfEmail = pandas.DataFrame(a['data']['emails'])
        dfEmail['still_in_page'] = ''
        dfEmail['Links List'] = ''
        # emailH = open('result/'+searchDomain+'/temp/emails.txt','r')
        for index, x in enumerate(a['data']['emails']):
            still_in_page = False
            linkList = []
            for y in x['sources']:
                still_in_page = still_in_page or bool(y['still_on_page'])
                if (still_in_page):
                    linkList.append(y['uri'])
            dfEmail.iloc[index, 12] = still_in_page
            dfEmail.iloc[index, 13] = len(linkList)
        try:
            dfEmailHarvester = pandas.read_csv('result/' + searchDomain + '/temp/emails.txt', header=None)
            dfEmailHarvester = dfEmailHarvester.rename(columns={0: 'value'})
            dfEmailFinal = pandas.concat([dfEmail.filter(
                items=['value', 'confidence', 'first_name', 'last_name', 'position', 'department', 'still_in_page',
                       'Links List'])
                                             , dfEmailHarvester], axis=0, sort=True, ignore_index=True)

        except:
            dfEmailFinal = dfEmail
        dfEmailFinal.to_csv('result/' + entityName + '/' + searchDomain + '/output/emailLists.csv')
        try:
            dfEmailFinal.astype({'confidence': 'float'})
            dfEmailFinal.filter(
                items=['value', 'still_in_page', 'Links List', 'confidence', 'department', 'first_name', 'last_name',
                       'position']).style.hide_index()
            emailFrame.append(dfEmailFinal)
            dfDisplay = pandas.concat(emailFrame)
            dfDisplay.to_csv('result/' + entityName + '/' + searchDomain + '/output/emailList.csv')
            outS2.append(dfDisplay)
        except:
            print("No Email found on " + searchDomain)
        print(
            "==========Section 2 Email for Social Engineering, output to result/" + entityName + '/' + searchDomain + '/output/emailLists.csv')

# ### Section 1.1 - Subdomain Listing (File Path: result/_ENTITY_NAME_/output/MergedDomainLists.csv )

# In[6]:
print("== Summary ==")
try:
    df11Display = pandas.concat(outS11)
    df11Display
except:
    print("No Findings - Subdomain Listing")

# ### Section 1.2  Potential Non-production entry points (File Path: output/nonprod.csv)
#

# In[19]:


try:
    df12Display = pandas.concat(outS12)
    df12Display
except:
    print("No Findings - Potential Non-prod")

# ### Section1.3 Vulnerable Servers (File Path: output/vul_server.csv)

# In[ ]:


try:
    df13Display = pandas.concat(outS13)
    df13Display
except:
    print("No Findings - Vulnerable Servers")

# ### Section1.4 Exposed FTP / SSH / RDP Servers (File Path: output/ftpssh_server.csv)

# In[ ]:


try:
    df14Display = pandas.concat(outS14)
    df14Display
except:
    print("No Fidings - Exposed FTP/SSH/RDP Server")

# ### Section1.5 Exposed Login Portals ( Mail or Web )
# #### The result will output the table for potential login pages

# In[ ]:


try:
    df15Display = pandas.concat(outS15)
    df15Display
except:
    print("No Findings - Exposed Login Portals")

# ### Section1.6 Blocking List Checking

# In[9]:


try:
    df16Display = pandas.concat(outS16)
    df16Display
except:
    print('No Findings - Block List')

# ### Section 1.7 SPF / DKIM Records

# In[ ]:


# ### Section 1.8 DMARC & Detailed SPF Records

# In[20]:


try:
    df18Display = pandas.concat(outS18)
    df18Display
except:
    print("No Findings - DMARC")

# ### Section 1.9 Domain Squatting (Only 10 requests per day)

# In[ ]:


# UNIXStamp = int(time.time())
# # New Test , Proxy set up to prevent IP Ban, which is considered unstable
# req1 = {'a': 'scan','domain': 'macaulegend.com', 'no_limit': 0, 'dnsr' : True}

# print("http://www.immuniweb.com/radar/api/v1/scan/"+str(UNIXStamp)+'.html')
# proxy = collector.get_proxy({'anonymous': True, 'type': 'http'})
# proxies={"http": proxy.host}
# print(proxy.host)
# DomainSquat = requests.post("http://www.immuniweb.com/radar/api/v1/scan/"+str(UNIXStamp)+'.html',data=req1)

# print(DomainSquat.text)
# while json.loads(DomainSquat.text)['status_id'] != '3':
#     print("The API Scanner for DNS Squatting is still running, please wait...")
#     os.systel('cls')
#     sleep(10000)
#     DomainSquat = requests.post("https://www.immuniweb.com/radar/api/v1/scan/"+str(UNIXStamp)+'.html',data=req1)
# req2 = {'id': json.loads(DomainSquat.text)['test_id']}
# DomainSquat = requests.post("https://www.immuniweb.com/radar/api/v1/get_result/"+str(UNIXStamp)+'.html',data=req2)
# DomainS = json.loads(DomainSquat.text)
# The displayer is temporaily closed as no API provided


# ### Section 1.10  TLS/SSL Certificate Analysis

# In[ ]:


# dfCert = pandas.read_csv(filepath_or_buffer='result/'+searchDomain+'/temp/output.txt', sep="\t", header=0 ,error_bad_lines=False, encoding="ISO-8859–1")
# dfCert = dfCert[dfCert['SSL Chain'].str.contains('None')==False].filter(items=['Host','Protocol','Organization','SSL Cert Issuer Common Name','Website Title','SSL Cert Signature Algorithm','No. Cve','Highest CVSS','Corresponding CVE'])
# dfCert.to_csv('result/'+searchDomain+'/output/SSLCertAnalysis.csv')
try:
    df110Display = pandas.concat(outS110)
    df110Display
except:
    print("No Findings - Cert Analysis")

# ## Section 2 Email Harvest ( Hunter IO & TheEmailHarvester )
# ---

# #### API Called Extract Email from Hunter.io & EmailHarvester (File Path: output/emailLists.csv)

# In[ ]:


# API Called
try:
    dfSection2Display = pandas.concat(outS2)
    dfSection2Display
except:
    print("No Findings - Email")

# # Section 3. Exposed Cloud Buckets
# ---

# <p>There's 2 ways of judgement:</p>
# <p> Section 3.1) Find the buckets that matched the keyword </p>
# <p> Section 3.2) Find the filename contained the keyword and read in file bias to determine whether the contents contained dubious data</p>

# ### Section 3.1 Extract potential brackets from keywords through API  (File: output/dbByBucketName.csv)

# In[ ]:


bucketsURL = "https://buckets.grayhatwarfare.com/api/v1/buckets/0/2000?access_token=bd44761391bfe57754976fd24172f289&keywords=" + keyword
headers = {
    'accept': "application/json",
    'apikey': bucketsAPI
}
print("========== Connecting to API to conduct bucket scannings")
BucketResponse = requests.request('get', bucketsURL, headers=headers)
b = json.loads(BucketResponse.text)
if (b['buckets_count'] > 2000):
    print("Reached API Limit")

dfBucket = pandas.DataFrame(b['buckets'])
dfBucket['Connection'] = 'Success'
dfBucket['Potential file lists'] = ''
dfBucket['Matched keyword files count'] = 0
opener = urllib.request.build_opener()
for i in range(len(dfBucket)):
    listinXML = []
    print(str(i) + " buckets scanned, remaining " + str(len(dfBucket) - i))
    clear_output(wait=True)
    os.system('cls')
    url = dfBucket.iloc[i, 1]
    try:
        tree = ET.parse(opener.open('http://' + url))
    except:
        dfBucket.iloc[i, 3] = 'No Longer Exist'
        continue
    for elem in tree.iter():
        try:
            if ('Key' in elem.tag) & any(s in elem.text for s in keyBucketWordList):
                listinXML.append(elem.text)
        except:
            continue
    dfBucket.iloc[i, 4] = ''.join(listinXML)
    dfBucket.iloc[i, 5] = len(listinXML)
dfBucket

# ### Section 3.2 Ordered list of buckets which contained keyword matched files (File Path: output/orderedListbyFiles.csv)

# In[ ]:


print("The following tables has been exported to output/dbByBucketName.csv")
dfBucket.filter(items=['bucket', 'fileCount', 'Connection', 'Matched keyword files count']).sort_values(
    by='Matched keyword files count', ascending=False).to_csv(
    'result/' + entityName + '/' + searchDomain + '/output/dbByBucketName.csv')
dfBucket.filter(items=['bucket', 'fileCount', 'Connection', 'Matched keyword files count']).sort_values(
    by='Matched keyword files count', ascending=False).style.hide_index().format({'bucket': make_clickable_both})
bucketsURL = "https://buckets.grayhatwarfare.com/api/v1/files/" + keyword + "/0/1000?access_token=bd44761391bfe57754976fd24172f289"
headers = {
    'accept': "application/json",
    'apikey': bucketsAPI
}
fileResponse = requests.request('get', bucketsURL, headers=headers)
b = json.loads(fileResponse.text)
try:
    dfFileBucket = pandas.DataFrame(b['files'])
    df2 = dfFileBucket.groupby('bucket').count().sort_values(by='url', ascending=False)
    df2['index'] = range(1, len(df2) + 1)
    df2 = df2.reset_index()
    df2.to_csv('result/' + entityName + '/' + searchDomain + '/output/orderedListbyFiles.csv')
    df2.filter(items=['bucket', 'filename']).style.format({'bucket': make_clickable_both})
except:
    print("No Bucket Found")

# ### Section 3.3 Extraction of dubious files (File Path: output/dubousfiles.txt)

# In[ ]:


dfDubiousFile = []
failedConnected = []
for x in range(len(dfFileBucket)):
    print(str(x) + " Files Scanned, Remaining" + str(len(dfFileBucket) - x))
    print("Scanning: " + dfFileBucket.iloc[x, 5])
    print(dfDubiousFile)
    clear_output(wait=True)
    os.system('cls')
    try:
        opener = urllib.request.build_opener()
        data = opener.open(dfFileBucket.iloc[x, 5])
        if any(s in data for s in keyFileWorldList):
            dfDubiousFile.append(dfFileBucket[x, 5])
    except:
        failedConnected.append(dfFileBucket.iloc[x, 5])
        continue
if len(dfDubiousFile) == 0:
    print("No dubious files found")
else:
    print(
        "Following links included dubious words in keyFileWorldList")  # Please view Section 0. configuration for keyFileWorldList
    with open('result/' + entityName + '/' + searchDomain + '/output/dubiouswords.txt', 'w') as f:
        for item in dfDubiousFile:
            f.write("%s\n" % item)
if len(failedConnected) != 0:
    print("In addition, following links encountered connection error and have been recorded to logs/failedConnect.txt")
    with open('result/' + entityName + '/' + searchDomain + '/logs/failedConnect.txt', 'w') as g:
        for item in failedConnected:
            g.write("%s\n" % item)
dfDubiousFile

# ### Section 4 Export to same Excel
#

# In[23]:


for searchDomain in searchDomains:
    all_files = glob.glob('result/' + entityName + '/' + searchDomain + '/output/*.csv')
    writer = pandas.ExcelWriter('result/' + entityName + '/consolidatedResult.xlsx', engine='xlsxwriter')
    for f in all_files:
        print("Reading CSV: " + os.path.basename(f))
        os.system(' cls ')
        # note6
        try:
            csvCon = pandas.read_csv(f)
            csvCon.to_excel(writer, sheet_name=os.path.basename(f))
        except:
            print('%s fail!' % f)
        # note6 end
    try:
        print("Success")
        writer.save()
    except:
        print("Failed")

   