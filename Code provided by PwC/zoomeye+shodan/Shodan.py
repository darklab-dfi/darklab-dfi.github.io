"""
Created 2019.1.5 by IsTr33

Modified 2019.3.31
Fixed the IP invalid bug.
"""

# -*- coding: UTF-8 -*-
import shodan
import time
import requests
from bs4 import BeautifulSoup
from importlib import reload
import re
import sys
reload(sys)
#sys.setdefaultencoding('utf8')

#Fill in Shodan API Key
SHODAN_API_KEY = "RifB5RHIyi80O3BZsz3V8yUHEupjRu1T"

api = shodan.Shodan(SHODAN_API_KEY)

def get_ip_list(file):
    pattern = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
    with open(file) as f:
        file_data = f.read()
    ip_list = pattern.findall(file_data)
    # Remove duplicate IP addresses
    ip_list_new = []
    for i in ip_list:
        if i not in ip_list_new:
            ip_list_new.append(i)
    return ip_list_new
	 
def get_http_title(ip, port, protocol, flag=0):
    url = protocol+"://"+ip+":"+port
    try:
        res = requests.get(protocol+"://"+ip+":"+port, verify=False)
        
        #When the page encoding is "ISO-8859-1", the actual page encoding format cannot be confirmed. If an exception occurs, set the flag, switch the encoding format and try again.
        if res.encoding == 'ISO-8859-1':
            if flag == 0:
                res.encoding = 'utf-8'
            elif flag ==1:
                res.encoding = 'gbk'

        #Find HTTP title in the page
        pattern = re.compile(r"(?i)<title>.*?</title>")
        if pattern.findall(res.text):
            title_list = pattern.findall(res.text)
            title = title_list[0]
            title = title[7:-8]
        else:
            title = "[!] HTTP title not found."
    except Exception as e:
        title = "[!] Can not connect."
    return title		 		 
		 
		 
def search_ip_ports(ip):
    host = ''
    port = ''
    module = ''
    str_all = ''
    try:
        # Lookup the host
        host = api.host(ip,history=False)
    except shodan.APIError as e:
        if re.search("No information available for that IP.",str(e)):
            print(ip+"\t [!] No result.")
            #print("--------------------------------------------------------------------------------")
            return
        if re.search("Invalid IP",str(e)):
            print(ip+"\t [!] IP invalid.")
            #print("--------------------------------------------------------------------------------")
            return

    # Print general info
    #print("""{} \t {} \t {}
#""".format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))

    # Print all banners
    for item in host['data']:
       
        timestamp = item.get('timestamp','n/a')
        curtime = time.strftime('%Y-%m-%dT%H:%M:%S',time.localtime(time.time()))
        ip_str = host.get('ip_str', 'n/a')
        product = item.get('product','n/a')
        shodanmodule = str(item['_shodan']['module'])
        try:
            shodanmodule_os = item[shodanmodule]['os']
        except KeyError:
            shodanmodule_os = 'None'
        org = host.get('org', 'n/a')
        cpe = item.get('cpe','n/a')
        vulns = host.get('vulns','n/a')
        vulnscount= len(vulns)
        portvulns_all = ""
        nocve = vulnscount
        dictcorr = {"None":0}
        cvss = 0

		 		 # Get all vulnerbilities field and concat to a single string
        for i in range(len(vulns)):
            try:
               portvulns = str(vulns[i])+";"+str(item['vulns'][vulns[i]]['cvss'])+";"+str(item['vulns'][vulns[i]]['references'])+";"+str(item['vulns'][vulns[i]]['summary'])+";"+str(item['vulns'][vulns[i]]['verified'])
               dictcorr.update({str(vulns[i]):float(item['vulns'][vulns[i]]['cvss'])})
               portvulns_all = portvulns_all + ";" + portvulns
            except KeyError:
               portvulns = "None"
               nocve = 0
        cvss = max(dictcorr.values())
        corrkey = max(dictcorr, key=dictcorr.get)
        # Get http server
        http = item.get('http','n/a')
        try:
            http_server = http.get('server','n/a')
        except AttributeError:
            http_server = "None"
        try:
            http_redirects = str(http.get('redirects','n/a'))
            http_redirects = http_redirects[:1024]
        except AttributeError:
            http_redirects = "None"
		 		 		 
		 		 # Get SSL Cert
        ssl_all = ""
        try:
            ssl = item.get('ssl','n/a')
        except AttributeError:
            ssl = "None"
        try:
            sslcert = ssl.get('cert','n/a')
        except AttributeError:
            sslcert = "None"
        try:
            sslcertfingerprint = sslcert.get('fingerprint','n/a')
        except AttributeError:
            sslcertfingerprint = "None"
        try:
            sslcertissuer = sslcert.get('issuer','n/a')
        except AttributeError:
            sslcertissuer = "None"
        try:
            sslcert_pubkey = sslcert.get('pubkey','n/a')
        except AttributeError:
            sslcert_pubkey = "None"
        try:
            sslcipher = ssl.get('cipher','n/a')
        except AttributeError:
            sslcipher = "None"
        try:
            sslcertsubject = sslcert.get('subject','n/a')
        except AttributeError:
            sslcertsubject = "None"
        try:
            sslcipher = ssl.get('cipher','n/a')
        except AttributeError:
            sslcipher = "None"
        try:
            ssl_acceptable_cas = str(ssl.get('acceptable_cas','n/a'))
            ssl_acceptable_cas = ssl_acceptable_cas[:512]
        except AttributeError:
            ssl_acceptable_cas = "None"
        try:
             ssl_alpn=ssl.get('alpn','n/a')
        except AttributeError:
            ssl_alpn = "None"
        try:
            sslcert_expired = sslcert.get('expired','n/a')
        except AttributeError:
            sslcert_expired = "None"
        try:
            sslcert_expires = sslcert.get('expires','n/a')
        except AttributeError:
            sslcert_expires = "None"		 		 		 
        try: 
            sslcert_extensions = sslcert.get('extensions','n/a')
        except AttributeError:
            sslcert_extensions = "None"		 		 		 
        try:            
            sslcertfingerprint_sha1 = sslcertfingerprint.get('sha1','n/a')
        except AttributeError:
            sslcertfingerprint_sha1 = "None"
        try:
            sslcertfingerprint_sha256 = sslcertfingerprint.get('sha256','n/a')
        except AttributeError:
            sslcertfingerprint_sha256 = "None"
        try:
            sslcert_issued = sslcert.get('issued','n/a')
        except AttributeError:
            sslcert_issued = "None"		 		 		 
        try:
            sslcertissuer_C = sslcertissuer.get('C','n/a')
        except AttributeError:
            sslcertissuer_C = "None"		 		 		 
        try:
            sslcertissuer_CN = sslcertissuer.get('CN','n/a')
        except AttributeError:
            sslcertissuer_CN = "None"		 		 		 
        try:
            sslcertissuer_L = sslcertissuer.get('L','n/a')
        except AttributeError:
            sslcertissuer_L = "None"		 		 		 
        try:
            sslcertissuer_O = sslcertissuer.get('O','n/a')
        except AttributeError:
            sslcertissuer_O = "None"		 		 		 
        try:
            sslcertissuer_OU = sslcertissuer.get('OU','n/a')
        except AttributeError:
            sslcertissuer_OU = "None"		 		 		 
        try:
            sslcertissuer_ST = sslcertissuer.get('ST','n/a')
        except AttributeError:
            sslcertissuer_ST = "None"
        try:
            sslcert_pubkeybits = sslcert_pubkey.get('bits','n/a')
        except AttributeError:
            sslcert_pubkeybits = "None"
        try:
            sslcert_pubkeytype = sslcert_pubkey.get('type','n/a')
        except AttributeError:
            sslcert_pubkeytype = "None"		 		 		 
        try:
            sslcert_serial = sslcert.get('serial','n/a')
        except AttributeError:
            sslcert_serial = "None"		 		 		 
        try:
            sslcert_sig_alg = sslcert.get('sig_alg','n/a')
        except AttributeError:
            sslcert_sig_alg = "None"
        try:
            sslcertsubject_CN = sslcertsubject.get('CN','n/a')
        except AttributeError:
            sslcertsubject_CN = "None"
        try:
            sslcertsubject_OU = sslcertsubject.get('OU','n/a')
        except AttributeError:
            sslcertsubject_OU = "None"		 		 		 
        try:
            sslcert_version = sslcert.get('version','n/a')
        except AttributeError:
            sslcert_version = "None"		 		 		 
        try:
            ssl_chain = ssl.get('chain','n/a')
        except AttributeError:
            ssl_chain = "None"
        try:
            sslcipher_bits = sslcipher.get('bits','n/a')
        except AttributeError:
            sslcipher_bits = "None"		 		 		 
        try:
            sslcipher_name = sslcipher.get('name','n/a')
        except AttributeError:
            sslcipher_name = "None"		 		 		 
        try:
            sslcipher_version = sslcipher.get('version','n/a')
        except AttributeError:
            sslcipher_version = "None"
        try:
            ssl_tlsext = ssl.get('tlsext','n/a')
        except AttributeError:
            ssl_tlsext = "None"
        try:
            ssl_versions = ssl.get('versions','n/a')
        except AttributeError:
            ssl_versions = "None"
        try:
            ssl_all = str(ssl_acceptable_cas)+"\t"+str(ssl_alpn)+"\t"+str(sslcert_expired)+"\t"+str(sslcert_expires)+"\t"+str(sslcert_extensions)+"\t"+str(sslcertfingerprint_sha1)+"\t"+str(sslcertfingerprint_sha256)+"\t"+str(sslcert_issued)+"\t"+str(sslcertissuer_C)+"\t"+str(sslcertissuer_CN)+"\t"+str(sslcertissuer_L)+"\t"+str(sslcertissuer_O)+"\t"+str(sslcertissuer_OU)+"\t"+str(sslcertissuer_ST)+"\t"+str(sslcert_pubkeybits)+"\t"+str(sslcert_pubkeytype)+"\t"+str(sslcert_serial)+"\t"+str(sslcert_sig_alg)+"\t"+str(sslcertsubject_CN)+"\t"+str(sslcertsubject_OU)+"\t"+str(sslcert_version)+"\t"+str(ssl_chain)+"\t"+str(sslcipher_bits)+"\t"+str(sslcipher_name)+"\t"+str(sslcipher_version)+"\t"+str(ssl_tlsext)+"\t"+str(ssl_versions)
        except AttributeError:
            ssl_all = "None"
		     # If module equals HTTP, get the HTTP title
        try:   
            http_title = str(http.get('title','n/a'))
        except AttributeError:
            http_title = "None" 		
        try:
            #Print ip_str,port,_shodan.module,http_title,org,os,http.server,sslcert_issued,sslcert_expires,sslcert_pubkeytype,sslcert_pubkeybits,sslcipher_name,sslcipher_bits,sslcipher_versions,vulnerbilities(cvss;references;summary;verified)
            str_all = (str(ip_str)+"\t"+str(curtime)+"\t"+str(timestamp)+"\t"+str(item['port'])+"\t"+str(item['_shodan']['module'])+"\t"+str(org)+"\t"+str(shodanmodule_os)+"\t"+str(product)+"\t"+str(cpe)+"\t"+str(http_title)+"\t"+str(http_server)+"\t"+str(http_redirects)+"\t"+str(ssl_all)+"\t"+str(portvulns_all)+"\t"+str(nocve)+"\t"+str(cvss)+"\t"+str(corrkey))
            str_all = str_all.replace('\r\n','')
            str_all = str_all.replace('\r','')
            str_all = str_all.replace('\n','')
            print (str_all)
			#print (str(protocol2))
        except UnicodeEncodeError as e:
            #http_title = "\t"+get_http_title(ip, str(item['port']), protocol.group(0), 1)
            str_all = (str(ip_str)+"\t"+str(curtime)+"\t"+str(timestamp)+"\t"+str(item['port'])+"\t"+str(item['_shodan']['module'])+"\t"+str(org)+"\t"+str(shodanmodule_os)+"\t"+str(product)+"\t"+str(cpe)+"\t"+str(http_title.encode("utf-8","surrogatepass"))+"\t"+str(http_server)+"\t"+str(http_redirects.encode("utf-8","surrogatepass"))+"\t"+str(ssl_all.encode("utf-8","surrogatepass"))+str(portvulns_all))
            str_all = str_all.replace('\r\n','')
            str_all = str_all.replace('\r','')
            str_all = str_all.replace('\n','')
            print (str_all)
            #print (str(item['port'])+"\t"+str(item['_shodan']['module'])+http_title.encode("utf-8"))

    #print("--------------------------------------------------------------------------------")

def search_ip_list_ports(iplist):
    for ip in iplist:
        time.sleep(1)
        search_ip_ports(ip)        

def main():
    if len(sys.argv) < 1:
        print("Usage: \n    python ShodanSearch.py \"IPList.txt\"")
        sys.exit()
    ip_list = get_ip_list(sys.argv[1])
    #print(ip_list)
    #print('[*] Total '+str(len(ip_list))+' IP addresses.')
    #print(time.strftime('[*] Search started at %H:%M:%S %a %Y-%m-%d.',time.localtime(time.time())))
    #print("--------------------------------------------------------------------------------")
    #print ('ip_str\tcurtime\ttimestamp\tport\t_shodan.module\torg\tos\tproduct\tcpe\thttp_title\thttp.server\thttp_redirects\tssl_acceptable_cas\tssl_alpn\tsslcert_expired\tsslcert_expires\tsslcert_extensions\tsslcertfingerprint_sha1\tsslcertfingerprint_sha256\tsslcert_issued\tsslcertissuer_C\tsslcertissuer_CN\tsslcertissuer_L\tsslcertissuer_O\tsslcertissuer_OU\tsslcertissuer_ST\tsslcert_pubkeybits\tsslcert_pubkeytype\tsslcert_serial\tsslcert_sig_alg\tsslcertsubject_CN\tsslcertsubject_OU\tsslcert_version\tssl_chain\tsslcipher_bits\tsslcipher_name\tsslcipher_version\tssl_tlsext\tssl_versions\tvulnerbilities(cvss;references;summary;verified......)')
    print ('Host\tRetrieve Time\tTimestamp\tPort\tProtocol\tOrganization\tOperating System\tService\tCommon Platform Enumeration ("CPE")\tWebsite Title\tService Version\tHTTP Redirect\tSSL Acceptable Certification Authorities\tSSL ALPN ("Application-Layer Protocol Negotiation")\tSSL Cert Expired\tSSL Cert Expiration Date\tsSSL Cert Extensions\tSSL Cert Fingerprint in SHA1\tSSL Cert Fingerprint in SHA256\tSSL Cert Issued On\tSSL Cert Issuer Country Name\tSSL Cert Issuer Common Name\tSSL Cert Issuer Locality\tSSL Cert Issuer Organization\tSSL Cert Issuer Organizational Unit\tSSL Cert Issuer State or Province Name\tSSL Cert Public Key Bits\tSSL Cert Public Key Type\tSSL Cert Serial\tSSL Cert Signature Algorithm\tSSL Cert Subject Common Name\tSSL Cert Subject Organizational Unit\tSSL Cert Version\tSSL Chain\tSSL Cipher Bits\tSSL Cipher Name\tSSL Cipher Version\tSSL TLS Extension\tSSL Versions\tVulnerability Details\tNo. Cve\tHighest CVSS\tCorresponding CVE')
    search_ip_list_ports(ip_list)
    #print(time.strftime('[*] Search finished at %H:%M:%S %a %Y-%m-%d.',time.localtime(time.time())))

if __name__ == '__main__':
    main()