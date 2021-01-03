# !/usr/bin/env python

import os
import requests
import json
import time
import re
import sys

class ZoomEye(object):
    def __init__(self, username="lazcrag23@gmail.com", password="S9CvUbbsny"):
        self.username = username
        self.password = password

        self.access_token = ''
        # self.zoomeye_login_api = "https://api.zoomeye.org/user/login"
        # self.zoomeye_dork_api = "https://api.zoomeye.org/{}/search"

        self.ip_port_list = []

        self.ipfile = sys.argv[1]

    def login(self):
        """
        Prompt to input account name and password
        :return: None
        """
        #self.username = input('[-] input : username :').strip()
        #self.password = input('[-] input : password :').strip()
        # self.username = "lazcrag23@gmail.com"  #sys.argv[]
        # self.password = "S9CvUbbsny"           #sys.argv[]

        #print('[*] try to login ...')
        data = {
            'username': self.username,
            'password': self.password
        }

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'
        }

        data_encoded = json.dumps(data)
        try:
            resp = requests.post(url='https://api.zoomeye.org/user/login', data=data_encoded, headers=headers)

            #print (resp)
            r_decoded = json.loads(resp.text)

            access_token = r_decoded['access_token']
            self.access_token = access_token
            #print("ok?")
        except:
            #print('[-] info : username or password is wrong, please try again ')
            print ("wrong?")
            exit()


    def get_ip_list(self):
        pattern = re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
        with open(self.ipfile) as f:
            file_data = f.read()
        ip_list = pattern.findall(file_data)
        # Remove duplicate IP addresses
        ip_list_new = []
        for i in ip_list:
            if i not in ip_list_new:
                ip_list_new.append(i)
        return ip_list_new

    def search(self):

        if not self.access_token:
            self.login()

        headers = {
            'Authorization': 'JWT ' + self.access_token,
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'
        }



        api = 'https://api.zoomeye.org/both/search'

        queryips = self.get_ip_list()

        for ip in queryips:
            #print(ip)


            # print('[+] query IP==>', ip)


            #resp = requests.get(api, headers=headers, params={"query": query, "page": page})
            resp = requests.get(api, headers=headers, params={"history": "true", "ip": ip})
            #print (resp.text)
            if resp.text == "":
                continue

            r_decoded = json.loads(resp.text)

            # file = 'testresult.txt'
            # with open(file, encoding="utf8") as f:
            #     #s = f.read()
            #     #r_decoded = json.loads(json.dumps(eval(s)))
            #      #r_decoded = json.loads(json.dumps(eval(s)))
            # #with open(file) as f:
            #     r_decoded = json.load(f)
            #     import pdb; pdb.set_trace()
            # print (r_decoded)
            for x in r_decoded["data"]:
                #print (x)
                # print("++++++++")
                # ip_str
                # host.get('ip_str', 'n/a')

                ip_str = ip
                # print(ip_str)
                # curtime
                # time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(time.time()))
                curtime = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(time.time()))
                # print(curtime)
                # timestamp
                # item.get('timestamp', 'n/a')


                timestamp = x.get('timestamp',None)
                # print(timestamp)

                # item['port']
                port = x.get('portinfo').get('port',None) if 'portinfo' in x else None
                # print(port)

                # item['_shodan']['module']
                protocol = x.get('portinfo').get('service',None) if 'portinfo' in x else None
                # print(protocol)

                # org
                # host.get('org', 'n/a')
                org = ""
                org1 = x.get('geoinfo').get('organization',None) if 'geoinfo' in x else None
                org_CN = x.get('geoinfo').get('organization_CN',None) if 'geoinfo' in x else None
                org_zh_CN = x.get('geoinfo').get('organization_zh-CN',None) if 'geoinfo' in x else None
                if (org1 != None):
                    org = org1
                elif(org_CN != None):
                    org = org_CN
                elif(org_zh_CN != None):
                    org = org_zh_CN
                else:
                    org = None
                # print (org)


                # shodanmodule_os
                # str(item['_shodan']['module'])['os']              # "None"
                os = x.get('portinfo').get('os',None) if 'portinfo' in x else None
                # print(os)

                # product
                # item.get('product', 'n/a')
                service = x.get('portinfo').get('product',None) if 'portinfo' in x else None
                # print (service)

                # cpe
                # item.get('cpe', 'n/a')
                # temp = x.get('raw_data').split('\r\n') if 'raw_data' in x else None
                # if temp != None:
                #     # server_file = open('servers.txt','a+')
                #     server = [ele for ele in temp if 'Server' in ele]
                #     #  tmp work
                #     if len(server) == 0:
                #         cpe = None
                #     # else:
                #     #     cpe = server[-1].split(': ')[1]
                #     else:
                #         tmp = server[0].split(': ')
                #         cpe = None if len(tmp) == 0 else tmp[-1]
                #     # server_file.write(str(server))
                #     # server_file.write(': ')
                #     # server_file.write(str(cpe))
                #     # server_file.write('\r\n')
                #     # server_file.close()
                # else:
                #     cpe = None
                # print (cpe)

                cpe = None

                # http_title
                # http = item.get('http', 'n/a')
                # str(http.get('title', 'n/a'))
                title = x.get('portinfo').get('title',None) if 'portinfo' in x else None
                # print (title)

                # http_server
                # http = item.get('http', 'n/a')
                # http.get('server', 'n/a')
                # "None"
                version = x.get('portinfo').get('version',None) if 'portinfo' in x else None
                # print (version)

                # http_redirects
                # str(http.get('redirects', 'n/a'))[:1024]
                http_redirects = None

                # ssl_all

                # ssl_value = None
                #
                # if (not 'ssl' in x.keys()) and (not 'ssl_new' in x.keys()):
                #     pass
                # elif ('ssl' in x.keys()) and (not 'ssl_new' in x.keys()):
                #     if (x['ssl']!= '') and (x['ssl']!= None): ssl_value=x['ssl']
                # elif (not 'ssl' in x.keys()) and ('ssl' in x.keys()):
                #     if (x['ssl_new']!= '') and (x['ssl_new']!= None): ssl_value=x['ssl_new']
                # elif ('ssl' in x.keys()) and ('ssl_new' in x.keys()):
                #     if (x['ssl'] != '') and (x['ssl'] != None): ssl_value = x['ssl']
                #     elif (x['ssl_new']!= '') and (x['ssl_new']!= None): ssl_value=x['ssl_new']
                #     else: pass
                # else:
                #     pass

                ssl_list = ['ssl_new', 'ssl']
                exclude = ['', None]
                ssl_value = [x.get(sd, '') for sd in ssl_list]
                target_value = None
                for val in ssl_value:
                    if not val in exclude:
                        target_value = val
                        break

                # print (target_value)

                # f = open('tmp.txt', 'w')
                # f.write(target_value)
                # f.close()
                # with open('tmp.txt') as f:
                #     lines = f.readlines()
                #     my_dic = {line[:line.index(':')].strip(): line[line.index(':') + 1:].strip() for line in lines if line}
                #
                # print (my_dic)
                #174.37.161.38

                tmp_target = {'Certificate:': None, 'Data:': None, 'Version: ': None, 'Serial Number: ': None,
                              'Signature Algorithm: ': None, 'C=': None, 'ST=': None, 'L=': None, 'O=': None, 'OU=': None,
                              'CN=': None, 'Not Before: ': None, 'Not After : ': None, 'Subject Public Key Info:': None,
                              'Public Key Algorithm: ': None, 'Public-Key: ': None, 'Exponent: ': None,
                              'X509v3 extensions:': None, 'X509v3 Subject Alternative Name:': None,
                              'X509v3 Key Usage: ': None, 'X509v3 Extended Key Usage:': None,
                              'X509v3 Basic Constraints:': None, 'Authority Information Access:': None, 'OCSP - URI:': None,
                              'CA Issuers - URI:': None, 'X509v3 Certificate Policies:': None,
                              'X509v3 CRL Distribution Points:': None, 'Full Name:': None,
                              'X509v3 Authority Key Identifier:': None, 'keyid:': None,
                              'X509v3 Subject Key Identifier:': None}

                subject_target = {'O=': None, 'CN=': None}

                if (target_value == '') or (target_value == None):
                    pass
                else:
                    for target in tmp_target:
                        if target in target_value:
                            start = target_value.index(target) + len(target)
                            tmp_str = target_value[start:]
                            end1 = tmp_str.index(',') if ',' in tmp_str else 9999999
                            end2 = tmp_str.index('\n') if '\n' in tmp_str else 9999999
                            if end1 <= end2:
                                end = end1
                            else:
                                end = end2
                            tmp_target[target] = target_value[start:(start + end)]
                            # print(target + tmp_target[target])


                    temp2 = target_value.split("\n")
                    subject = [ele for ele in temp2 if "Subject:" in ele]
                    if len(subject) == 0:
                        subject = None
                    else:
                        for t in subject_target:
                            if t in subject:
                                sub_start = subject.index(t) + len(t)
                                tmp_subjstr = subject[sub_start:]
                                sub_end1 = tmp_subjstr.index(',') if ',' in tmp_subjstr else 9999999
                                sub_end2 = tmp_subjstr.index('\n') if '\n' in tmp_subjstr else 9999999
                                if sub_end1 <= sub_end2:
                                    sub_end = sub_end1
                                else:
                                    sub_end = sub_end2
                                subject_target[t] = subject[sub_start:(sub_start + sub_end)]

                SSLAcceptableCertificationAuthorities = tmp_target["Certificate:"]
                # print(SSLAcceptableCertificationAuthorities)

                SSLALPN= None

                SSLCertExpired = None

                SSLCertExpirationDate = tmp_target["Not After : "]
                # print(SSLCertExpirationDate)

                sSSLCertExtensions = None

                SSLCertFingerprintinSHA1 = None

                SSLCertFingerprintinSHA256 = None

                SSLCertIssuedOn = tmp_target["Data:"]
                # print(SSLCertIssuedOn)

                SSLCertIssuerCountryName = tmp_target["C="]
                #print(SSLCertIssuerCountryName)

                SSLCertIssuerCommonName = tmp_target["CN="]
                # print(SSLCertIssuerCommonName)

                SSLCertIssuerLocality = tmp_target["L="]

                SSLCertIssuerOrganization = tmp_target["O="]
                # print(SSLCertIssuerOrganization)

                SSLCertIssuerOrganizationalUnit = tmp_target["OU="]
                # print(SSLCertIssuerOrganization)

                SSLCertIssuerStateorProvinceName = tmp_target["ST="]
                # print(SSLCertIssuerStateorProvinceName)

                SSLCertPublicKeyBits = tmp_target["Public-Key: "]
                # print(SSLCertPublicKeyBits)

                SSLCertPublicKeyType = tmp_target["Public Key Algorithm: "]
                # print(SSLCertPublicKeyType)

                SSLCertSerial = tmp_target["Serial Number: "]
                # print (SSLCertSerial)

                SSLCertSignatureAlgorithm = tmp_target["Signature Algorithm: "]
                # print (SSLCertSignatureAlgorithm)


                # subject_target = {'O=': None, 'CN=': None}
                # temp2 = target_value.split("\n")
                # subject = [ele for ele in temp2 if "Subject:" in ele]
                # if len(subject) == 0:
                #     subject = None
                # else:
                #     for t in subject_target:
                #         if t in subject:
                #             sub_start = subject.index(t) + len(t)
                #             tmp_subjstr = subject[sub_start:]
                #             sub_end1 = tmp_subjstr.index(',') if ',' in tmp_subjstr else 9999999
                #             sub_end2 = tmp_subjstr.index('\n') if '\n' in tmp_subjstr else 9999999
                #             if sub_end1 <= sub_end2:
                #                 sub_end = sub_end1
                #             else:
                #                 sub_end = sub_end2
                #             subject_target[t] = subject[sub_start:(sub_start + sub_end)]

                SSLCertSubjectCommonName = subject_target["CN="]
                # print (SSLCertSubjectCommonName)

                SSLCertSubjectOrganizationalUnit = subject_target["O="]
                # print (SSLCertSubjectOrganizationalUnit)


                SSLCertVersion = tmp_target["Version: "]
                # print(SSLCertVersion)

                SSLChain = None

                SSLCipherBits = None

                SSLCipherName = None

                SSLCipherVersion = None

                SSLTLSExtension = None

                SSLVersions = None
                #print(SSLVersions)
                # item.get('ssl', 'n/a')
                # ssl.get('cert', 'n/a')
                # sslcert.get('fingerprint', 'n/a')
                # sslcert.get('pubkey', 'n/a')
                # sslcert.get('subject', 'n/a')

                portvulns_all = None

                # str(vulns[i]) + ";" + str(item['vulns'][vulns[i]]['cvss']) + ";" + str(
                #     item['vulns'][vulns[i]]['references']) + ";" + str(item['vulns'][vulns[i]]['summary']) + ";" + str(
                #     item['vulns'][vulns[i]]['verified'])

                nocve = 0

                # host.get('vulns', 'n/a')
                # len(vulns)

                cvss = 0

                # dictcorr = {"None": 0}
                # dictcorr.update({str(vulns[i]): float(item['vulns'][vulns[i]]['cvss'])})
                # max(dictcorr.values())

                corrkey = None

                # dictcorr = {"None": 0}
                # dictcorr.update({str(vulns[i]): float(item['vulns'][vulns[i]]['cvss'])})
                # max(dictcorr, key=dictcorr.get)


                #print(x['ip'], ':', x['portinfo']['port'])
                #self.ip_port_list.append(x['ip'] + ':' + str(x['portinfo']['port']))
        #self.save_result()

                str_all = (str(ip_str) + "\t" + str(curtime) + "\t" + str(timestamp) + "\t" + str(port) + "\t" + str(protocol) + "\t" + str(org) + "\t" + str(os) + "\t" + str(service) + "\t" + str(cpe) + "\t" + str(title) + "\t" + str(version) + "\t" + str(http_redirects) + "\t" +
                            str(SSLAcceptableCertificationAuthorities) + "\t" +
                            str(SSLALPN) + "\t" +
                            str(SSLCertExpired) + "\t" +
                            str(SSLCertExpirationDate)+ "\t" +
                            str(sSSLCertExtensions) + "\t" +
                            str(SSLCertFingerprintinSHA1) + "\t" +
                            str(SSLCertFingerprintinSHA256) + "\t" +
                            str(SSLCertIssuedOn) + "\t" +
                            str(SSLCertIssuerCountryName) + "\t" +
                            str(SSLCertIssuerCommonName) + "\t" +
                            str(SSLCertIssuerLocality) + "\t" +
                            str(SSLCertIssuerOrganization) + "\t" +
                            str(SSLCertIssuerOrganizationalUnit) + "\t" +
                            str(SSLCertIssuerStateorProvinceName) + "\t" +
                            str(SSLCertPublicKeyBits) + "\t" +
                            str(SSLCertPublicKeyType) + "\t" +
                            str(SSLCertSerial) + "\t" +
                            str(SSLCertSignatureAlgorithm) + "\t" +
                            str(SSLCertSubjectCommonName) + "\t" +
                            str(SSLCertSubjectOrganizationalUnit) + "\t" +
                            str(SSLCertVersion) + "\t" +
                            str(SSLChain) + "\t" +
                            str(SSLCipherBits) + "\t" +
                            str(SSLCipherName) + "\t" +
                            str(SSLCipherVersion) + "\t" +
                            str(SSLTLSExtension) + "\t" +
                            str(SSLVersions) + "\t"+
                            str(portvulns_all) + "\t"+
                            str(nocve) + "\t"+
                            str(cvss) + "\t" +
                            str(corrkey) + "\t")

                print(str_all)
        pass

    # def save_result(self):
    #
    #     xtime = time.strftime("[%Y-%m-%d][%H.%M.%S]")
    #     ip_port_list_file = '{}.txt'.format(xtime)
    #
    #     with open(ip_port_list_file, 'w') as fw:
    #         for line in self.ip_port_list:
    #             fw.write(line + '\n')
    #     pass


if __name__ == '__main__':
    zoomeye = ZoomEye()
    zoomeye.search()
    pass
