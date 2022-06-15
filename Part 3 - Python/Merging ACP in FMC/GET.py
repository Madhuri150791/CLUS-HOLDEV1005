#
# Generated FMC REST API
# There is no API available for GETALL funnction in FMC even in 6.6.x
#

import json
import sys
import requests
import csv
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
############################################################################################
##              Define Variables
############################################################################################
def getServer():
    readfile = open("details.json", "r")
    details=json.loads(readfile.read().replace("\n",''))
    return details["server"]
def getUserName():
    readfile = open("details.json", "r")
    details=json.loads(readfile.read().replace("\n",''))
    return details["username"]
def getPassword():
    readfile = open("details.json", "r")
    details=json.loads(readfile.read().replace("\n",''))
    return details["password"]
def getDomain_uuid():
    readfile = open("details.json", "r")
    details=json.loads(readfile.read().replace("\n",''))
    return details["domain_uuid"]
def getServer():
    readfile = open("details.json", "r")
    details=json.loads(readfile.read().replace("\n",''))
    return details["server"]
def get_AccessPolicy_UUID():
    readfile = open("details.json", "r")
    details = json.loads(readfile.read().replace("\n", ''))
    return details["accesspolicy_uuid"]
def get_MergedAccessPolicy_UUID():
    readfile = open("details.json", "r")
    details = json.loads(readfile.read().replace("\n", ''))
    return details["mergedaccesspolicy_uuid"]
def geresponse():
    readfile = open("details.json", "r")
    details = json.loads(readfile.read().replace("\n", ''))
    return details["r"]

############################################################################################
##              Generate Access Token
############################################################################################
def getaccesstoken():

    headers = {'Content-Type': 'application/json'}
    api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
    auth_url = getServer() + api_auth_path
    try:
        #print("Generating Authentication Token...................")
        r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(getUserName(), getPassword()),
                          verify=False)
        auth_headers = r.headers
        auth_token = auth_headers.get('X-auth-access-token', default=None)
        if auth_token == None:
            #print("auth_token not found. Exiting...")
            sys.exit()
    except Exception as err:
        #print("Error in generating auth token --> " + str(err))
        sys.exit()

    headers['X-auth-access-token'] = auth_token

    return (headers)
def getrules(filename):
    policies = get_AccessPolicy_UUID()
    for policy in policies:
        print("Policy ID : %s" % policy)
        getaccessrule(filename,policy)

def getaccessrule(filename,policy):
        api_path = "/api/fmc_config/v1/domain/" + getDomain_uuid() + "/policy/accesspolicies/" + policy + "/accessrules"  # param
        url = getServer() + api_path
        if (url[-1] == '/'):
            url = url[:-1]
        page = 0
        # GET OPERATION
        fwrite = open(filename, 'a')
        # rulenotget=open("Rules_Not_Present.txt","w")
        wwrite = csv.writer(fwrite, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
        try:
            r = requests.get(url, headers=getaccesstoken(), verify=False)
            status_code = r.status_code
            responses = r.json()
            resp = r.text
            if (status_code == 200):
                # print("GET successful. Response data --> ")
                print("Initial Page:")
                json_resp = json.loads(resp)
                if responses["links"] == {}:
                    print(responses.text)
                    pass
                else:
                    k=0
                    headers=getaccesstoken()
                    for item in responses["items"]:
                        k+=1
                        #print("fetching rule ..... %s"%(k))
                        api_path = "/api/fmc_config/v1/domain/" + getDomain_uuid() + "/policy/accesspolicies/" + policy + "/accessrules/" + \
                                   item["id"]  # param

                        url = getServer() + api_path
                        if (url[-1] == '/'):
                            url = url[:-1]
                        try:

                            r = requests.get(url, headers=headers, verify=False)
                            status_code = r.status_code
                            res = r.json()
                            resp = r.text
                            if (status_code == 200):
                                #print("GET successful. Response data --> ")
                                page +=1
                                json.dump(res, fwrite)
                                fwrite.write("\n")
                                json_resp = json.loads(resp)

                            else:
                                r.raise_for_status()
                                print("Error occurred in GET --> " + resp)
                        except requests.exceptions.HTTPError as err:
                            print("Error in connection --> " + str(err))
                            if status_code == 401:  # This mean the access token is expired
                                headers = getaccesstoken()
                            if status_code == 429:
                                time.sleep(5)
                        finally:
                            if r: r.close()
                        # wwrite.writerow(mylist)
                try:
                    if 'next' in responses["paging"]:
                        print("Found Pages:")
                        while True:
                            print(responses["paging"]["next"][0])
                            urlx = responses["paging"]["next"][0]
                            headers=getaccesstoken()
                            response1 = requests.get(urlx, headers=headers,
                                                     verify=False)  # this is to get list of all Service Group Object
                            responses1 = response1.json()
                            #print(responses1)

                            if response1.status_code != 400 and response1.status_code != 401:

                                if responses1["links"] == {}:
                                    pass
                                else:
                                    for item in responses1["items"]:

                                        api_path = "/api/fmc_config/v1/domain/" + getDomain_uuid() + "/policy/accesspolicies/" + policy + "/accessrules/" + \
                                                   item["id"]  # param
                                        url = getServer() + api_path
                                        if (url[-1] == '/'):
                                            url = url[:-1]
                                        try:
                                            r = requests.get(url, headers=headers, verify=False)
                                            status_code = r.status_code
                                            res = r.json()
                                            if (status_code == 200):
                                                #print("GET successful. Response data --> ")
                                                page +=1
                                                json.dump(res, fwrite)
                                                fwrite.write("\n")
                                            else:
                                                r.raise_for_status()
                                                print("Error occurred in GET --> " + resp)
                                        except requests.exceptions.HTTPError as err:
                                            print("Error in connection --> " + str(err))
                                            if status_code == 401:  # This mean the access token is expired
                                                headers = getaccesstoken()
                                            if status_code == 429:
                                                time.sleep(5)
                                        finally:
                                            if r: r.close()
                                        # wwrite.writerow(mylist)
                                #print(responses1["paging"])
                                responses = responses1
                                '''if 'next' not in responses['paging']:
                                    print("iam here")
                                    break'''

                    elif int(responses['pages']) < page:
                        print(page)
                        print(responses['pages'])
                        for item in responses["items"]:

                            api_path = "/api/fmc_config/v1/domain/" + getDomain_uuid() + "/policy/accesspolicies/" + policy + "/accessrules/" + \
                                       item["id"]  # param
                            url = getServer() + api_path
                            if (url[-1] == '/'):
                                url = url[:-1]
                            try:
                                r = requests.get(url, headers=headers, verify=False)
                                status_code = r.status_code
                                res = r.json()
                                if (status_code == 200):
                                    print("GET successful. Response data --> ")
                                    page +=1
                                    json.dump(res, fwrite)
                                    fwrite.write("\n")
                                else:
                                    r.raise_for_status()
                                    print("Error occurred in GET --> " + resp)
                            except requests.exceptions.HTTPError as err:
                                print("Error in connection --> " + str(err))
                                if status_code == 401:  # This mean the access token is expired
                                    headers = getaccesstoken()
                                if status_code == 429:
                                    time.sleep(5)
                            finally:
                                if r: r.close()

                except:
                    pass

            else:
                r.raise_for_status()
                print("Error occurred in GET --> " + resp)
        except requests.exceptions.HTTPError as err:
            print("Error in connection --> " + str(err))
        #finally:
            #if r: r.close()
        fwrite.close()




#getaccessrule("accessrule.txt")
