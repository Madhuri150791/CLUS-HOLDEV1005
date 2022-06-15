#
# Generated FMC REST API
#

import json
import sys
import csv
import requests
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

############################################################################################
##              Define Variables
############################################################################################
def getPolicyName():
    readfile = open("details.json", "r")
    details = json.loads(readfile.read().replace("\n", ''))
    return details["policyname"]
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
        print("Generating Authentication Token...................")
        r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(getUserName(), getPassword()),
                          verify=False)
        auth_headers = r.headers
        auth_token = auth_headers.get('X-auth-access-token', default=None)
        if auth_token == None:
            print("auth_token not found. Exiting...")
            sys.exit()
    except Exception as err:
        print("Error in generating auth token --> " + str(err))
        sys.exit()

    headers['X-auth-access-token'] = auth_token
    print(headers)
    return (headers)


############################################################################################
##              Create a new ACP
############################################################################################

def createnewACP(name):
    #print("Create new ACP")
    api_path = "/api/fmc_config/v1/domain/" + getDomain_uuid() + "/policy/accesspolicies/" # param
    # print(api_path)
    url = getServer() + api_path
    if (url[-1] == '/'):
        url = url[:-1]
    #print(url)
    readfile = open("policyformat.json", "r")
    policy=json.loads(readfile.read().replace("\n",''))
    policy_dat={"name": name}
    policy.update(policy_dat)
    policy=json.dumps(policy)
    print(url)
    r = requests.post(url, data=policy, headers=getaccesstoken(), verify=False)
    status_code = r.status_code
    print(status_code)
    resp = r.text
    if (status_code == 201):
        json_resp = json.loads(resp)
        print("Access Policy Create was successful.........for %s" % (json_resp["name"]))
        # print(json.dumps(json_resp, sort_keys=True, indent=4, separators=(',', ': ')))
        return json_resp["id"]
    else:
        #r.raise_for_status()
        print("Status code:-->" + str(status_code))
        print("Error occurred in PUT --> " + str(resp))
        return ("-1")




############################################################################################
##              Copy Rules to New Policy
############################################################################################


def putrule(accessrule):
    #print("inputrule")
    if get_MergedAccessPolicy_UUID()== " ":
        readfile = open("details.json", "r")
        details = json.loads(readfile.read().replace("\n", '').replace("'",'"'))
        uuid=createnewACP(getPolicyName())
        print("uuid is = "+uuid)
        if uuid!="-1":
            details["mergedaccesspolicy_uuid"]=uuid
            readfile = open("details.json", "w")
            json.dump(details,readfile)
            readfile.close()
            readfile = open("details.json", "r")
            converted=readfile.read().replace("'", '"').replace("True", '"true"').replace("False", '"false"')
            readfile = open("details.json", "w")
            readfile.write(converted)
            readfile.close()


        else:
            exit(-1)
    api_path = "/api/fmc_config/v1/domain/" + getDomain_uuid() + "/policy/accesspolicies/" + get_MergedAccessPolicy_UUID() + "/accessrules?bulk=true&category=310B-INT-BHS"   # param
    #print(api_path)
    url = getServer() + api_path
    if (url[-1] == '/'):
        url = url[:-1]
    #print(json.dumps(accessrule))
    test=open("text.txt","w")
    json.dump(accessrule,test)
    r = requests.post(url, data=json.dumps(accessrule), headers=getaccesstoken(), verify=False)
    status_code = r.status_code
    resp = r.text
    if (status_code == 200):
        json_resp = json.loads(resp)
        print("Put was successful.........for %s" % (json_resp["name"]))
        # print(json.dumps(json_resp, sort_keys=True, indent=4, separators=(',', ': ')))
    else:
        r.raise_for_status()
        print("Status code:-->" + str(status_code))
        print("Error occurred in PUT --> " + resp)
    print(status_code)
    return (status_code)


def putruleinnewacp(getfile,filterfile,nooutput):
    readfile = open(filterfile, "r")  # Place the file here which is obtained from the GET operation
    rulesnotput = open(nooutput, "w")
    i = 0
    count = 0
    length = sum(1 for line in open(getfile))
    readfile.seek(0)
    accessrule = []
    print("Reading the GET file.............................")
    for line in readfile:
        #print(line)
        data_json = json.loads(line)
        #put_data = {"logEnd": 'true'}
        #data_json.update(put_data)
        # print(json.dumps(data_json, sort_keys=True, indent=4, separators=(',', ': ')))
        try:
            if count == 990:
                count = 0
                #print(accessrule)
                status_code = putrule(accessrule)
                accessrule=[]
                count += 1
                accessrule.append(data_json)
                print(count)

            else:
                count += 1
                accessrule.append(data_json)

        except requests.exceptions.HTTPError as err:
            print("Error in connection --> " + str(err))
            rulesnotput.write(data_json["name"])
            if status_code == 401:  # This mean the access token is expired
                headers = getaccesstoken()
            if status_code == 429:
                time.sleep(5)

    if count!=0:
        count==0
        try:
            #print("calling putrule %s"%(accessrule))
            status_code = putrule(accessrule)
            if status_code == 201:
                print("LAST batch done fine in connection --> ")
            rulesnotput.write(data_json["name"])
            if status_code == 401:  # This mean the access token is expired
                headers = getaccesstoken()
            if status_code == 429:
                time.sleep(5)
            if status_code == 400:
                print("Check your Payload, it might contain some duplicate objects in rule name")
        except requests.exceptions.HTTPError as err:
            print(err)




