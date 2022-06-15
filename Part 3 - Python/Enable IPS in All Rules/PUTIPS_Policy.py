#
# Generated FMC REST API sample script
#

import json
import sys
import csv
import requests
import time
import FMCDetail
###Please provide the details here before running the script################################################################################

server = FMCDetail.server
username = FMCDetail.username
password = FMCDetail.password
domain_uuid=FMCDetail.domain_uuid
accesspolicy_uuid=FMCDetail.accesspolicy_uuid

r = None
headers = {'Content-Type': 'application/json'}
api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
auth_url = server + api_auth_path
try:
    print("Generating Authentication Token...................")
    r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username, password),
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



# PUT OPERATION

readfile=open("filterrule-UWA3.txt","r")#Place the file here which is obtained from the GET operation
rulesnotput=open("Rulesnotput.txt","w")
i=0
length=sum(1 for line in open("accessrule-meralco-sdc-comment.txt"))
readfile.seek(0)
print("Reading the GET file.............................")
for line in readfile:
        
                    data_json = json.loads(line)
                    if data_json["action"]=="ALLOW":
                        
                        put_data = {"ipsPolicy": {
    "type": "IntrusionPolicy",
    "id": "d2f62f8c-9c85-11e8-ad7b-ffa1f65ee055",
    "name": "UWA_IPS_Policy"
  },"logEnd":'true'}
                        data_json.update(put_data)
                    else:
                        pass
                    
                    try:
                        api_path = "/api/fmc_config/v1/domain/" + domain_uuid + "/policy/accesspolicies/" + accesspolicy_uuid + "/accessrules/" + data_json["id"]  # param
                        print(api_path)
                        url = server + api_path
                        if (url[-1] == '/'):
                            url = url[:-1]
                        #print(json.dumps(data_json,sort_keys=True,indent=4, separators=(',', ': ')))
                        r = requests.put(url, data=json.dumps(data_json), headers=headers, verify=False)
                        status_code = r.status_code
                        resp = r.text
                        if (status_code == 200):
                            #print(json.dumps(data_json,sort_keys=True,indent=4, separators=(',', ': ')))
                            json_resp = json.loads(resp)
                            print("Put was successful.........for %s"%(json_resp["name"]))
                            #print(json.dumps(json_resp, sort_keys=True, indent=4, separators=(',', ': ')))
                        else:
                            r.raise_for_status()
                            print("Status code:-->" + status_code)
                            print("Error occurred in PUT --> " + resp)
                    except requests.exceptions.HTTPError as err:
                        print("Error in connection --> " + str(err))
                        rulesnotput.write(data_json["name"])
                        if status_code==401:# This mean the access token is expired
                                        headers = {'Content-Type': 'application/json'}
                                        api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
                                        auth_url = server + api_auth_path
                                        try:
                                            r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username, password),
                                                              verify=False)
                                            auth_headers = r.headers
                                            auth_token = auth_headers.get('X-auth-access-token', default=None)
                                            if auth_token == None:
                                                print("auth_token not found. Exiting...")
                                                sys.exit()
                                        except Exception as err:
                                            print("Error in generating auth token --> " + str(err))
                                        headers['X-auth-access-token'] = auth_token
                        if status_code==429:
                            time.sleep(5)
                    finally:
                        if r: r.close()

                
               
