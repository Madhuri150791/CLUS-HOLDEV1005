
import json
import sys
import requests
import csv
import time
import FMCDetail
###Please provide the details here before running the script################################################################################

server = FMCDetail.server
username = FMCDetail.username
password = FMCDetail.password
domain_uuid=FMCDetail.domain_uuid
accesspolicy_uuid=FMCDetail.accesspolicy_uuid

#########################################################################################################################################
r = None
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
    sys.exit()

headers['X-auth-access-token'] = auth_token

api_path = "/api/fmc_config/v1/domain/"+domain_uuid+"/policy/accesspolicies/"+accesspolicy_uuid+"/accessrules"  # param
url = server + api_path
if (url[-1] == '/'):
    url = url[:-1]

# GET OPERATION
fwrite = open("accessrule-UWA3.txt", 'w')
#rulenotget=open("Rules_Not_Present.txt","w")
wwrite = csv.writer(fwrite, delimiter=',', quotechar='"', quoting=csv.QUOTE_ALL)
try:

    r = requests.get(url, headers=headers, verify=False)
    status_code = r.status_code
    responses=r.json()
    resp = r.text
    if (status_code == 200):
        #print("GET successful. Response data --> ")
        json_resp = json.loads(resp)
        if responses["links"]=={}:
            pass
        else:
            for item in responses["items"]:
                api_path = "/api/fmc_config/v1/domain/"+domain_uuid+"/policy/accesspolicies/"+accesspolicy_uuid+"/accessrules/" +item["id"]  # param
                url = server + api_path
                if (url[-1] == '/'):
                    url = url[:-1]
                try:

                    r = requests.get(url, headers=headers, verify=False)
                    status_code = r.status_code
                    res = r.json()
                    resp = r.text
                    if (status_code == 200):
                        print("GET successful. Response data --> ")
                        json.dump(res,fwrite)
                        fwrite.write("\n")
                        json_resp = json.loads(resp)
                       
                    else:
                        r.raise_for_status()
                        print("Error occurred in GET --> " + resp)
                except requests.exceptions.HTTPError as err:
                    print("Error in connection --> " + str(err))
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
                #wwrite.writerow(mylist)
        try:
            if 'next' in responses["paging"]:
               
                while True:
                    #print(responses["paging"]["next"][0])
                    urlx = responses["paging"]["next"][0]
                    response1 = requests.get(urlx, headers=headers,verify=False)  # this is to get list of all Service Group Object
                    responses1 = response1.json()
                    # print(responses)
                    
                    if response1.status_code != 400 and response1.status_code != 401:

                        if responses1["links"] == {}:
                            pass
                        else:

                            for item in responses1["items"]:
                       
                                api_path = "/api/fmc_config/v1/domain/" + domain_uuid + "/policy/accesspolicies/" + accesspolicy_uuid + "/accessrules/"+item["id"]  # param
                                url = server + api_path
                                if (url[-1] == '/'):
                                    url = url[:-1]
                                try:
                                    r = requests.get(url, headers=headers, verify=False)
                                    status_code = r.status_code
                                    res=r.json()
                                    resp = r.text
                                    if (status_code == 200):
                                        print("GET successful. Response data --> ")
                                        json.dump(res,fwrite)
                                        fwrite.write("\n")
                                       

                                    else:
                                        r.raise_for_status()
                                        print("Error occurred in GET --> " + resp)
                                except requests.exceptions.HTTPError as err:
                                    print("Error in connection --> " + str(err))
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
                                #wwrite.writerow(mylist)
                        print(responses1["paging"])
                        responses = responses1
                        if 'next' not in responses['paging']:
                            print("iam here")
                            break

        except:
            pass


        #print(json.dumps(json_resp, sort_keys=True, indent=4, separators=(',', ': ')))
    else:
        r.raise_for_status()
        print("Error occurred in GET --> " + resp)
except requests.exceptions.HTTPError as err:
    print("Error in connection --> " + str(err))
finally:
    if r: r.close()
fwrite.close()


