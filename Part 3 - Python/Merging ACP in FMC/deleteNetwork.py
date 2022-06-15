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
def deleteobjecttype(object):
    payload = {}
    api_path = "/api/fmc_config/v1/domain/" + getDomain_uuid() + "/object/" + object
    url = getServer() + api_path
    if (url[-1] == '/'):
        url = url[:-1]
    try:
        r = requests.get(url, headers=getaccesstoken(), verify=False)
        status_code = r.status_code
        responses = r.json()
        if status_code == 200:
            for item in responses["items"]:
                api_path_obj = "/api/fmc_config/v1/domain/" + getDomain_uuid() + "/object/" + object +"/"+ str(item["id"])
                url = getServer() + api_path_obj
                if (url[-1] == '/'):
                    url = url[:-1]
                #print(url)
                #print(str(item))
                try:
                    obj = requests.request("DELETE",url,headers=getaccesstoken(), verify=False)
                    #print(str(obj))
                    status_code_o = obj.status_code
                    if status_code_o == 200:
                        print("Delete Success for "+ str(item["name"]) +" "+item["id"])
                    elif status_code_o==400:
                        #print(str(item))
                        #print(url)
                        print(str(obj.text))
                    else:
                        print("Error " + str(status_code_o)+ " for " + str(item["name"]) )
                except:
                    print(" Issue seen while deleting "+ str(item["name"]))
            try:
                if 'next' in responses["paging"]:
                    print("Found Pages:")
                    while True:
                        print(responses["paging"]["next"][0])
                        urlx = responses["paging"]["next"][0]
                        headers = getaccesstoken()
                        response1 = requests.get(urlx, headers=headers,
                                                 verify=False)  # this is to get list of all Service Group Object
                        responsesx = response1.json()
                        responses = responsesx
                        status_codex=response1.status_code
                        if status_codex == 200:
                            for item in responsesx["items"]:
                                api_path_obj = "/api/fmc_config/v1/domain/" + getDomain_uuid() + "/object/" + object +"/"+ str(item["id"])
                                url = getServer() + api_path_obj
                                if (url[-1] == '/'):
                                    url = url[:-1]

                                try:
                                    obj = requests.request("DELETE",url, headers=getaccesstoken(), verify=False)
                                    status_code = obj.status_code
                                    if status_code == 200:
                                        print("Delete Success for " + str(item["name"]) + " " + item["id"])
                                    elif status_code == 400:
                                        print(str(item))
                                        print(api_path_obj)
                                    else:
                                        print("Error " + str(status_code) + " for " + str(item["name"]))

                                except:
                                    print(" Issue seen while deleting " + str(item["name"]))
                        else:
                            print(str(response1.text))
            except:
                pass
    except:
        pass
def defineobjects():
    objects = ["urlgroups","portobjectgroups","networkgroups","dnsservergroups","icmpv4objects","fqdns","interfacegroups","networkgroups","portobjectgroups","protocolportobjects","ranges","securityzones","urls","networks","hosts"]
    for object in objects:
        print("Deleting "+ str(object)+"......\n")
        deleteobjecttype(object)
defineobjects()