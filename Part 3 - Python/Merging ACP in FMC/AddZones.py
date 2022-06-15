import json
import sys
import requests
import csv
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
networkobject = []
ftdnetwork_src=[]
ftdnetwork_dst =[]
ftdservice_src =[]
ftdservice_dst =[]
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
def parsezone(zones):
    ftdzone = []
    for zone in zones:
        ftdzone.append(zone['name'])
    return (ftdzone)
def getobject(type,id,ftdnetwork):
    api_path = "/api/fmc_config/v1/domain/" + getDomain_uuid() + "/object/" + type + "/"+id  # param
    url = getServer() + api_path
    if (url[-1] == '/'):
        url = url[:-1]
    # GET OPERATION
    try:
        r = requests.get(url, headers=getaccesstoken(), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            json_resp = json.loads(resp)
            if (type!="networkgroups"):
                return ftdnetwork.append(json_resp['value'])
            else:
                if "objects" in json_resp:
                    for item in json_resp["objects"]:
                        if item['type'] =='Network':
                            getobject("networks",item['id'],ftdnetwork)
                        if item['type'] =='Host':
                            getobject("hosts",item['id'],ftdnetwork)
                        if item['type'] =='FQDN':
                            getobject("fqdns",item['id'],ftdnetwork)
                        if item['type'] =='NetworkGroup':
                            getobject("networkgroups",item['id'],ftdnetwork)
                        if item['type'] =='Range':
                            getobject("ranges",item['id'],ftdnetwork)
                if 'literals' in json_resp:
                    for item in json_resp["literals"]:
                        ftdnetwork.append(item['value'])
        else:
            print(url)
            print(resp)
    except Exception as e:
        print("in exceot"+ str(e))
        pass
def parseNetwork(networks,ftdnetwork):
    for network in networks:
        if network['type']=="Host":
            if 'value' in network:
                ftdnetwork.append(network['value'])
            else:
                (getobject("hosts",network['id'],ftdnetwork))
        if network['type']=="Network":
            if 'value' in network:
                ftdnetwork.append(network['value'])
            else:
                getobject("networks",network['id'],ftdnetwork)
        if network['type']=="Range":
            if 'value' in network:
                ftdnetwork.append(network['value'])
            else:
                getobject("ranges",network['id'],ftdnetwork)
        if network['type']=="FQDN":
            if 'value' in network:
                ftdnetwork.append(network['value'])
            else:
                getobject("fqdns",network['id'],ftdnetwork)
        if network['type']=="NetworkGroup":
            getobject("networkgroups",network['id'],ftdnetwork)
    netlist= ftdnetwork
def getserviceobject(type,id,servicelist):
    api_path = "/api/fmc_config/v1/domain/" + getDomain_uuid() + "/object/" + type + "/"+id  # param

    url = getServer() + api_path
    if (url[-1] == '/'):
        url = url[:-1]
    # GET OPERATION
    #print(url)
    try:
        r = requests.get(url, headers=getaccesstoken(), verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            json_resp = json.loads(resp)
            if (type!="portobjectgroups"):
                if 'port' in json_resp:
                    return servicelist.append(json_resp['protocol']+":"+json_resp['port'])
                else:
                    return servicelist.append(json_resp['protocol'])
            else:
                if "objects" in json_resp:
                    for item in json_resp["objects"]:
                        if item['type'] =='ProtocolPortObject':
                            getserviceobject("protocolportobjects",item['id'],servicelist)
                        if item['type'] =='ICMPV4Object':
                            servicelist.append("icmp")
                        if item['type'] =='PortObjectGroup':
                            getserviceobject("portobjectgroups",item['id'],servicelist)
                        if item['type'] =='Range':
                            getserviceobject("ranges",item['id'],servicelist)
                if 'literals' in json_resp:
                    for item in json_resp["literals"]:
                        servicelist.append(item['protocol']+":"+item['port'])
        else:
            print(url)
            print(resp)
    except Exception as e:
        print(url)
        print("in exceot"+ str(e))
        pass


def parseService(services,servicelist):
    for service in services:
        if 'id' not in service:
            if service['type']=="PortLiteral":
                if service['protocol'] == '6':
                    servicelist.append("TCP:"+service['port'])
                elif service['protocol'] == '17':
                    servicelist.append("UDP:"+service['port'])
                else:
                    if 'port' in service:
                        servicelist.append(service['port'])
                    else:
                        if service['protocol']=='50':
                            servicelist.append("ESP")
                        elif service['protocol']=='51':
                            servicelist.append("AH")
                        else:
                            servicelist.append(service['protocol'])
            elif service['type']=="ICMPv4PortLiteral":
                servicelist.append("icmp")
        elif service['type']=="ProtocolPortObject":
            if service['protocol'] =='AH':
                servicelist.append("AH")
            elif service['protocol'] =='ESP':
                servicelist.append("ESP")
            else:
                getserviceobject("protocolportobjects",service['id'],servicelist)
        elif service['type']=='PortObjectGroup':
            getserviceobject("portobjectgroups",service['id'],servicelist)
    pass

def parseRule(rule):
    accessrule = []
    networkobject.clear()
    accessrule.append([rule['name']])
    if "sourceZones" in rule:
        accessrule.append(parsezone(rule['sourceZones']['objects']))
    else:
        accessrule.append([])
    if "destinationZones" in rule:
        accessrule.append(parsezone(rule['destinationZones']['objects']))
    else:
        accessrule.append([])
    if "sourceNetworks" in rule:
        ftdnetwork_src.clear()
        if 'objects' in rule['sourceNetworks']:
            dummy = parseNetwork(rule['sourceNetworks']['objects'],ftdnetwork_src)

        if 'literals' in rule['sourceNetworks']:
            dummy=parseNetwork(rule['sourceNetworks']['literals'],ftdnetwork_src)
        accessrule.append(ftdnetwork_src)


    else:
        accessrule.append([])
    if "destinationNetworks" in rule:
        ftdnetwork_dst.clear()
        if 'objects' in rule['destinationNetworks']:
            dummy=parseNetwork(rule['destinationNetworks']['objects'],ftdnetwork_dst)
        if 'literals' in rule['destinationNetworks']:
            dummy=parseNetwork(rule['destinationNetworks']['literals'],ftdnetwork_dst)
        accessrule.append(ftdnetwork_dst)
    else:
        accessrule.append([])
    if "sourcePorts" in rule:
        ftdservice_src.clear()
        if 'objects' in rule['sourcePorts']:
            parseService(rule['sourcePorts']['objects'],ftdservice_src)
        if 'literals' in rule['sourcePorts']:
            parseService(rule['sourcePorts']['literals'],ftdservice_src)
        accessrule.append(ftdservice_src)
    else:
        accessrule.append([])
    if "destinationPorts" in rule:
        ftdservice_dst.clear()
        if 'objects' in rule['destinationPorts']:
            parseService(rule['destinationPorts']['objects'],ftdservice_dst)
        if 'literals' in rule['destinationPorts']:
            # print(rule['destinationPorts'])
            parseService(rule['destinationPorts']['literals'],ftdservice_dst)
        accessrule.append(ftdservice_dst)
    else:
        accessrule.append([])
    return (accessrule)


def fileread():
    file = open("accessrule-production.txt")
    filew = open("accessrule-full-detail-production.csv", "w")
    filecsv=csv.writer(filew)
    filewrite = []
    # filewrite.append(["name","sourcezone","destinationzone","sourcenetwork","destinationnetwork"])
    # filew.write(str(filewrite))
    # filew.write("\n")
    for line in file:
        data = json.loads(line)
        filewrite = parseRule(data)
        # filew.write(str(filewrite))
        # filew.write("\n")
        filecsv.writerow(filewrite)
        print(filewrite)

fileread()



