
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
readfile = open("filedetail.json","r")
filedetail=json.loads(readfile.read())
writefile=open(filedetail["internetSpecific"],"w")

def segregateInternet():
    readfinalfile=open(filedetail["finalfilter"],"r")

    for line in readfinalfile.readlines():
        towrite = 0
        rule = json.loads(line)
        try:
            for zones in rule["sourceZones"]["objects"]:
                if "port8" in zones["name"] or "port16" in zones["name"]:
                    towrite=1
            for zones in rule["destinationZones"]["objects"]:
                if "port8" in zones["name"] or "port16" in zones["name"]:
                    towrite = 1
            if towrite ==1:
                line= str(rule)
                line=line.replace("'", '"').replace("True", '"true"').replace("False", '"false"')
                writefile.write(line)
                writefile.write("\n")


        except:
            pass
        #print(rule["sourceZones"])

segregateInternet()
writefile.close()