##############################################################################################################
# Prepared with Assumption that the rules from AODB, 300E, 310B and ASA with be having different rulename
##############################################################################################################


import GET as get
import FilterMetadata as FT
import PUT as put
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
readfile = open("filedetail.json","r")
filedetail=json.loads(readfile.read())
get.getrules(filedetail["getfile"])
#FT.filterfile(filedetail["getfile"],filedetail["filterfile"],filedetail["finalfilter"])
#put.putruleinnewacp(filedetail["getfile"],filedetail["finalfilter"],filedetail["nooutput"])