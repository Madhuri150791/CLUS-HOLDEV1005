import json
import sys
import csv
import requests

def filterfile(getfile,filterfile,finalfilter):
    readfile = open(getfile, "r")  # Place the file here which is obtained from the GET operation
    writefile = open(filterfile, "w")
    uniquename = []
    for line in readfile:
        data = json.loads(line)
        if "users" in data:
            pass
        else:

            if "metadata" in data:
                del data["metadata"]


                #del data["metadata"]["links"]
                # print (data)
                if "links" in data:
                    del data["links"]
                    name=data["name"]
                    if name in uniquename:
                        name = name+"md123"
                        if name not in uniquename:
                            data["name"] = name
                            uniquename.append(name)

                        else:
                            name=name+"dm123"
                            data["name"] = name
                            uniquename.append(name)
                    else:
                        uniquename.append(name)
                    # print(data)
                    # print("\n")
                    # del data["commentHistoryList"]
                    writefile.write(str(data))
                    writefile.write("\n")

    writefile.close()
    readfile.close()
    readfile = open(filterfile, "r")
    converted = readfile.read().replace("'", '"').replace("True", '"true"').replace("False", '"false"')
    writefile1 = open(finalfilter, "w")
    writefile1.write(converted)
    writefile1.close()
    readfile.close()