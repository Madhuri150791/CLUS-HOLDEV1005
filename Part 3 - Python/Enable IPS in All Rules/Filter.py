import json
import sys
import csv
import requests

readfile = open("accessrule-UWA3.txt", "r")  # Place the file here which is obtained from the GET operation
writefile = open("filterrule-UWA3.txt", "w")
for line in readfile:
    data = json.loads(line)
    if "users" in data:
        pass
    else:

        if "metadata" in data:
            del data["metadata"]
            # print (data)
            if "links" in data:
                del data["links"]
                # print(data)
                # print("\n")
                # del data["commentHistoryList"]
                writefile.write(str(data))
                writefile.write("\n")

    print(data)

writefile.close()
