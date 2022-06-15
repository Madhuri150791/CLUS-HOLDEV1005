import requests
import json

url = "https://10.122.186.169/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/accesspolicies"

payload = json.dumps({
    "type": "AccessPolicy",
    "name": "AccessPolicy2",
    "defaultAction": {
        "action": "BLOCK"
    }
})
headers = {
    'X-auth-access-token': 'b17b7386-86d6-4501-83de-39507d9beb5d',
    'Content-Type': 'application/json'
}

response = requests.request("POST", url, headers=headers, data=payload,verify=False)

print(response.text)