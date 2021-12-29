from falconpy import Hosts
from falconpy import Incidents
from falconpy import Detects
import time

falcon = Hosts(client_id="", client_secret="")

falcon2 = Incidents(client_id="", client_secret="")

falcon3 = Detects(client_id="", client_secret="")


def getNumDetections(hostname):
    
    response = falcon3.QueryDetects(offset=0, limit=1000,filter=f"device.hostname:'{hostname}'")
    
    if (response["body"]["errors"]):
        print(response)
        if (response["body"]["errors"][0] == 429):
            print("Waiting")
            time.sleep(61)
            return getNumDetections(hostname)
        else:
            return -1

    return len(response["body"]["resources"])

def getNumIncidents(deviceid):
    
    response = falcon2.QueryIncidents(offset = 0, limit = 500, filter = f"host_ids:'{deviceid}'")
    
    if (response["body"]["errors"]):
        print(response)
        if (response["body"]["errors"][0] == 429):
            print("Waiting")
            time.sleep(61)
            return getNumIncidents(deviceid)
        else: 
            return -1
    
    return len(response["body"]["resources"])

def progressBar(current, total, barLength = 40):
    percent = float(current) * 100 / total
    arrow   = '-' * int(percent/100 * barLength - 1) + '>'
    spaces  = ' ' * (barLength - len(arrow))

    print('Progress: [%s%s] %d %%' % (arrow, spaces, percent), end='\r')


response = falcon.QueryDevicesByFilter(offset=0, limit=4000, filter=f"platform_name:'Windows'")

deviceList = response["body"]["resources"]

result = falcon.GetDeviceDetails(ids=deviceList)

names = []
agentVersion =[]
lastSeen = []
osVersion = []
firstSeen = []
numIncidents = []
numDetections = []

currDevice = 1
totalDevices = len(response["body"]["resources"])
print()

for device in result["body"]["resources"]:

    progressBar(currDevice, totalDevices)

    numDetections.append(getNumDetections(device.get("hostname", None)))
    numIncidents.append(getNumIncidents(device.get("device_id", None)))
    names.append(device.get("hostname", None))
    agentVersion.append(device.get("agent_version", None))
    osVersion.append(device.get("os_version", None))
    firstSeen.append(device.get("first_seen", None))
    lastSeen.append(device.get("last_seen", None))

    currDevice = currDevice + 1

output = open("CS API Output.csv", "w")
output.write("Device Name, Agent Version, OS Version, First Seen, Last Seen, Num Detections, Num Incidents\n")

for index in range(0, len(names)):
    out = str(names[index]) + ", "+ str(agentVersion[index]) + ", " + str(osVersion[index]) + ", " + str(firstSeen[index]) + ", " + str(lastSeen[index]) + ", " + str(numDetections[index]) + ", " + str(numIncidents[index]) + "\n"
    output.write(out)

output.write("\n")

output.write("TOTAL STATS\n")
out = "Total Windows Devices in CS: " + str(len(result["body"]["resources"])) + "\n"
output.write(out)

print("Completed Successfully")
print()
