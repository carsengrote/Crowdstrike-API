from falconpy import Hosts
from datetime import datetime, timedelta, timezone
import sys
import json

daysSince = sys.argv[1]

falcon = Hosts(client_id="", client_secret="")

today = datetime.strptime(str(datetime.now(timezone.utc)), "%Y-%m-%d %H:%M:%S.%f%z")

oldDate = str(today - timedelta(days=int(daysSince))).replace(" ", "T")[:-6]

result = falcon.QueryDevicesByFilter(offset=0, limit=4000,sort="last_seen.asc" ,filter=f"last_seen:<='{oldDate}Z'")

result = falcon.GetDeviceDetails(ids = result["body"]["resources"])

names = []
agentVersion =[]
lastSeen = []
osVersion = []
firstSeen = []
numIncidents = []
numDetections = []

print()

for device in result["body"]["resources"]:

    names.append(device.get("hostname", None))
    agentVersion.append(device.get("agent_version", None))
    osVersion.append(device.get("os_version", None))
    firstSeen.append(device.get("first_seen", None))
    lastSeen.append(device.get("last_seen", None))


output = open("Old Hosts.csv", "w")
output.write("Device Name, Last Seen, Agent Version, OS Version, First Seen\n")

for index in range(0, len(names)):
    out = str(names[index]) + ", " + str(lastSeen[index]) + ", " +  str(agentVersion[index]) + ", " + str(osVersion[index]) + ", " + str(firstSeen[index]) + "\n"
    output.write(out)
