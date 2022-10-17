from falconpy import Detects
from datetime import datetime, timedelta, timezone
import os.path
import sys
import smtplib

def sendMail(detectDict, actionsList):

    FROM = 'carsen.grote@'
    TO = ["----------"]
    SUBJECT = "CrowdStrike Detection for " + detectDict["user_name"]

    TEXT = "New CrowdStrike Detection for " + detectDict["user_name"] + " at " + detectDict["timestamp"] + "\n\n"
    TEXT = TEXT + "---- Details ----\n"
    TEXT = TEXT + "Hostname: " + detectDict["hostname"] + "\n"
    TEXT = TEXT + "Detection Description: " + detectDict["description"] + "\n"
    TEXT = TEXT + "Filename: " + detectDict["filename"] + "\n"
    TEXT = TEXT + "Filepath: " + detectDict["filepath"] + "\n"
    TEXT = TEXT + "Alleged Filetype: " + detectDict["alleged_filetype"] + "\n"
    TEXT = TEXT + "cmdline: " + detectDict["cmdline"] + "\n"
    TEXT = TEXT + "Parent cmdline: " + detectDict["parent_cmdline"] + "\n"
    TEXT = TEXT + "Scenario: " + detectDict["scenario"] + "\n"
    TEXT = TEXT + "Objective: " + detectDict["objective"] + "\n"
    TEXT = TEXT + "Technique: " + detectDict["technique"] + "\n"
    TEXT = TEXT + "Severity: " + str(detectDict["severity"]) + " Confidence: " + str(detectDict["confidence"]) + "\n"
    TEXT = TEXT + "First Behavior: " + detectDict["first_behavior"] + " Last Behavior: " + detectDict["last_behavior"] + "\n\n"
    TEXT = TEXT + "---- Actions Taken By CrowdStrike ----\n"
    
    if len(actionsList) == 0:
        TEXT = TEXT + "None"
    else:        
        for action in actionsList:
            TEXT = TEXT + str(action) + "\n"

    TEXT = TEXT + "\n---- Other Info ----\n"
    TEXT = TEXT + "Detection ID: " + detectDict["detection_id"] + "\n"
    TEXT = TEXT + "Agent Version: " + detectDict["agent_version"] + "\n"
    TEXT = TEXT + "Local IP: " + detectDict["local_ip"] + "\n"
    TEXT = TEXT + "OS Version: " + detectDict["os_version"] + "\n"
    TEXT = TEXT + "Site: " + detectDict["site"] + "\n"
    TEXT = TEXT + "Behavior ID: " + detectDict["behavior_id"] + "\n"
    TEXT = TEXT + "File SHA256: " + detectDict["sha256"] + "\n"
    TEXT = TEXT + "Device ID: " + detectDict["device_id"] + "\n"

    # Prepare actual message
    message = """\
    From: %s
    To: %s
    Subject: %s

    %s
    """ % (FROM, ", ".join(TO), SUBJECT, TEXT)
    # Send the mail
    if mail == 1:
        server = smtplib.SMTP('----------')
        server.sendmail(FROM, TO, message)
        server.quit()
    else:
        print(TEXT)

    return

def getDetections(secondsDelta, minutesDelta, daysDelta):

    # Open file of past detections and read in as list
    if (os.path.exists("detectionIds.txt")):
        detectionsFile = open("detectionIds.txt", "r+")
    else:
        detectionsFile = open("detectionIds.txt", "w+")
        
    line = detectionsFile.readline()
    oldId = " "
    if line.find("$") != -1:
        endIndex = line.index("$")
        oldId = line[0:endIndex]

    now = datetime.strptime(str(datetime.now(timezone.utc)), "%Y-%m-%d %H:%M:%S.%f%z")    
    date = str(now - timedelta(seconds=secondsDelta, days=daysDelta, minutes=minutesDelta)).replace(" ", "T")[:-6]
    date = date[:-7] + "Z"
    response = falcon.QueryDetects(offset = 0, limit = 5000, sort ="first_behavior|desc", filter=f"first_behavior:>='{date}'")
    id_list = response["body"]["resources"]
    
    # Return if no new detections
    if len(id_list) == 0:
        detectionsFile.close()
        return

    # Go through non empty list of new detections
    for id in id_list:

        # Stop once we reach old detection
        if oldId == id:
            break

        detect = falcon.GetDetectSummaries(id)
        detect = detect["body"]["resources"][0]
        detectionInfo(detect) 

    # Write new, most recently seen detection id to file
    detectionsFile.seek(0)
    detectionsFile.truncate()
    detectionsFile.write(id_list[0] + "$\n")
    detectionsFile.close()

    return

def detectionInfo(detect):

    detectDict = dict()
    detectDict["detection_id"] = detect.get("detection_id", None)
    detectDict["agent_version"] = detect.get("device", None).get("agent_version", None)
    detectDict["hostname"] = detect.get("device", None).get("hostname", None)
    detectDict["device_id"] = detect.get("device", None).get("device_id", None)
    detectDict["local_ip"] = detect.get("device", None).get("local_ip", None)
    detectDict["os_version"] = detect.get("device", None).get("os_version", None)
    detectDict["site"] = detect.get("device", None).get("site_name", None)
    detectDict["timestamp"] = detect.get("behaviors", None)[0].get("timestamp", None)
    detectDict["behavior_id"] = detect.get("behaviors", None)[0].get("behavior_id", None)
    detectDict["filename"] = detect.get("behaviors", None)[0].get("filename", None)
    detectDict["filepath"] = detect.get("behaviors", None)[0].get("filepath", None)
    detectDict["alleged_filetype"] = detect.get("behaviors", None)[0].get("alleged_filetype", None)
    detectDict["cmdline"] = detect.get("behaviors", None)[0].get("cmdline", None)
    detectDict["scenario"] = detect.get("behaviors", None)[0].get("scenario", None)
    detectDict["objective"] = detect.get("behaviors", None)[0].get("objective", None)
    detectDict["technique"] = detect.get("behaviors", None)[0].get("technique", None)
    detectDict["description"] = detect.get("behaviors", None)[0].get("description", None)
    detectDict["severity"] = detect.get("behaviors", None)[0].get("severity", None)
    detectDict["confidence"] = detect.get("behaviors", None)[0].get("confidence", None)
    detectDict["user_name"] = detect.get("behaviors", None)[0].get("user_name", None)
    detectDict["sha256"] = detect.get("behaviors", None)[0].get("sha256", None)
    detectDict["parent_cmdline"] = detect.get("behaviors", None)[0].get("parent_details", None).get("parent_cmdline", None)
    detectDict["first_behavior"] = detect.get("first_behavior", None)
    detectDict["last_behavior"] = detect.get("last_behavior", None)

    actionsList = []
    actions = detect.get("behaviors", None)[0].get("pattern_disposition_details", None)
    for item in actions.items():
        if (item[1]):
            actionsList.append(item[0])

    sendMail(detectDict, actionsList)
    
    return

def main():

    if len(sys.argv) != 5:
        print("Usage: detections.py <seconds> <minutes> <days> <0 for no email (testing) 1 for email>")
        return

    global falcon
    global hosts
    global mail
    falcon = Detects(client_id="", client_secret="")
    sec = int(sys.argv[1])
    min = int(sys.argv[2])
    days = int(sys.argv[3])
    mail = int(sys.argv[4])
    getDetections(sec,min,days)


if __name__ == "__main__":
    main()
