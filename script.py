from subprocess import check_output
import time
import sys
import os

debug=False

def readPcapDir():
    dirDict = {}
    output = check_output("ls -la --time-style=full-iso /opt/capture-*", shell=True)
    for line in str(output).split("\\n"):
        if not line.startswith("-"):
            continue
        if debug:
            print("\n" + line)
        lineParts = line.split()
        if debug:
            partNum = 0
            for item in lineParts:
                print(str(partNum) + ":" + item)
                partNum += 1
        fileName = lineParts[8]
        fileTime = lineParts[6]
        dirDict[fileName] = fileTime
    return dirDict

def validateTime(timeToCheck):
    if timeToCheck.count(":") != 2:
        return("Invalid time. Must be in the format HH:MM:SS.")
    else:
        timeParts = timeToCheck.split(":")
        if len(timeParts[0]) != 2 or len(timeParts[1]) != 2 or len(timeParts[2]) != 2:
            return("Invalid time. Must be in the format HH:MM:SS.")
        else:
            try:
                if int(timeParts[0]) < 0 or int(timeParts[0]) > 24:
                    return("Invalid hour.")
                elif int(timeParts[1]) < 0 or int(timeParts[1]) > 60:
                    return("Invalid minute.")
                elif int(timeParts[2]) < 0 or int(timeParts[2]) > 60:
                    return("Invalid second.")
            except:
                return("Invalid time. Must be in the format HH:MM:SS.")
    return("")

##
## PROCESS COMMAND LINE ARGS
##

count   = 0
capTime = ""
ipAddr  = ""
for option in sys.argv:
    if option == "-h" or option == "--help":
        print("\n\n")
        print("Usage: carver.py [OPTIONS] [PARAMETERS]")
        print("  -t              Time of event to carve as HH:MM:SS")
        print("                  (must be to the second)")
        print("  -a              IP address to carve (CIDR permitted)")
        print("                  Default is to carve all traffic")
        print("  -h, --help      You're looking at it!")
        print("  -d              Enable debug mode.")
        print("")
        print("Examples:")
        print("  carver.py -t 13:15:06                           (Grabs and merges first pcap with last modified timestamp just after 13:15:06)")
        print("  carver.py -t 13:15:00-13:15:06                  (Grabs and merges pcaps for traffic between 13:15:00 and 13:15:06)")
        print("  carver.py -t 13:15:06 -a 10.3.66.32             (Grabs first pcap with last modified timestamp just after 13:15:06 and filters for traffic to or from 10.3.66.32)")
        print("  carver.py -t 13:15:00-13:15:06 -a 10.3.66.0/24  (Grabs and merges pcaps for traffic between 13:15:00 and 13:15:06 and filters for traffic to or from 10.3.66.0/24 subnet)")
        print("\n\n")
        sys.exit()
    elif option == "-d": debug = True
    elif option == "-t": 
        try:
            capTime = sys.argv[count + 1]
        except:
            print("The -t option needs to be followed by a time (to the second).")
            sys.exit()
    elif option == "-a":
        try:
            ipAddr = sys.argv[count + 1]
        except:
            print("The -a option needs to be followed by a valid IP address.")
            sys.exit()
    count = count + 1
if capTime == "":
    print("Time (-t option) is required.")
    sys.exit()
timeRange = False
if capTime.find("-") > 0:
    timeRange = True
    startTime, endTime = capTime.split("-")
    errorMessage = validateTime(startTime)
    if errorMessage != "":
        print("Start time error: " + errorMessage)
        sys.exit()
    errorMessage = validateTime(endTime)
    if errorMessage != "":
        print("End time error: " + errorMessage)
        sys.exit()
else:
    errorMessage = validateTime(capTime)
    if errorMessage != "":
        print(errorMessage)
        sys.exit()
    else:
        endTime = capTime

ip = ""
if ipAddr != "":
    if ipAddr.count("/") > 0:
        ip,cidr = ipAddr.split("/")
        try:
            if int(cidr) < 0 or int(cidr) > 32:
                print("Invalid CIDR.")
                sys.exit()
        except:
            print("Invalid IP address. Must be in the format xxx.xxx.xxx.xxx/xx (CIDR optional)")
            sys.exit()
    else:
        ip = ipAddr

    if ip.count(".") != 3:
        print("Invalid IP addreess. Must be in the format xxx.xxx.xxx.xxx/xx (CIDR optional)")
        sys.exit()
    else:
        ipParts = ip.split(".")
        try:
            if int(ipParts[0]) < 0 or int(ipParts[0]) > 255:
                print("Invalid first octet.")
                sys.exit()
            elif int(ipParts[1]) < 0 or int(ipParts[1]) > 255:
                print("Invalid second octet.")
                sys.exit()
            elif int(ipParts[2]) < 0 or int(ipParts[2]) > 255:
                print("Invalid third octet.")
                sys.exit()
            elif int(ipParts[3]) < 0 or int(ipParts[3]) > 255:
                print("Invalid fourth octet.")
                sys.exit()
        except:
            print("Invalid IP address. Must be in the format xxx.xxx.xxx.xxx/xx (CIDR optional)")
            sys.exit()

##
## OKAY, INPUT VALIDATED... LET'S GET TO WORK!
##
if timeRange:
    newFileName = startTime.replace(":","") + "-" + endTime.replace(":","")
else:
    newFileName = endTime.replace(":","")

alreadyMerged = False
alreadyCarved = False
findFile1 = newFileName + ".pcap"
findFile2 = newFileName + "-" + ip + ".pcap"
if debug:
    print("Checking if " + findFile1 + " has already been output...")
    print("Checking if " + findFile2 + " has already been output...")
dirList = check_output("ls -la /opt/carver/", shell=True)
for line in str(dirList).split("\\n"):
    if debug:
        print("Processing Carver Output Line: " + line)
    if line.find("pcap") < 1:
        continue
    lineParts = line.split()
    if findFile1 == lineParts[8]:
        if debug:
            print("Found " + findFile1)
        alreadyMerged = True
    if findFile2 == lineParts[8]:
        if debug:
            print("Found " + findFile2)
        alreadyCarved = True

if alreadyCarved and alreadyMerged:
    print("This job has already been run. Check /opt/carver/ for the output.")
    sys.exit()
if ipAddr == "" and alreadyMerged:
    print("This job has already been run. Check /opt/carver/ for the output.")
    sys.exit()

if not alreadyMerged:
    dirInfo = readPcapDir()
    sortedFilesByDate = (sorted(dirInfo.items(), key = lambda kv:(kv[1], kv[0])))

    numPostCaps = 0
    previousCapName = ""
    for fileName, fileTime in sortedFilesByDate:
        if numPostCaps > 0:
            check_output("cp " + fileName + " /opt/carver/", shell=True)
            break
        if timeRange and fileTime > startTime:
            check_output("cp " + fileName + " /opt/carver/", shell=True)
        if fileTime > endTime:
            if previousCapName != "" and not timeRange:
                check_output("cp " + previousCapName + " /opt/carver/", shell=True)
            check_output("cp " + fileName + " /opt/carver/", shell=True)
            numPostCaps += 1
        else:
            previousCapName = fileName

    check_output("mergecap -a /opt/carver/* -w /opt/carver/" + newFileName + ".pcap", shell=True)
    check_output("rm /opt/carver/capture-*", shell=True)

if ipAddr != "":
    if not alreadyCarved:
        check_output("tshark -r /opt/carver/" + newFileName + ".pcap -w /opt/carver/" + newFileName + "-" + ip + ".pcap -Y ip.addr==" + ipAddr, shell=True)
