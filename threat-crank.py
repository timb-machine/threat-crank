#!/usr/bin/python3

import os
import sys
import getopt
import urllib.request
import json
import re
import random
from pprint import pprint

debugflag = False
verboseflag = False
attackurl = "https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"
gephiflag = False
gephitype = "unified"
wargameflag = False
maximumrolls = 1
actorspattern = ".*"
industriespattern = ".*"
regionspattern = ".*"
platformspattern = ".*"
toolspattern = ".*"
malwarepattern = ".*"
gamephasenamelist = ["initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "command-and-control", "exfiltration", "impact"]

def usage(commandname):
    print("usage: " + os.path.basename(__file__) + " [-G <\"unified\" | \"discrete\"> | -W <maxiumumrolls>] -A <attackurl> [-d] [-v] [-a <actorspattern> -i <industriespattern>] [-r <regionspattern>] [-p <platformspattern>] [-t <toolspattern>] [-m <malwarepattern>]")
    print()
    print("\t-d - debug mode, toggles additional output")
    print("\t-v - verbose mode, toggles descriptions in non-gephi mode")
    print("\t-A - use a different ATT&CK source")
    print("\t-G - gephi mode, dump node pairs for directed graph of matching ATT&CK kill chains for consumption by Gephi")
    print("\t-W - wargame mode, construct a number of randomised attack trees")
    print("\t-a - constrain ATT&CK kill chains to specific actors")
    print("\t-i - constrain ATT&CK kill chains to specific industries")
    print("\t-r - constrain ATT&CK kill chains to specific regions")
    print("\t-p - constrain ATT&CK kill chains to specific platforms")
    print("\t-t - constrain ATT&CK kill chains to specific tools")
    print("\t-m - constrain ATT&CK kill chains to specific malware")
    sys.exit(1)

def filterActor(jsonobjects, debugflag, actorspattern, industriespattern, regionspattern):
    newjsonobjects = []
    for jsonobject in filterObjectType(jsonobjects, debugflag, "intrusion-set"):
        matchflag = False
        if re.match(actorspattern, jsonobject["name"], re.IGNORECASE | re.MULTILINE):
            if debugflag == True:
                print("I: actor match " + jsonobject["name"])
            matchflag = True
        if "aliases" in jsonobject.keys():
            for actoralias in jsonobject["aliases"]:
                if re.match(actorspattern, actoralias, re.IGNORECASE | re.MULTILINE):
                    if debugflag == True:
                        print("I: actor match " + actoralias)
                    matchflag = matchflag or True
                else:
                    matchflag = matchflag or False
        if "description" in jsonobject.keys():
            if re.match(industriespattern, jsonobject["description"], re.IGNORECASE | re.MULTILINE) and re.match(regionspattern, jsonobject["description"], re.IGNORECASE | re.MULTILINE):
                if debugflag == True:
                    print("I: industry/region match " + jsonobject["description"])
                matchflag = matchflag and True
            else:
                matchflag = False
        if matchflag == True:
            newjsonobjects.append(jsonobject)
    return newjsonobjects

# intrusion-set["id"] -> relationship["source_ref"] -> relationship["target_ref"] -> attack-pattern["id"] -> relationship["target_ref"] -> relationship["source_ref"] -> tool["id"]

def filterActorToolPlatform(actorjsonobjects, actorobjects, debugflag, platformspattern):
    return filterActorPlatform(jsonobjects, actorobjects, debugflag, "tool", platformspattern)

def filterActorMalwarePlatform(actorjsonobjects, actorobjects, debugflag, platformspattern):
    return filterActorPlatform(jsonobjects, actorobjects, debugflag, "malware", platformspattern)

def filterActorPlatform(jsonobjects, actorobjects, debugflag, objecttype, platformspattern):
    newjsonobjects = []
    for jsonobject in actorobjects:
        for jsonobject2 in filterObjectType(jsonobjects, debugflag, "relationship"):
            if jsonobject2["source_ref"] == jsonobject["id"]:
                for jsonobject3 in filterReference(filterObjectType(jsonobjects, debugflag, "attack-pattern"), debugflag, jsonobject2["target_ref"]):
                    for jsonobject4 in filterObjectType(jsonobjects, debugflag, "relationship"):
                        if jsonobject4["target_ref"] == jsonobject3["id"]:
                            for jsonobject5 in filterPlatform(filterReference(filterObjectType(jsonobjects, debugflag, objecttype), debugflag, jsonobject4["source_ref"]), debugflag, platformspattern):
                                newjsonobjects.append(jsonobject)

    return newjsonobjects

def filterAttackPlatform(jsonobjects, debugflag, platformspattern):
    return filterPlatform(jsonobjects, debugflag, "attack-pattern", platformspattern)

def filterAttackTool(jsonobjects, debugflag, toolspattern):
    return filterToolOrMalware(jsonobjects, debugflag, "tool", toolspattern)

def filterAttackMalware(jsonobjects, debugflag, malwarepattern):
    return filterToolOrMalware(jsonobjects, debugflag, "malware", malwarepattern)

def filterAttackToolOrMalware(jsonobjects, debugflag, objecttype, toolormalwarepattern):
    newjsonobjects = []
    return newjsonobjects

def filterToolPlatform(jsonobjects, debugflag, platformspattern):
    return filterPlatform(jsonobjects, debugflag, "tool", platformspattern)

def filterMalwarePlatform(jsonobjects, debugflag, platformspattern):
    return filterPlatform(jsonobjects, debugflag, "malware", platformspattern)

def filterPlatform(jsonobjects, debugflag, objecttype, platformspattern):
    newjsonobjects = []
    for jsonobject in filterObjectType(jsonobjects, debugflag, objecttype):
        matchflag = False
        if "x_mitre_platforms" in jsonobject.keys():
            for platformname in jsonobject["x_mitre_platforms"]:
                if re.match(platformspattern, platformname, re.IGNORECASE | re.MULTILINE):
                    if debugflag == True:
                        print("I: platform match " + platformname)
                    matchflag = matchflag or True
                else:
                    matchflag = matchflag or False
            if matchflag == True:
                newjsonobjects.append(jsonobject)
    return newjsonobjects

def filterTool(jsonobjects, debugflag, toolspattern):
    return filterToolOrMalware(jsonobjects, debugflag, "tool", toolspattern)

def filterMalware(jsonobjects, debugflag, malwarepattern):
    return filterToolOrMalware(jsonobjects, debugflag, "malware", malwarepattern)

def filterToolOrMalware(jsonobjects, debugflag, objecttype, toolormalwarepattern):
    newjsonobjects = []
    for jsonobject in filterObjectType(jsonobjects, debugflag, objecttype):
        matchflag = False
        if re.match(toolormalwarepattern, jsonobject["name"], re.IGNORECASE | re.MULTILINE):
            if debugflag == True:
                print("I: tool/malware match " + jsonobject["name"])
            matchflag = True
        if "aliases" in jsonobject.keys():
            for toolormalwarealias in jsonobject["aliases"]:
                if re.match(toolormalwarepattern, toolormalwarealias, re.IGNORECASE | re.MULTILINE):
                    if debugflag == True:
                        print("I: tool/malware match " + toolormalwarealias)
                    matchflag = matchflag or True
                else:
                    matchflag = matchflag or False
        if matchflag == True:
            newjsonobjects.append(jsonobject)
    return newjsonobjects

def filterObjectType(jsonobjects, debugflag, objecttype):
    newjsonobjects = []
    for jsonobject in jsonobjects:
        if jsonobject["type"] == objecttype:
            newjsonobjects.append(jsonobject)
    return newjsonobjects

def filterReference(jsonobjects, debugflag, reference):
    newjsonobjects = []
    for jsonobject in jsonobjects:
        if jsonobject["id"] == reference:
            newjsonobjects.append(jsonobject)
    return newjsonobjects

def gephi(jsonobjects, debugflag, actorspattern, industriespattern, regionspattern, platformspattern, toolspattern, malwarepattern, gephitype):
    for jsonobject in filterObjectType(jsonobjects, debugflag, "relationship"):
        for jsonobject2 in filterReference(filterActor(jsonobjects, debugflag, actorspattern, industriespattern, regionspattern), debugflag, jsonobject["source_ref"]):
            for jsonobject3 in filterReference(filterAttackPlatform(jsonobjects, debugflag, platformspattern), debugflag, jsonobject["target_ref"]):
                if "kill_chain_phases" in jsonobject3.keys():
                    for phase in jsonobject3["kill_chain_phases"]:
                        if "phase_name" in phase.keys():
                            if gephitype == "unified":
                                print(jsonobject2["name"] + ";" + phase["phase_name"])
                            else:
                                print(jsonobject2["name"] + ";" + jsonobject2["name"] + "-" + phase["phase_name"])
                            if "external_references" in jsonobject3.keys():
                                for referenceobject in jsonobject3["external_references"]:
                                    if "source_name" in referenceobject.keys():
                                        if referenceobject["source_name"] == "mitre-attack" or referenceobject["source_name"] != "capec":
                                            if "external_id" in referenceobject.keys():
                                                if gephitype == "unified":
                                                    print(phase["phase_name"] + ";" + referenceobject["external_id"])
                                                else:
                                                    print(jsonobject2["name"] + "-" + phase["phase_name"] + ";" + referenceobject["external_id"])

def wargame(gamephasenamelist, jsonobjects, debugflag, verboseflag, actorspattern, industriespattern, regionspattern, platformspattern, toolspattern, malwarepattern, maximumrolls):
    print("# Shall we play a game?\n")
    for rollcounter in range(0, maximumrolls):
        print("## Roll #" + str(rollcounter + 1) + "\n")
        (gameidlist, gamenamelist, gamedescriptionlist) = roll(gamephasenamelist, jsonobjects, debugflag, verboseflag, actorspattern, industriespattern, regionspattern, platformspattern, toolspattern, malwarepattern)
        for gamephasename in gamephasenamelist:
            print("### " + gamephasename + "\n")
            if gamephasename in gameidlist.keys() and gamephasename in gamenamelist.keys() and gamephasename in gamedescriptionlist.keys():
                print("* " + gameidlist[gamephasename] + ": " + gamenamelist[gamephasename] + "\n")
                if verboseflag == True:
                    print(gamedescriptionlist[gamephasename] + "\n")
            else:
                print(gamenamelist[gamephasename] + "\n")

def roll(gamephasenamelist, jsonobjects, debugflag, verboseflag, actorspattern, industriespattern, regionspattern, platformspattern, toolspattern, malwarepattern):
    gamephaseattackidlist = {}
    gamephaseattacknamelist = {}
    gamephaseattackdescriptionlist = {}
    for gamephasename in gamephasenamelist:
        attacknamelist = {}
        attackdescriptionlist = {}
        for jsonobject in filterObjectType(jsonobjects, debugflag, "relationship"):
            for jsonobject2 in filterReference(filterActor(jsonobjects, debugflag, actorspattern, industriespattern, regionspattern), debugflag, jsonobject["source_ref"]):
                for jsonobject3 in filterReference(filterAttackPlatform(jsonobjects, debugflag, platformspattern), debugflag, jsonobject["target_ref"]):
                    if "kill_chain_phases" in jsonobject3.keys():
                        for phase in jsonobject3["kill_chain_phases"]:
                            if "phase_name" in phase.keys():
                                if phase["phase_name"] == gamephasename:
                                    if "external_references" in jsonobject3.keys():
                                        for referenceobject in jsonobject3["external_references"]:
                                            if "source_name" in referenceobject.keys():
                                                if referenceobject["source_name"] == "mitre-attack" or referenceobject["source_name"] != "capec":
                                                    if "external_id" in referenceobject.keys():
                                                        attacknamelist[referenceobject["external_id"]] = jsonobject3["name"]
                                                        attackdescriptionlist[referenceobject["external_id"]] = jsonobject3["description"].replace("###", "####")
        if attacknamelist and attackdescriptionlist:
            gamephaseattackidlist[gamephasename] = random.choice(list(attacknamelist.keys()))
            gamephaseattacknamelist[gamephasename] = attacknamelist[gamephaseattackidlist[gamephasename]]
            gamephaseattackdescriptionlist[gamephasename] = attackdescriptionlist[gamephaseattackidlist[gamephasename]]
        else:
            gamephaseattacknamelist[gamephasename] = "E: You have been eaten by a grue!"
    return (gamephaseattackidlist, gamephaseattacknamelist, gamephaseattackdescriptionlist)

def report(jsonobjects, debugflag, verboseflag, actorspattern, industriespattern, regionspattern, platformspattern, toolspattern, malwarepattern):
    (reportdescriptionlist, reportreferencelist) = filterReportReferences(jsonobjects, debugflag, verboseflag, actorspattern, industriespattern, regionspattern, platformspattern, toolspattern, malwarepattern)
    (attacklist, phaselist, platformlist, defencelist, telemetrylist, referencelist, toollist, toolreferencelist, malwarelist, malwarereferencelist) = buildReport(jsonobjects, debugflag, verboseflag, reportreferencelist)
    print("# Threat groups\n")
    for reportreferencename in sorted(reportdescriptionlist.keys()):
        print("* " + reportreferencename)
        if verboseflag:
            print(reportdescriptionlist[reportreferencename])
    print()
    print("# Validate the following attacks\n")
    for attackname in sorted(attacklist.keys()):
        print("* " + attackname + " - " + str(attacklist[attackname]))
    print()
    print("# Validate the following phases\n")
    for phasename in sorted(phaselist.keys()):
        print("* " + phasename + " - " + str(phaselist[phasename]))
    print()
    print("# Validate the following platforms\n")
    for platformname in sorted(platformlist.keys()):
        print("* " + platformname + " - " + str(platformlist[platformname]))
    print()
    print("# Validate the following defences\n")
    for defencename in sorted(defencelist.keys()):
        print("* " + defencename + " - " + str(defencelist[defencename]))
    print()
    print("# Validate the following data sources\n")
    for telemetryname in sorted(telemetrylist.keys()):
        print("* " + telemetryname + " - " + str(telemetrylist[telemetryname]))
    print()
    print("# Review the following attack references\n")
    for referenceurl in sorted(referencelist.keys()):
        print("* " + referenceurl + " - " + referencelist[referenceurl])
    print()
    print("# Validate the following tools\n")
    for toolname in sorted(toollist.keys()):
        print("* " + toolname + " - " + str(toollist[toolname]))
    print()
    print("# Review the following tool references\n")
    for toolreferenceurl in sorted(toolreferencelist.keys()):
        print("* " + toolreferenceurl + " - " + toolreferencelist[toolreferenceurl])
    print()
    print("# Validate the following malware\n")
    for malwarename in sorted(malwarelist.keys()):
        print("* " + malwarename + " - " + str(malwarelist[malwarename]))
    print()
    print("# Review the following malware references\n")
    for malwarereferenceurl in sorted(malwarereferencelist.keys()):
        print("* " + malwarereferenceurl + " - " + malwarereferencelist[malwarereferenceurl])
    print()

def filterReportReferences(jsonobjects, debugflag, verboseflag, actorspattern, industriespattern, regionspattern, platformspattern, toolspattern, malwarepattern):
    reportdescriptionlist = {}
    reportreferencelist = {}
    for jsonobject in filterObjectType(jsonobjects, debugflag, "relationship"):
        for jsonobject2 in filterReference(filterActor(jsonobjects, debugflag, actorspattern, industriespattern, regionspattern), debugflag, jsonobject["source_ref"]):
            for jsonobject3 in filterReference(filterAttackPlatform(jsonobjects, debugflag, platformspattern), debugflag, jsonobject["target_ref"]):
                reportdescriptionlist[jsonobject2["name"]] = jsonobject2["description"].replace("###", "####")
                if jsonobject2["name"] not in reportreferencelist.keys():
                    reportreferencelist[jsonobject2["name"]] = []
                reportreferencelist[jsonobject2["name"]].append(jsonobject3["id"])
            for jsonobject3 in filterReference(filterTool(filterToolPlatform(jsonobjects, debugflag, platformspattern), debugflag, toolspattern), debugflag, jsonobject["target_ref"]):
                reportdescriptionlist[jsonobject2["name"]] = jsonobject2["description"].replace("###", "####")
                if jsonobject2["name"] not in reportreferencelist.keys():
                    reportreferencelist[jsonobject2["name"]] = []
                reportreferencelist[jsonobject2["name"]].append(jsonobject3["id"])
            for jsonobject3 in filterReference(filterMalware(filterMalwarePlatform(jsonobjects, debugflag, platformspattern), debugflag, malwarepattern), debugflag, jsonobject["target_ref"]):
                reportdescriptionlist[jsonobject2["name"]] = jsonobject2["description"].replace("###", "####")
                if jsonobject2["name"] not in reportreferencelist.keys():
                    reportreferencelist[jsonobject2["name"]] = []
                reportreferencelist[jsonobject2["name"]].append(jsonobject3["id"])
    return (reportdescriptionlist, reportreferencelist)

def buildReport(jsonobjects, debugflag, verboseflag, reportreferencelist):
    attacklist = {}
    phaselist = {}
    platformlist = {}
    defencelist = {}
    telemetrylist = {}
    referencelist = {}
    toollist = {}
    toolreferencelist = {}
    malwarelist = {}
    malwarereferencelist = {}
    for reportreferencename in reportreferencelist.keys():
        for reportreferenceid in reportreferencelist[reportreferencename]:
            for jsonobject in filterReference(filterObjectType(jsonobjects, debugflag, "attack-pattern"), debugflag, reportreferenceid):
                if debugflag == True:
                    pprint(jsonobject)
                if jsonobject["name"] not in attacklist.keys():
                    attacklist[jsonobject["name"]] = 0
                attacklist[jsonobject["name"]] += 1
                if "kill_chain_phases" in jsonobject.keys():
                    for phaseobject in jsonobject["kill_chain_phases"]:
                        if phaseobject["phase_name"] not in phaselist.keys():
                            phaselist[phaseobject["phase_name"]] = 0
                        phaselist[phaseobject["phase_name"]] += 1
                if "x_mitre_platforms" in jsonobject.keys():
                    for platformname in jsonobject["x_mitre_platforms"]:
                        if platformname not in platformlist.keys():
                            platformlist[platformname] = 0
                        platformlist[platformname] += 1
                if "x_mitre_defense_bypassed" in jsonobject.keys():
                    for defencename in jsonobject["x_mitre_defense_bypassed"]:
                        if defencename not in defencelist.keys():
                            defencelist[defencename] = 0
                        defencelist[defencename] += 1
                if "x_mitre_data_sources" in jsonobject.keys():
                    for telemetryname in jsonobject["x_mitre_data_sources"]:
                        if telemetryname not in telemetrylist.keys():
                            telemetrylist[telemetryname] = 0
                        telemetrylist[telemetryname] += 1
                if "external_references" in jsonobject.keys():
                    for referenceobject in jsonobject["external_references"]:
                        if "source_name" in referenceobject.keys():
                            if referenceobject["source_name"] != "mitre-attack" and referenceobject["source_name"] != "capec":
                                if "url" in referenceobject.keys():
                                    if "description" in referenceobject.keys():
                                        referencelist[referenceobject["url"]] = referenceobject["description"]
        for reportreferenceid in reportreferencelist[reportreferencename]:
            for jsonobject in filterReference(filterObjectType(jsonobjects, debugflag, "tool"), debugflag, reportreferenceid):
                if debugflag == True:
                    pprint(jsonobject)
                if jsonobject["name"] not in toollist.keys():
                    toollist[jsonobject["name"]] = 0
                toollist[jsonobject["name"]] += 1
                if "x_mitre_platforms" in jsonobject.keys():
                    for platformname in jsonobject["x_mitre_platforms"]:
                        if platformname not in platformlist.keys():
                            platformlist[platformname] = 0
                        platformlist[platformname] += 1
                if "external_references" in jsonobject.keys():
                    for referenceobject in jsonobject["external_references"]:
                        if "source_name" in referenceobject.keys():
                            if referenceobject["source_name"] != "mitre-attack" and referenceobject["source_name"] != "capec":
                                if "url" in referenceobject.keys():
                                    if "description" in referenceobject.keys():
                                        toolreferencelist[referenceobject["url"]] = referenceobject["description"]
        for reportreferenceid in reportreferencelist[reportreferencename]:
            for jsonobject in filterReference(filterObjectType(jsonobjects, debugflag, "malware"), debugflag, reportreferenceid):
                if debugflag == True:
                    pprint(jsonobject)
                if jsonobject["name"] not in malwarelist.keys():
                    malwarelist[jsonobject["name"]] = 0
                malwarelist[jsonobject["name"]] += 1
                if "x_mitre_platforms" in jsonobject.keys():
                    for platformname in jsonobject["x_mitre_platforms"]:
                        if platformname not in platformlist.keys():
                            platformlist[platformname] = 0
                        platformlist[platformname] += 1
                if "external_references" in jsonobject.keys():
                    for referenceobject in jsonobject["external_references"]:
                        if "source_name" in referenceobject.keys():
                            if referenceobject["source_name"] != "mitre-attack" and referenceobject["source_name"] != "capec":
                                if "url" in referenceobject.keys():
                                    if "description" in referenceobject.keys():
                                        malwarereferencelist[referenceobject["url"]] = referenceobject["description"]
    return (attacklist, phaselist, platformlist, defencelist, telemetrylist, referencelist, toollist, toolreferencelist, malwarelist, malwarereferencelist)
    
print(os.path.basename(__file__) + " 0.2.1")
try:
    options, arguments = getopt.getopt(sys.argv[1:], "dvA:G:W:a:i:r:p:t:m:", ["debug", "verbose", "attackurl=", "gephi=", "wargame=", "actor=", "industry=", "region=", "platform=", "tool=", "malware="])
except:
    usage(os.path.basename(__file__))
for option, value in options:
    if option == "-d" or option == "--debug":
        debugflag = True
    if option == "-v" or option == "--verbose":
        verboseflag = True
    if option == "-A" or option == "--attackurl":
        attackurl = value
    if option == "-G" or option == "--gephi":
        gephiflag = True
        if value != "":
            gephitype = value
    if option == "-W" or option == "--wargame":
        wargameflag = True
        if value:
            maximumrolls = int(value)
    if option == "-a" or option == "--actor":
        actorspattern = value
        print("I: searching for actors that match " + actorspattern)
    if option == "-i" or option == "--industry":
        industriespattern = value
        print("I: searching for industries that match " + industriespattern)
    if option == "-r" or option == "--region":
        regionspattern = value
        print("I: searching for regions that match " + regionspattern)
    if option == "-p" or option == "--platform":
        platformspattern = value
        print("I: searching for platforms that match " + platformspattern)
    if option == "-t" or option == "--tool":
        toolspattern = value
        print("I: searching for tools that match " + toolspattern)
    if option == "-m" or option == "--malware":
        malwarepattern = value
        print("I: searching for malwares that match " + malwarepattern)
print("I: using " + attackurl)
with urllib.request.urlopen(attackurl) as url:
    jsonobjects = json.loads(url.read().decode())
    if gephiflag == True:
        gephi(jsonobjects["objects"], debugflag, actorspattern, industriespattern, regionspattern, platformspattern, toolspattern, malwarepattern, gephitype)
    else:
        if wargameflag == True:
            wargame(gamephasenamelist, jsonobjects["objects"], debugflag, verboseflag, actorspattern, industriespattern, regionspattern, platformspattern, toolspattern, malwarepattern, maximumrolls)
        else:
            report(jsonobjects["objects"], debugflag, verboseflag, actorspattern, industriespattern, regionspattern, platformspattern, toolspattern, malwarepattern)
