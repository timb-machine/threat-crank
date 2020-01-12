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
gamephasenamelist = ["initial-access", "execution", "persistence", "privilege-escalation", "defense-evasion", "credential-access", "discovery", "command-and-control", "exfiltration", "impact"]

def usage(commandname):
    print("usage: " + os.path.basename(__file__) + " [-G <\"unified\" | \"discrete\"> | -W <maxiumumrolls>] -A <attackurl> [-d] [-v] [-a <actorspattern> -i <industriespattern>] [-r <regionspattern>] [-p <platformspattern>]")
    print()
    print("	-d - debug mode, toggles additional output")
    print("	-v - verbose mode, toggles descriptions in non-gephi mode")
    print("	-A - use a different ATT&CK source")
    print("	-G - gephi mode, dump node pairs for directed graph of matching ATT&CK kill chains for consumption by Gephi")
    print("	-W - wargame mode, construct a number of randomised attack trees")
    print("	-a - constrain ATT&CK kill chains to specific actors")
    print("	-i - constrain ATT&CK kill chains to specific industries")
    print("	-r - constrain ATT&CK kill chains to specific regions")
    print("	-p - constrain ATT&CK kill chains to specific platforms")
    sys.exit(1)

def filterActor(jsonobjects, debugflag, actorspattern, industriespattern, regionspattern):
    newjsonobjects = []
    for jsonobject in jsonobjects["objects"]:
        if jsonobject["type"] == "intrusion-set":
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
            if "description" in jsonobject.keys():
                if re.match(industriespattern, jsonobject["description"], re.IGNORECASE | re.MULTILINE) and re.match(regionspattern, jsonobject["description"], re.IGNORECASE | re.MULTILINE):
                    if debugflag == True:
                        print("I: industry/region match " + jsonobject["description"])
                    matchflag = matchflag and True
            if matchflag == True:
                newjsonobjects.append(jsonobject)
    return newjsonobjects

def filterAttackPlatform(jsonobjects, debugflag, targetreference, platformspattern):
    return filterPlatform(jsonobjects, debugflag, "attack-pattern", targetreference, platformspattern)

def filterMalwarePlatform(jsonobjects, debugflag, targetreference, platformspattern):
    return filterPlatform(jsonobjects, debugflag, "malware", targetreference, platformspattern)

def filterToolPlatform(jsonobjects, debugflag, targetreference, platformspattern):
    return filterPlatform(jsonobjects, debugflag, "tool", targetreference, platformspattern)

def filterPlatform(jsonobjects, debugflag, objecttype, targetreference, platformspattern):
    newjsonobjects = []
    for jsonobject in jsonobjects["objects"]:
        matchflag = False
        if jsonobject["type"] == objecttype:
            if targetreference == jsonobject["id"]:
                if "x_mitre_platforms" in jsonobject.keys():
                    for platformname in jsonobject["x_mitre_platforms"]:
                        if matchflag == False:
                            if re.match(platformspattern, platformname, re.IGNORECASE | re.MULTILINE):
                                if debugflag == True:
                                    print("I: platform match " + platformname)
                                matchflag = matchflag or True
                    if matchflag == True:
                        newjsonobjects.append(jsonobject)
    return newjsonobjects


def gephi(jsonobjects, debugflag, actorspattern, industriespattern, regionspattern, platformspattern, gephitype):
    for jsonobject in filterActor(jsonobjects, debugflag, actorspattern, regionspattern, platformspattern):
         for jsonobject2 in jsonobjects["objects"]:
             if jsonobject2["type"] == "relationship":
                 if "source_ref" in jsonobject2.keys():
                     if jsonobject2["source_ref"] == jsonobject["id"]:
                         for jsonobject3 in filterAttackPlatform(jsonobjects, debugflag, jsonobject2["target_ref"], platformspattern):
                              if "kill_chain_phases" in jsonobject3.keys():
                                  for phase in jsonobject3["kill_chain_phases"]:
                                      if "phase_name" in phase.keys():
                                          if gephitype == "unified":
                                              print(jsonobject["name"] + ";" + phase["phase_name"])
                                          else:
                                              print(jsonobject["name"] + ";" + jsonobject["name"] + "-" + phase["phase_name"])
                                          if "external_references" in jsonobject3.keys():
                                              for datasource in jsonobject3["external_references"]:
                                                  if "source_name" in datasource.keys():
                                                      if datasource["source_name"] == "mitre-attack" or datasource["source_name"] != "capec":
                                                          if "external_id" in datasource.keys():
                                                              if gephitype == "unified":
                                                                  print(phase["phase_name"] + ";" + datasource["external_id"])
                                                              else:
                                                                  print(jsonobject["name"] + "-" + phase["phase_name"] + ";" + datasource["external_id"])

def wargame(gamephasenamelist, jsonobjects, debugflag, verboseflag, actorspattern, industriespattern, regionspattern, platformspattern, maximumrolls):
    print("# Shall we play a game?\n")
    for rollcounter in range(0, maximumrolls):
        print("## Roll #" + str(rollcounter + 1) + "\n")
        (gameidlist, gamenamelist, gamedescriptionlist) = roll(gamephasenamelist, jsonobjects, debugflag, verboseflag, actorspattern, industriespattern, regionspattern, platformspattern)
        for gamephasename in gamephasenamelist:
            print("### " + gamephasename + "\n")
            if gamephasename in gameidlist.keys() and gamephasename in gamenamelist.keys() and gamephasename in gamedescriptionlist.keys():
                print("* " + gameidlist[gamephasename] + ": " + gamenamelist[gamephasename] + "\n")
                if verboseflag == True:
                    print(gamedescriptionlist[gamephasename] + "\n")
            else:
                print(gamenamelist[gamephasename] + "\n")

def roll(gamephasenamelist, jsonobjects, debugflag, verboseflag, actorspattern, industriespattern, regionspattern, platformspattern):
    gamephaseattackidlist = {}
    gamephaseattacknamelist = {}
    gamephaseattackdescriptionlist = {}
    for gamephasename in gamephasenamelist:
        attacknamelist = {}
        attackdescriptionlist = {}
        for jsonobject in filterActor(jsonobjects, debugflag, actorspattern, industriespattern, regionspattern):
             for jsonobject2 in jsonobjects["objects"]:
                 if jsonobject2["type"] == "relationship":
                     if "source_ref" in jsonobject2.keys():
                         if jsonobject2["source_ref"] == jsonobject["id"]:
                             for jsonobject3 in filterAttackPlatform(jsonobjects, debugflag, jsonobject2["target_ref"], platformspattern):
                                  if "kill_chain_phases" in jsonobject3.keys():
                                      for phase in jsonobject3["kill_chain_phases"]:
                                          if "phase_name" in phase.keys():
                                              if phase["phase_name"] == gamephasename:
                                                  if "external_references" in jsonobject3.keys():
                                                      for datasource in jsonobject3["external_references"]:
                                                          if "source_name" in datasource.keys():
                                                              if datasource["source_name"] == "mitre-attack" or datasource["source_name"] != "capec":
                                                                  if "external_id" in datasource.keys():
                                                                      attacknamelist[datasource["external_id"]] = jsonobject3["name"]
                                                                      attackdescriptionlist[datasource["external_id"]] = jsonobject3["description"].replace("###", "####")
        if attacknamelist and attackdescriptionlist:
            gamephaseattackidlist[gamephasename] = random.choice(list(attacknamelist.keys()))
            gamephaseattacknamelist[gamephasename] = attacknamelist[gamephaseattackidlist[gamephasename]]
            gamephaseattackdescriptionlist[gamephasename] = attackdescriptionlist[gamephaseattackidlist[gamephasename]]
        else:
            gamephaseattacknamelist[gamephasename] = "E: You have been eaten by a grue!"
    return (gamephaseattackidlist, gamephaseattacknamelist, gamephaseattackdescriptionlist)

def report(jsonobjects, debugflag, verboseflag, actorspattern, industriespattern, regionspattern, platformspattern):
    (reportdescriptionlist, reportreferencelist) = filterReportReferences(jsonobjects, debugflag, verboseflag, actorspattern, industriespattern, regionspattern, platformspattern)
    (attacklist, phaselist, platformlist, defencelist, telemetrylist, referencelist, toollist, toolreferencelist) = buildReport(jsonobjects, debugflag, verboseflag, reportreferencelist)
    print("# Threat groups\n")
    for reportreferencename in reportdescriptionlist.keys():
        print("* " + reportreferencename)
        if verboseflag:
            print(reportdescriptionlist[reportreferencename])
    print()
    print("# Validate the following attacks\n")
    for attackname in attacklist.keys():
       print("* " + attackname + " - " + str(attacklist[attackname]))
    print()
    print("# Validate the following phases\n")
    for phasename in phaselist.keys():
       print("* " + phasename + " - " + str(phaselist[phasename]))
    print()
    print("# Validate the following platforms\n")
    for platformname in platformlist.keys():
       print("* " + platformname + " - " + str(platformlist[platformname]))
    print()
    print("# Validate the following defences\n")
    for defencename in defencelist.keys():
       print("* " + defencename + " - " + str(defencelist[defencename]))
    print()
    print("# Validate the following data sources\n")
    for telemetryname in telemetrylist.keys():
       print("* " + telemetryname + " - " + str(telemetrylist[telemetryname]))
    print()
    print("# Review the following attack references\n")
    for referenceurl in referencelist.keys():
       print("* " + referenceurl + " - " + referencelist[referenceurl])
    print()
    print("# Validate the following tools and malware\n")
    for toolname in toollist.keys():
       print("* " + toolname + " - " + str(toollist[toolname]))
    print()
    print("# Review the following tool and malware references\n")
    for toolreferenceurl in toolreferencelist.keys():
       print("* " + toolreferenceurl + " - " + toolreferencelist[toolreferenceurl])
    print()

def filterReportReferences(jsonobjects, debugflag, verboseflag, actorspattern, industriespattern, regionspattern, platformspattern):
    reportdescriptionlist = {}
    reportreferencelist = {}
    for jsonobject in filterActor(jsonobjects, debugflag, actorspattern, industriespattern, regionspattern):
         for jsonobject2 in jsonobjects["objects"]:
             if jsonobject2["type"] == "relationship":
                 if "source_ref" in jsonobject2.keys():
                     if jsonobject2["source_ref"] == jsonobject["id"]:
                         for jsonobject3 in filterAttackPlatform(jsonobjects, debugflag, jsonobject2["target_ref"], platformspattern):
                             reportdescriptionlist[jsonobject["name"]] = jsonobject["description"].replace("###", "####")
                             if jsonobject["name"] not in reportreferencelist.keys():
                                 reportreferencelist[jsonobject["name"]] = []
                             reportreferencelist[jsonobject["name"]].append(jsonobject3["id"])
                         for jsonobject3 in filterMalwarePlatform(jsonobjects, debugflag, jsonobject2["target_ref"], platformspattern):
                              reportdescriptionlist[jsonobject["name"]] = jsonobject["description"].replace("###", "####")
                              if jsonobject["name"] not in reportreferencelist.keys():
                                  reportreferencelist[jsonobject["name"]] = []
                              reportreferencelist[jsonobject["name"]].append(jsonobject3["id"])
                         for jsonobject3 in filterToolPlatform(jsonobjects, debugflag, jsonobject2["target_ref"], platformspattern):
                              reportdescriptionlist[jsonobject["name"]] = jsonobject["description"].replace("###", "####")
                              if jsonobject["name"] not in reportreferencelist.keys():
                                  reportreferencelist[jsonobject["name"]] = []
                              reportreferencelist[jsonobject["name"]].append(jsonobject3["id"])
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
    for reportreferencename in reportreferencelist.keys():
        for jsonobject in jsonobjects["objects"]:
            if jsonobject["type"] == "attack-pattern":
                for reportreferenceid in reportreferencelist[reportreferencename]:
                    if jsonobject["id"] == reportreferenceid:
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
            if jsonobject["type"] == "malware" or jsonobject["type"] == "tool":
                for reportreferenceid in reportreferencelist[reportreferencename]:
                    if jsonobject["id"] == reportreferenceid:
                        if debugflag == True:
                            pprint(jsonobject)
                        if jsonobject["name"] not in toollist.keys():
                            toollist[jsonobject["name"]] = 0
                        toollist[jsonobject["name"]] += 1
                        if "x_mitre_platforms" in jsonobject.keys():
                            for platformname in jsonobject["x_mitre_platforms"]:
                                if platformname not in platformlist.keys():
                                    platformlist[platform] = 0
                                platformlist[platformname] += 1
                        if "external_references" in jsonobject.keys():
                            for referenceobject in jsonobject["external_references"]:
                                if "source_name" in referenceobject.keys():
                                    if referenceobject["source_name"] != "mitre-attack" and referenceobject["source_name"] != "capec":
                                        if "url" in referenceobject.keys():
                                            if "description" in referenceobject.keys():
                                                toolreferencelist[datasource["url"]] = datasource["description"]
    return (attacklist, phaselist, platformlist, defencelist, telemetrylist, referencelist, toollist, toolreferencelist)
    
print(os.path.basename(__file__) + " 0.2")
try:
    options, arguments = getopt.getopt(sys.argv[1:], "dvA:G:W:a:i:r:p:", ["debug", "verbose", "attackurl=", "gephi=", "wargame=", "actor=", "industry=", "region=", "platform="])
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
print("I: using " + attackurl)
with urllib.request.urlopen(attackurl) as url:
    jsonobjects = json.loads(url.read().decode())
    if gephiflag == True:
        gephi(jsonobjects, debugflag, actorspattern, industriespattern, regionspattern, platformspattern, gephitype)
    else:
        if wargameflag == True:
            wargame(gamephasenamelist, jsonobjects, debugflag, verboseflag, actorspattern, industriespattern, regionspattern, platformspattern, maximumrolls)
        else:
            report(jsonobjects, debugflag, verboseflag, actorspattern, industriespattern, regionspattern, platformspattern)
