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
industries = ".*"
regions = ".*"
platforms = ".*"
gamephases = ["initial-access", "execution", "persistence", "privilege-escalation", "defence-evasion", "credential-access", "discovery", "command-and-control", "exfiltration", "impact"]

print(os.path.basename(__file__) + " 0.1")
try:
    options, arguments = getopt.getopt(sys.argv[1:], "dva:G:W:i:r:p:", ["debug", "verbose", "attackurl=", "gephi=", "wargame=", "industry=", "region=", "platform="])
except:
    print("usage: " + os.path.basename(__file__) + " [-G <\"unified\" | \"discrete\"> | -W <maxiumumrolls>] -a <attackurl> [-d] [-v] [-i <industry>] [-r <region>] [-p <platform>]")
    print()
    print("	-d - debug mode, toggles additional output")
    print("	-v - verbose mode, toggles descriptions in non-gephi mode")
    print("	-a - use a different ATT&CK source")
    print("	-G - gephi mode, dump node pairs for directed graph of matching ATT&CK kill chains for consumption by Gephi")
    print("	-W - wargame mode, construct a number of randomised attack trees")
    print("	-i - constrain ATT&CK kill chains to specific industries")
    print("	-r - constrain ATT&CK kill chains to specific regions")
    print("	-p - constrain ATT&CK kill chains to specific platforms")
    sys.exit(1)
for option, value in options:
    if option == "-d" or option == "--debug":
        debugflag = True
    if option == "-v" or option == "--verbose":
        verboseflag = True
    if option == "-a" or option == "--attackurl":
        attackurl = value
    if option == "-G" or option == "--gephi":
        gephiflag = True
        if value != "":
            gephitype = value
    if option == "-W" or option == "--wargame":
        wargameflag = True
        if value:
            maximumrolls = int(value)
    if option == "-i" or option == "--industry":
        industries = value
        print("I: searching for industries that match " + industries)
    if option == "-r" or option == "--region":
        regions = value
        print("I: searching for regions that match " + regions)
    if option == "-p" or option == "--platform":
        platforms = value
        print("I: searching for platforms that match " + platforms)
print("I: using " + attackurl)
with urllib.request.urlopen(attackurl) as url:
    data = json.loads(url.read().decode())
    if gephiflag == True:
        for item in data["objects"]:
            if item["type"] == "intrusion-set":
                if "description" in item.keys():
                    if re.match(industries, item["description"], re.IGNORECASE | re.MULTILINE) and re.match(regions, item["description"], re.IGNORECASE | re.MULTILINE):
                        if debugflag == True:
                            print("I: industry/region match " + item["description"])
                        for item2 in data["objects"]:
                            if item2["type"] == "relationship":
                                if "source_ref" in item2.keys():
                                    if item2["source_ref"] == item["id"]:
                                        for item3 in data["objects"]:
                                            if item3["type"] == "attack-pattern":
                                                if item2["target_ref"] == item3["id"]:
                                                    if "x_mitre_platforms" in item3.keys():
                                                        for platform in item3["x_mitre_platforms"]:
                                                            if re.match(platforms, platform, re.IGNORECASE | re.MULTILINE):
                                                                if debugflag == True:
                                                                    print("I: platform match " + platform)
                                                                if "kill_chain_phases" in item3.keys():
                                                                    for phase in item3["kill_chain_phases"]:
                                                                        if "phase_name" in phase.keys():
                                                                            if gephitype == "unified":
                                                                                print(item["name"] + ";" + phase["phase_name"])
                                                                            else:
                                                                                print(item["name"] + ";" + item["name"] + "-" + phase["phase_name"])
                                                                            if "external_references" in item3.keys():
                                                                                for datasource in item3["external_references"]:
                                                                                    if "source_name" in datasource.keys():
                                                                                        if datasource["source_name"] == "mitre-attack" or datasource["source_name"] != "capec":
                                                                                            if "external_id" in datasource.keys():
                                                                                                if gephitype == "unified":
                                                                                                    print(phase["phase_name"] + ";" + datasource["external_id"])
                                                                                                else:
                                                                                                    print(item["name"] + "-" + phase["phase_name"] + ";" + datasource["external_id"])
    else:
        if wargameflag == True:
            print("# Shall we play a game?\n")
            for rollcounter in range(0, maximumrolls):
                print("## Roll #" + str(rollcounter + 1) + "\n")
                for gamephase in gamephases:
                    print("### Phase: " + gamephase + "\n")
                    names = {}
                    descriptions = {}
                    for item in data["objects"]:
                        if item["type"] == "intrusion-set":
                            if "description" in item.keys():
                                if re.match(industries, item["description"], re.IGNORECASE | re.MULTILINE) and re.match(regions, item["description"], re.IGNORECASE | re.MULTILINE):
                                    if debugflag == True:
                                        print("I: industry/region match " + item["description"])
                                    for item2 in data["objects"]:
                                        if item2["type"] == "relationship":
                                            if "source_ref" in item2.keys():
                                                if item2["source_ref"] == item["id"]:
                                                    for item3 in data["objects"]:
                                                        if item3["type"] == "attack-pattern":
                                                            if item2["target_ref"] == item3["id"]:
                                                                if "x_mitre_platforms" in item3.keys():
                                                                    for platform in item3["x_mitre_platforms"]:
                                                                        if re.match(platforms, platform, re.IGNORECASE | re.MULTILINE):
                                                                            if debugflag == True:
                                                                                print("I: platform match " + platform)
                                                                            if "kill_chain_phases" in item3.keys():
                                                                                for phase in item3["kill_chain_phases"]:
                                                                                    if "phase_name" in phase.keys():
                                                                                        if phase["phase_name"] == gamephase:
                                                                                            if "external_references" in item3.keys():
                                                                                                for datasource in item3["external_references"]:
                                                                                                    if "source_name" in datasource.keys():
                                                                                                        if datasource["source_name"] == "mitre-attack" or datasource["source_name"] != "capec":
                                                                                                            if "external_id" in datasource.keys():
                                                                                                                names[datasource["external_id"]] = item3["name"]
                                                                                                                descriptions[datasource["external_id"]] = item3["description"].replace("###", "####")
                    if names and descriptions:
                        id = random.choice(list(names.keys()))
                        print("* " + id + ": " + names[id] + "\n")
                        if verboseflag:
                            print(descriptions[id] + "\n")
                    else:
                        print("E: You have been eaten by a grue!\n")
        else:
            descriptions = {}
            references = {}
            for item in data["objects"]:
                if item["type"] == "intrusion-set":
                    if "description" in item.keys():
                        if re.match(industries, item["description"], re.IGNORECASE | re.MULTILINE) and re.match(regions, item["description"], re.IGNORECASE | re.MULTILINE):
                            if debugflag == True:
                                print("I: industry/region match " + item["description"])
                            for item2 in data["objects"]:
                                if item2["type"] == "relationship":
                                    if "source_ref" in item2.keys():
                                        if item2["source_ref"] == item["id"]:
                                            for item3 in data["objects"]:
                                                if item3["type"] == "attack-pattern":
                                                    if item2["target_ref"] == item3["id"]:
                                                        if "x_mitre_platforms" in item3.keys():
                                                            for platform in item3["x_mitre_platforms"]:
                                                                if re.match(platforms, platform, re.IGNORECASE | re.MULTILINE):
                                                                    if debugflag == True:
                                                                        print("I: platform match " + platform)
                                                                    descriptions[item["name"]] = item["description"].replace("###", "####")
                                                                    if item["name"] not in references.keys():
                                                                        references[item["name"]] = []
                                                                    references[item["name"]].append(item3["id"])
                                                if item3["type"] == "malware" or item3["type"] == "tool":
                                                    if item2["target_ref"] == item3["id"]:
                                                        if "x_mitre_platforms" in item3.keys():
                                                            for platform in item3["x_mitre_platforms"]:
                                                                if re.match(platforms, platform, re.IGNORECASE | re.MULTILINE):
                                                                    if debugflag == True:
                                                                        print("I: platform match " + platform)
                                                                    descriptions[item["name"]] = item["description"].replace("###", "####")
                                                                    if item["name"] not in references.keys():
                                                                        references[item["name"]] = []
                                                                    references[item["name"]].append(item3["id"])
            phases = {}
            attacks = {}
            platforms = {}
            defences = {}
            datasources = {}
            attackreferences = {}
            tools = {}
            toolreferences = {}
            for name in references.keys():
                for item in data["objects"]:
                    if item["type"] == "attack-pattern":
                        for reference in references[name]:
                            if item["id"] == reference:
                                if debugflag == True:
                                    pprint(item)
                                if item["name"] not in attacks.keys():
                                    attacks[item["name"]] = 0
                                attacks[item["name"]] += 1
                                if "kill_chain_phases" in item.keys():
                                    for phase in item["kill_chain_phases"]:
                                        if phase["phase_name"] not in phases.keys():
                                            phases[phase["phase_name"]] = 0
                                        phases[phase["phase_name"]] += 1
                                if "x_mitre_platforms" in item.keys():
                                    for platform in item["x_mitre_platforms"]:
                                        if platform not in platforms.keys():
                                            platforms[platform] = 0
                                        platforms[platform] += 1
                                if "x_mitre_defense_bypassed" in item.keys():
                                    for defence in item["x_mitre_defense_bypassed"]:
                                        if defence not in defences.keys():
                                            defences[defence] = 0
                                        defences[defence] += 1
                                if "x_mitre_data_sources" in item.keys():
                                    for datasource in item["x_mitre_data_sources"]:
                                        if datasource not in datasources.keys():
                                            datasources[datasource] = 0
                                        datasources[datasource] += 1
                                if "external_references" in item.keys():
                                    for datasource in item["external_references"]:
                                        if "source_name" in datasource.keys():
                                            if datasource["source_name"] != "mitre-attack" and datasource["source_name"] != "capec":
                                                if "url" in datasource.keys():
                                                    if "description" in datasource.keys():
                                                        attackreferences[datasource["url"]] = datasource["description"]
                    if item["type"] == "malware" or item["type"] == "tool":
                        for reference in references[name]:
                            if item["id"] == reference:
                                if debugflag == True:
                                    pprint(item)
                                if item["name"] not in tools.keys():
                                    tools[item["name"]] = 0
                                tools[item["name"]] += 1
                                if "x_mitre_platforms" in item.keys():
                                    for platform in item["x_mitre_platforms"]:
                                        if platform not in platforms.keys():
                                            platforms[platform] = 0
                                        platforms[platform] += 1
                                if "external_references" in item.keys():
                                    for datasource in item["external_references"]:
                                        if "source_name" in datasource.keys():
                                            if datasource["source_name"] != "mitre-attack" and datasource["source_name"] != "capec":
                                                if "url" in datasource.keys():
                                                    if "description" in datasource.keys():
                                                        toolreferences[datasource["url"]] = datasource["description"]
            print("# Threat groups\n")
            for name in descriptions.keys():
                print("* " + name)
                if verboseflag:
                    print(descriptions[name])
            print()
            print("# Validate the following attacks\n")
            for attack in attacks.keys():
               print("* " + attack + " - " + str(attacks[attack]))
            print()
            print("# Validate the following phases\n")
            for phase in phases.keys():
               print("* " + phase + " - " + str(phases[phase]))
            print()
            print("# Validate the following platforms\n")
            for platform in platforms.keys():
               print("* " + platform + " - " + str(platforms[platform]))
            print()
            print("# Validate the following defences\n")
            for defence in defences.keys():
               print("* " + defence + " - " + str(defences[defence]))
            print()
            print("# Validate the following data sources\n")
            for datasource in datasources.keys():
               print("* " + datasource + " - " + str(datasources[datasource]))
            print()
            print("# Review the following attack references\n")
            for externalreference in attackreferences.keys():
               print("* " + externalreference + " - " + str(attackreferences[externalreference]))
            print()
            print("# Validate the following tools and malware\n")
            for attack in tools.keys():
               print("* " + attack + " - " + str(tools[attack]))
            print()
            print("# Review the following tool and malware references\n")
            for toolreference in toolreferences.keys():
               print("* " + toolreference + " - " + str(toolreferences[toolreference]))
            print()
