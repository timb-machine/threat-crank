# threat-crank

This repository contains all of the scripts and source code for Threat Crank.

More details can be found at Portcullis Labs.

For any queries about the contents of this repository please contact [Security Advisory EMEAR](mailto:css-adv-outreach@cisco.com).

* What is Threat Crank? Threat Crank makes useful information from the ATT&CK TTP project

* What can it do? Currently it has 3 modes of operation:
 
 1. Report mode – generates a formatted text file containing actors and associated TTPs:
  * Kill chain phases
  * Targeted platforms
  * Affected defences
  * Sources of useful telemetry
  * Referenced third party TTP sources
  * Attack tools used
  * Referenced third party tool references
 2. Wargame mode – generates a random kill chain
 3. Gephi mode – outputs a Gephi formatted list that can be used to construct a directed graph of the kill chain including:
  * Threat groups
  * Kill chain phases
  * TTPs

Each of these will generate a full list based on the combined ATT&CK TTP project or you can apply various filters including actors, targeted industries, targeted regions, targeted platforms. Three examples can be seen below:
 
    ./threat-crank.py -r ".* Russia .*" -p "Windows" -v  - generates a (verbose, including descriptions) threat report of actors that operate in Russia and target Windows
    ./threat-crank.py -G unified -a "Equation" - generates a Gephi formatted list that can be used to draw the Equation groups kill chain in Gephi (“unified” forces all affected threat actors who share the same TTPs to share the nodes vs representing common TTPs per actor
    ./threat-crank.py -W 5 -i “.* financial .*” - generates 5 rounds of random kill chain picked form the TTPs of actors that target the financial services community

Note that the filter flags (-a, -i, -r and -p) can be used to filter irrespective of the output mode – these are just some examples. Filters are regexes so you can do more interesting things if you feel the need.
 
Why might this be useful? Report mode can be used for red/purple/TI/threat modelling (either in scoping or delivery). Wargame mode can be used for red/purple/IR table top (again, scoping or delivery). Gephi mode can be used to draw pretty graphs to illustrate any collateral that you can think of and make us all look smart.
 
You can also use -A to point it at another ATT&CK JSON database e.g. the mobile one (ICS isn’t yet in JSON and pre-ATT&CK needs some tweaks to the code).
 
Let me know if you have other ideas that you’d like to explore. Once I’ve added support for filtering by tool/malware, there should be enough code in there to do reverse attribution (subject of course to the limits of the ATT&CK TTP project).
