# MasonBayesian-ATTaCK-Graph
GMU CYSE-650 - Summer 2024 Project - Cyber Risk Modeling and Analysis Tools

## Overview
Software translates MITRE's ATT&CK framework into a baysian node representation. Input files must be in .json format and conform to MITRE standards as of July 2024 (ATT&CK 15.1), Output files will be in a .net format.


## Use

1. Place .json files into the input directory
2. Run `python JSONtoNET` in main directory
3. Terminal will display whether the conversion was a success/failure
4. If successful, output .net files will be available in the output directory, with copies of the original .json files in a backup sub-directory
5. Graphical output of these .net files works best with Java-based UnBBayes applicaiton

Notes:
* Software is distributed with three sample .json files for testing purposes, use the MITRE ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator) to generate your own
* This software depends on presence of 'enterprise-attack.json' file. Distributed version is from May 2024, a more up-to-date version can be found on the MITRE Github (https://github.com/mitre/cti/tree/master/enterprise-attack)
* Software is designed for integration with UnBBayes (https://unbbayes.sourceforge.net/)
* Further project documentation is distributed with this repository


## Liscense
BSD 2-Clause License
