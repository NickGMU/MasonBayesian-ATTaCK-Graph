import json
import os
import shutil
import numpy as np
import sys
from pgmpy.models import BayesianNetwork
from pgmpy.factors.discrete import TabularCPD
from pgmpy.global_vars import logger

logger.disabled = True

# Directories
directoryIn = "JSON Input Files"
directoryOut = "NET Output Files"
directoryBackup = os.path.join("NET Output Files", "JSON Backups")
risk = "Risk"

# Create directories if they don't exist
os.makedirs(directoryIn, exist_ok=True)
os.makedirs(directoryOut, exist_ok=True)
os.makedirs(directoryBackup, exist_ok=True)

files = os.listdir(directoryIn)

def JSONtoNET(model, filename):
    with open(filename, 'w') as f:
        # Write header to .net file
        f.write("net\n{\n")
        f.write("    node_size = (0 0);\n")
        f.write('    name = "New BN";\n')
        f.write('    UnBBayes_Color_Probabilistic_Description = "-256";\n')
        f.write('    UnBBayes_Color_Probabilistic_Explanation = "-16711936";\n')
        f.write("}\n")
        x, y2, offset, topNode, lineBreak = 0, 100, False, False, False

        # Evaluate nodes
        for node in model.nodes():
            if not topNode and model.get_parents(node):
                topNode, lineBreak = True, True
            if x > 1000 or lineBreak:
                x, y2, lineBreak = np.random.randint(0, 100), y2 + 50, False
            x += 150
            y = y2 + 50 if offset else y2
            offset = not offset
            if node == risk:
                x, y = 500, y2 + 150

            # Write nodes to .net file
            f.write(f"node {node}\n{{\n    label = \"{node}\";\n    position = ({x} {y});\n    states = (\"False\" \"True\");\n}}\n")
        
        # pgmpy/NuPY CPD
        for cpd in model.get_cpds():
            node = cpd.variable
            upNode = model.get_parents(node)
            f.write(f"potential ({node}")
            if upNode:
                f.write(f" | {' '.join(upNode)}")
            f.write(")\n{\n    data = ")

            err = np.transpose(cpd.values, tuple(range(cpd.values.ndim - 1, -1, -1))).flatten() if cpd.values.ndim > 1 else cpd.values.flatten()
            f.write("(" + " ".join(f"{p:.6f}" for p in err) + ");\n}\n")

def bayesian_model(techniques):
    catTactics = {'Credential_Access', 'Persistence', 'Lateral_Movement'}
    model = BayesianNetwork()
    tactics = {}

    for technique in techniques:
        catID = technique['name']
        model.add_node(catID)
        tactic = technique['tactic'].replace('-', '_').replace('/', '_').title()
        tactics.setdefault(tactic, []).append(catID)

    # Add nodes
    for tactic, catIDs in tactics.items():
        model.add_node(tactic)
        model.add_edges_from([(catID, tactic) for catID in catIDs])
    model.add_node(risk)
    model.add_edges_from([(tactic, risk) for tactic in tactics])
    for technique in techniques:
        prob = setProb(technique['score'])
        cpd = TabularCPD(technique['name'], 2, [[1 - prob], [prob]])
        model.add_cpds(cpd)

    # pgmpy CPD function
    def setTableCPD(width, logic):
        tableCPD = np.zeros((2, 2 ** width))
        for i in range(2 ** width):
            localNodes = format(i, f'0{width}b')
            if logic == 'AND':
                tableCPD[1][i] = 1.0 if all(int(bit) for bit in localNodes) else 0.0
            else:  # OR logic
                tableCPD[1][i] = 1.0 if any(int(bit) for bit in localNodes) else 0.0
        tableCPD[0] = 1 - tableCPD[1]
        return tableCPD

    for tactic in tactics:
        upNode = model.get_parents(tactic)
        logic = 'AND' if tactic in catTactics else 'OR'
        tableCPD = setTableCPD(len(upNode), logic)
        cpd = TabularCPD(tactic, 2, tableCPD, evidence=upNode, evidence_card=[2] * len(upNode))
        model.add_cpds(cpd)

    upNode = model.get_parents(risk)
    tableCPD = setTableCPD(len(upNode), 'OR')
    cpd = TabularCPD(risk, 2, tableCPD, evidence=upNode, evidence_card=[2] * len(upNode))
    model.add_cpds(cpd)

    return model

# Load MITRE STIX Template data
stix_file = 'enterprise-attack.json'
with open(stix_file, 'r') as f:
    stix_data = json.load(f)

# Set RiskProbability
def setProb(score):
    if 0 <= score <= 100:
        return score / 100.0
    else:
        return 0.0

fileTokens = {}
for obj in stix_data['objects']:
    if obj['type'] == 'attack-pattern':
        for xref in obj.get('external_references', []):
            if xref.get('source_name') == 'mitre-attack':
                fileTokens[xref['external_id']] = obj['name'].replace(' ', '_').replace('-', '_').replace('/', '_')

# Process each JSON file in the input directory
for file_name in files:
    if file_name.endswith('.json'):
        input_file_path = os.path.join(directoryIn, file_name)

        with open(input_file_path, 'r') as f:
            data = json.load(f)

        # Map technique IDs to names
        catTechniques = data['techniques']
        for technique in catTechniques:
            technique['name'] = fileTokens.get(technique['techniqueID'], technique['techniqueID'])

        bayModel = bayesian_model(catTechniques)
        if bayModel.check_model():
            print(f"Bayesian model for {file_name} succeeded")
        else:
            print(f"Bayesian model for {file_name} did not succeed, check file for corruption")

        # Export to .net file
        net_file_name = os.path.splitext(file_name)[0] + '.net'
        net_file_path = os.path.join(directoryOut, net_file_name)
        JSONtoNET(bayModel, net_file_path)
        print(f"NET File {net_file_name} written to {net_file_path}")

        # Move the original file to the backup directory
        backup_file_path = os.path.join(directoryBackup, file_name)
        shutil.move(input_file_path, backup_file_path)
        print(f"JSON File {file_name} moved to {directoryBackup}")
