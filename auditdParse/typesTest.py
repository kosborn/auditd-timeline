import yaml

a = open('types.yaml','r').read()

print yaml.load(a)

types =  yaml.dump(yaml.load(a),default_flow_style=False)
print types
