import json
import requests
import gzip
import tempfile

# Obtain the JSON data
url = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2002.json.gz"
response = requests.get(url)


# Save the JSON feed in a temporary file
with tempfile.TemporaryFile() as temp:
    temp.write(response.content) # save gzip contents to file
    temp.seek(0) # reset the file handler to the beginning of file
    with gzip.open(temp, 'rb') as f:
        file_content = f.read()

        data = json.loads(file_content)

        # Extract the relevant information
        for entry in data['vulnerabilities']:
            cve = entry['cve']
            cve_id = cve['id']
            cve_description = "\n".join(x["value"] for x in cve['descriptions'] if x["lang"] == "en")
            
            print("\n\n\n\n\n")
            
            print("CVE ID: ", cve_id)
            print("Description: ", cve_description)

            print("\n-----------------------------------------------------------------\n")
            
            if not "configurations" in cve: continue
            
            # Traverse each configuration entry to identify the list of CPEs
            for config in cve['configurations']:
                for config_nodes in config["nodes"]:
                    for cpe_match in config_nodes["cpeMatch"]:
                        print("\n")
                        print(cpe_match)

            
    
            