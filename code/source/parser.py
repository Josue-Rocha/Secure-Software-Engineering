import requests, gzip, json, tempfile, sqlite3
from datetime import datetime

current_year = datetime.now().year
base_url = "https://nvd.nist.gov/feeds/json/cve/2.0/"
DB_NAME = "vulnerabilities.sqlite"

con = sqlite3.connect(DB_NAME)
cur = con.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS cpe_db(cpe_uri, cve_id, description, version_start, version_end, start_inc, end_inc)")

for year in range(2002, current_year + 1):
#for year in range(2002, 2003):
    url = f"{base_url}nvdcve-2.0-{year}.json.gz"
    print(f"Fetching {url} ...")
    response = requests.get(url)

    if response.status_code != 200:
        print(f"Failed to fetch {url}")
        continue

    with tempfile.TemporaryFile() as temp:
        temp.write(response.content)
        temp.seek(0)
        with gzip.open(temp, 'rb') as f:
            file_content = f.read()
            data = json.loads(file_content)

            # Process CVEs for this year
            for entry in data['vulnerabilities']:
                cve = entry['cve']
                cve_id = cve['id']
                description = "\n".join(
                    x["value"] for x in cve['descriptions'] if x["lang"] == "en"
                )

            
                print("CVE ID: ", cve_id)
                print("Description: ", description)

            
                if not "configurations" in cve: continue
            
                #   Traverse each configuration entry to identify the list of CPEs
                for config in cve['configurations']:
                    for config_nodes in config["nodes"]:
                        for cpe_match in config_nodes["cpeMatch"]:
                            print("\n")
                            print(cpe_match)


                            cpe_uri = cpe_match.get("criteria")
                            
                            # Defaults
                            version_start = "0"
                            version_end = "0"
                            start_inc = 0
                            end_inc = 0

                            # Handle versionStart*
                            if "versionStartIncluding" in cpe_match:
                                version_start = cpe_match["versionStartIncluding"]
                                start_inc = 1
                            elif "versionStartExcluding" in cpe_match:
                                version_start = cpe_match["versionStartExcluding"]
                                start_inc = 0

                            # Handle versionEnd*
                            if "versionEndIncluding" in cpe_match:
                                version_end = cpe_match["versionEndIncluding"]
                                end_inc = 1
                            elif "versionEndExcluding" in cpe_match:
                                version_end = cpe_match["versionEndExcluding"]
                                end_inc = 0
                            
                            cur.execute("""
                                        INSERT OR IGNORE INTO cpe_db
                                        VALUES (?, ?, ?, ?, ?, ?, ?)
                            """, (cpe_uri, cve_id, description, version_start, version_end, start_inc, end_inc))
                            con.commit()
con.close()