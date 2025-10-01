import sys
import os
import sqlite3
import subprocess
import xml.etree.ElementTree as xml

DB_NAME = "vulnerabilities.sqlite"

def print_usage():
    print("Usage:")
    print("  python main.py detect /path/to/pom.xml")
    print("  python main.py all /path/to/pom.xml")

def clear_database():
    """Erase all data in the SQLite knowledge base."""
    if os.path.exists(DB_NAME):
        print(f"Clearing existing database: {DB_NAME}")
        conn = sqlite3.connect(DB_NAME)
        cur = conn.cursor()

        # Drop all tables
        cur.execute("DROP TABLE IF EXISTS cpe_db")
        conn.commit()
        conn.close()
    else:
        print(f"No existing database found. Will create {DB_NAME} fresh.")


def run_parser():
    """Run parser.py to rebuild the database."""
    print("Rebuilding database with parser.py...")
    # Make the pom_path absolute relative to main.py's folder
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parser_path = os.path.join(script_dir, "parser.py")

    result = subprocess.run([sys.executable, parser_path], capture_output=True, text=True)

    if result.returncode != 0:
        print("Error running parser.py:")
        print(result.stderr)
        sys.exit(1)
    else:
        print("Database rebuilt successfully.")
        print(result.stdout)
    

    

def main():
    if len(sys.argv) != 3:
        print("Error: Incorrect number of arguments.\n")
        print_usage()
        sys.exit(1)

    mode = sys.argv[1]

    pom_path = sys.argv[2]

    # Make the pom_path absolute relative to main.py's folder
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pom_path = os.path.join(script_dir, pom_path)


    if mode not in ["detect", "all"]:
        print(f"Error: Invalid mode '{mode}'.\n")
        print_usage()
        sys.exit(1)

    if not os.path.exists(pom_path):
        print(f"Error: The pom.xml file '{pom_path}' does not exist.")
        sys.exit(1)

    if mode == "detect":
        print("Detect-only mode selected.")

    elif mode == "all":
        print("Re-load & Detect mode selected.")
        clear_database()
        run_parser()
    
    tree = xml.parse(pom_path)
    root = tree.getroot()
    groupId = ""
    artifactId = ""
    version = ""

    # Maven POM uses namespaces, we need to handle them
    ns = {"mvn": "http://maven.apache.org/POM/4.0.0"}

    # Find all dependencies
    for dep in root.findall(".//mvn:dependency", ns):
        group_id = dep.find("mvn:groupId", ns)
        artifact_id = dep.find("mvn:artifactId", ns)
        version = dep.find("mvn:version", ns)

        groupId = group_id.text if group_id is not None else "UNKNOWN"
        artifactId = artifact_id.text if artifact_id is not None else "UNKNOWN"
        version = version.text if version is not None else "UNKNOWN"
        
        print(f"GroupId: {groupId}, ArtifactId: {artifactId}, Version: {version}")


if __name__ == "__main__":
    main()
