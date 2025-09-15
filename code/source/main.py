import sys
import os
import sqlite3
import subprocess
import xml.etree.ElementTree as xml
import Levenshtein  # python-Levenshtein library for distance

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
        cur.execute("DROP TABLE IF EXISTS cpe_db")
        conn.commit()
        conn.close()
    else:
        print(f"No existing database found. Will create {DB_NAME} fresh.")

def run_parser():
    """Run parser.py to rebuild the database."""
    print("Rebuilding database with parser.py...")
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

def parse_pom(pom_path):
    """Extract dependencies from a POM file."""
    tree = xml.parse(pom_path)
    root = tree.getroot()
    ns = {"mvn": "http://maven.apache.org/POM/4.0.0"}

    dependencies = []
    for dep in root.findall(".//mvn:dependency", ns):
        group_id = dep.find("mvn:groupId", ns)
        artifact_id = dep.find("mvn:artifactId", ns)
        version = dep.find("mvn:version", ns)

        group_id = group_id.text if group_id is not None else "UNKNOWN"
        artifact_id = artifact_id.text if artifact_id is not None else "UNKNOWN"
        version = version.text if version is not None else "UNKNOWN"

        dependencies.append((group_id, artifact_id, version))
    return dependencies

def version_in_range(dep_version, start, end, start_inc, end_inc):
    """Check if a dependency version falls in a vulnerable range."""
    if start == "0" and end == "0":
        return True  # no version restriction

    if start != "0":
        if start_inc and dep_version < start:
            return False
        if not start_inc and dep_version <= start:
            return False

    if end != "0":
        if end_inc and dep_version > end:
            return False
        if not end_inc and dep_version >= end:
            return False

    return True

def detect_vulnerabilities(dependencies):
    """Match dependencies against vulnerabilities in the DB and write results to output.txt."""
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()

    found_any = False

    with open("output.txt", "w") as f:
        f.write("Known security vulnerabilities detected:\n\n")

        for group_id, artifact_id, version in dependencies:
            dep_name = f"{group_id}:{artifact_id}"

            cur.execute("SELECT cpe_uri, cve_id, description, version_start, version_end, start_inc, end_inc FROM cpe_db")
            rows = cur.fetchall()

            for cpe_uri, cve_id, description, v_start, v_end, s_inc, e_inc in rows:
                # Normalize to strings
                v_start = str(v_start) if v_start else "0"
                v_end = str(v_end) if v_end else "0"
                s_inc = int(s_inc) if s_inc is not None else 0
                e_inc = int(e_inc) if e_inc is not None else 0

                # Heuristic matching: only against cpe_uri
                dist_uri = Levenshtein.distance(dep_name, cpe_uri)

                if dist_uri <= 5:  # tweakable threshold
                    if version_in_range(version, v_start, v_end, s_inc, e_inc):
                        found_any = True
                        f.write(f"Dependency: {artifact_id}\n")
                        if v_start != "0" or v_end != "0":
                            range_str = f">= {v_start}" if v_start != "0" else ""
                            if v_end != "0":
                                if range_str:
                                    range_str += " "
                                range_str += ("<=" if e_inc else "<") + f" {v_end}"
                            f.write(f"Version(s): {range_str}\n")
                        else:
                            f.write(f"Version(s): {version}\n")
                        f.write("Vulnerabilities:\n")
                        f.write(f"- {cve_id}\n\n")

        if not found_any:
            f.write("No vulnerabilities found.\n")

    conn.close()


def main():
    if len(sys.argv) != 3:
        print("Error: Incorrect number of arguments.\n")
        print_usage()
        sys.exit(1)

    mode = sys.argv[1]
    pom_path = sys.argv[2]

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

    dependencies = parse_pom(pom_path)
    detect_vulnerabilities(dependencies)

if __name__ == "__main__":
    main()
