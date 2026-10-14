import os

print("--- Starting the Smart Python Secret Sniffer ---")

target_file = "Dockerfile"

if not os.path.exists(target_file):
    print("Error: No Dockerfile found to scan!")
    exit(1)

# DEVSECOPS UPGRADE: Try standard web format first (utf-8). 
# If Windows breaks it with an 0xff signature, fall back to Microsoft format (utf-16) automatically!
try:
    with open(target_file, "r", encoding="utf-8") as file:
        lines = file.readlines()
except UnicodeDecodeError:
    with open(target_file, "r", encoding="utf-16") as file:
        lines = file.readlines()

vulnerabilities_found = 0

for line_number, text in enumerate(lines, 1):
    if "PASSWORD" in text.upper() or "SECRET" in text.upper():
        print(f"ALERT: Potential leaked secret found on line {line_number}!")
        print(f"   Dangerous text: {text.strip()}")
        vulnerabilities_found += 1

if vulnerabilities_found > 0:
    print(f"\nAudit Failed! Found {vulnerabilities_found} security flaws.")
else:
    print("\nAudit Passed! The file looks clean and safe.")

    # adding a try/except block to catch and handle encoding differences