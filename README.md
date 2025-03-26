🛡️ SQLi Testing Tool

Automated SQL Injection Testing Tool with Subdomain Enumeration & SQLmap

This tool automates the subdomain enumeration, endpoint extraction, and SQL injection testing process. It combines various tools to streamline the security testing workflow.

📍 How It Works

The tool follows these steps:
1️⃣ Subdomain Enumeration (Subfinder)

    The tool runs Subfinder to discover subdomains of the target domain.

    Results are saved in subdomains.txt.

2️⃣ Live Subdomain Check (Httpx)

    It verifies which subdomains are alive by making HTTP requests.

    Results are saved in live_subdomains.txt.

3️⃣ Endpoint Extraction

    Uses Katana to extract URLs & API endpoints from live subdomains.

    Optionally, uses Waybackurls to retrieve historical endpoints.

    Saves results in final_endpoints.txt.

4️⃣ Filtering & Deduplication

    Extracts only URLs with query parameters (for potential SQL injection).

    Filters only one URL per unique parameter to avoid redundant testing.

    Saves results in unique_param_urls.txt.

5️⃣ SQL Injection Testing (SQLmap)

    Specified Testing Mode:

        User selects high-risk SQLi parameters (id=, query=, user=, etc.).

        Runs SQLmap only on endpoints containing those parameters.

    General Testing Mode:

        Runs SQLmap on all extracted parameterized URLs.

        If more than 200 endpoints, it splits them into batches.

6️⃣ Results & Reporting

    SQLmap outputs the results, including detected vulnerabilities.

    Saves vulnerable endpoints in vulnerable_endpoints.txt.

🛠️ Installation

1️⃣ Install Dependencies 

Run the following commands:
        sudo apt update
        sudo apt install -y subfinder httpx sqlmap
        go install github.com/projectdiscovery/katana/cmd/katana@latest
        go install github.com/tomnomnom/waybackurls@latest
Move installed tools to /usr/local/bin/:
        mv ~/go/bin/katana /usr/local/bin/
        mv ~/go/bin/waybackurls /usr/local/bin/


🚀 Usage

Run the script:
        python3 auto_sqli_enum.py
