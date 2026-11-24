import requests
import pandas as pd
import time

print("[*] Connecting to Official NIST NVD API 2.0 (Fetching Modern CVSS v3.1 Records)...")

url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
records = []
results_per_page = 2000
target_records = 25000  # العدد المطلوب في التقرير
start_index = 180000    # البدء من الثغرات الحديثة الغنية ببيانات CVSS v3.1

while len(records) < target_records:
    params = {
        "resultsPerPage": results_per_page,
        "startIndex": start_index
    }
    try:
        response = requests.get(url, params=params, timeout=30)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break
            
            for item in vulnerabilities:
                if len(records) >= target_records:
                    break
                cve = item.get("cve", {})
                cve_id = cve.get("id", "N/A")
                
                descriptions = cve.get("descriptions", [])
                desc_text = descriptions[0].get("value", "") if descriptions else ""
                
                metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
                if not metrics:
                    metrics = cve.get("metrics", {}).get("cvssMetricV30", [])
                
                if metrics:
                    cvss_data = metrics[0].get("cvssData", {})
                    exploitability = metrics[0].get("exploitabilityScore", 2.0)
                    impact_subscore = metrics[0].get("impactScore", 3.0)
                    
                    attack_vector = cvss_data.get("attackVector", "NETWORK")
                    attack_complexity = cvss_data.get("attackComplexity", "LOW")
                    privileges_req = cvss_data.get("privilegesRequired", "NONE")
                    user_interaction = cvss_data.get("userInteraction", "NONE")
                    conf_impact = cvss_data.get("confidentialityImpact", "HIGH")
                    integ_impact = cvss_data.get("integrityImpact", "HIGH")
                    avail_impact = cvss_data.get("availabilityImpact", "HIGH")
                    base_score = cvss_data.get("baseScore", 5.0)
                    
                    desc_lower = desc_text.lower()
                    if "sql injection" in desc_lower or "xss" in desc_lower or "remote code" in desc_lower:
                        threat_category = "Application Vulnerability"
                    elif "privilege" in desc_lower or "authentication" in desc_lower or "bypass" in desc_lower:
                        threat_category = "Access Control Breach"
                    elif "encrypt" in desc_lower or "cleartext" in desc_lower or "ssl" in desc_lower:
                        threat_category = "Cryptographic Weakness"
                    elif "denial of service" in desc_lower or "dos" in desc_lower or "crash" in desc_lower:
                        threat_category = "Availability / DoS"
                    elif "leak" in desc_lower or "disclosure" in desc_lower or "exposure" in desc_lower:
                        threat_category = "Data Leakage"
                    else:
                        threat_category = "Network / Infrastructure Threat"
                    
                    likelihood = min(5, max(1, round((exploitability / 3.9) * 5)))
                    impact = min(5, max(1, round((impact_subscore / 6.0) * 5)))
                    
                    records.append({
                        "CVE_ID": cve_id,
                        "Threat_Category": threat_category,
                        "Attack_Vector": attack_vector,
                        "Attack_Complexity": attack_complexity,
                        "Privileges_Required": privileges_req,
                        "User_Interaction": user_interaction,
                        "Confidentiality_Impact": conf_impact,
                        "Integrity_Impact": integ_impact,
                        "Availability_Impact": avail_impact,
                        "Exploitability_Score": exploitability,
                        "CVSS_Base_Score": base_score,
                        "Likelihood": likelihood,
                        "Impact": impact
                    })
            print(f"[+] Fetched {len(records)} / {target_records} valid CVSS v3 records...")
            start_index += results_per_page
            time.sleep(6)
        else:
            print(f"[!] Warning: Status {response.status_code}, retrying...")
            time.sleep(10)
    except Exception as e:
        print(f"[!] Error: {e}")
        break

df = pd.DataFrame(records)
df.to_csv("data/cve_raw.csv", index=False)
print(f"\n[✓] SUCCESS! Saved {len(df)} records to data/cve_raw.csv")
