import requests


def get_cves_for_cpe(cpe):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    query_url = f"{base_url}?cpeName={cpe}&startIndex=0&resultsPerPage=100"

    response = requests.get(query_url)
    if response.status_code == 200:
        data = response.json()
        if "result" in data and "CVE_Items" in data["result"]:
            cve_list = []
            for cve_item in data["result"]["CVE_Items"]:
                cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]
                cve_list.append(cve_id)
            return cve_list
    return []


def main():
    cpe_to_search = "cpe:2.3:o:microsoft:windows_server_2012:r2:x64:1607"
    cves = get_cves_for_cpe(cpe_to_search)

    if cves:
        print(f"Found {len(cves)} CVEs for {cpe_to_search}:")
        for cve_id in cves:
            print(cve_id)
    else:
        print(f"No CVEs found for {cpe_to_search}")


if __name__ == "__main__":
    main()
