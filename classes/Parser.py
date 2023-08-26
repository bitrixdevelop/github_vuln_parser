""" Class Parser for parsing github advisories """
import json
import requests
from bs4 import BeautifulSoup


class Parser:
    """ Class for parsing github advisories """
    def __init__(self, url):
        self.url = url
        response = requests.get(url, timeout=60)
        self.soup = BeautifulSoup(response.text, "lxml")
        self.pages_total = self.get_count_pages()

    def get_count_pages(self):
        """ Get count pages """
        self.pages_total = int(
            self.soup.find("div", class_="pagination").find_all("a")[-2].text
        )
        return self.pages_total

    def get_advisories(self):
        """ Get advisories """
        advisories = []
        for page in range(1, self.pages_total + 1):
            response = requests.get(self.url + f"&page={page}", timeout=60)
            self.soup = BeautifulSoup(response.text, "lxml")
            advisories_arr = self.soup.find_all("div", class_="Box-row")
            for advisory in advisories_arr:
                cve_id = ""
                ghsa_id = ""
                pull_request_link = ""
                package_name = ""
                affected_version = ""
                patched_version = ""
                advisory_title = advisory.find("a", class_="Link--primary")
                advisory_span = advisory.find("span", class_="Label")

                detail_response = requests.get(
                    "https://github.com" + advisory_title.get("href"),
                    timeout=60
                )
                detail_soup = BeautifulSoup(detail_response.text, "lxml")
                discussion_sidebar = detail_soup.find_all(
                    "div", class_="discussion-sidebar-item"
                )
                for sidebar in discussion_sidebar:
                    sidebar_title = sidebar.find("h3")

                    if sidebar_title:
                        if sidebar_title.text == "CVE ID":
                            cve_id = (
                                sidebar.find("div", class_="color-fg-muted")
                                .text.replace("\n", "")
                                .strip()
                            )

                        if sidebar_title.text == "GHSA ID":
                            ghsa_id = (
                                sidebar.find("div", class_="color-fg-muted")
                                .text.replace("\n", "")
                                .strip()
                            )

                content_blocks = detail_soup.find_all("div", class_=["Box--responsive"])
                header_block = content_blocks[0]
                if header_block:
                    header_subblocks = header_block.find_all("div", class_="float-left")
                    if header_subblocks:
                        package_name = (
                            header_subblocks[0]
                            .find(
                                "span", class_=["f4", "color-fg-default", "text-bold"]
                            )
                            .text
                        )
                        affected_version_array = header_subblocks[1].find_all(
                            "div", class_=["f4", "color-fg-default"]
                        )
                        # Преобразовываем массив в строку с разделителем ', '
                        affected_version = ", ".join(
                            [
                                affected_version_item.text.replace("\n", "").strip()
                                for affected_version_item in affected_version_array
                            ]
                        )
                        patched_version_array = header_subblocks[2].find_all(
                            "div", class_=["f4", "color-fg-default"]
                        )

                        patched_version = ", ".join(
                            [
                                patched_version_item.text.replace("\n", "").strip()
                                for patched_version_item in patched_version_array
                            ]
                        )

                central_block = content_blocks[1]
                if central_block:
                    # Trying to find link a with attr data-hovercard-type="pull_request"
                    pull_request_links = central_block.find_all(
                        "a", attrs={"data-hovercard-type": "pull_request"}
                    )
                    if pull_request_links:
                        pull_request_link = ", ".join(
                            [
                                pull_request_link_item.get("href")
                                for pull_request_link_item in pull_request_links
                            ]
                        )

                arr_advisory = {
                    "title": advisory_title.text.replace(
                        "\n                      ", ""
                    ).strip(),
                    "advisory_url": "https://github.com" + advisory_title.get("href"),
                    "severity": advisory_span.text.strip(),
                    "cve_id": cve_id,
                    "ghsa_id": ghsa_id,
                    "package_name": package_name,
                    "affected": affected_version,
                    "patched": patched_version,
                    "patch": pull_request_link,
                }

                advisories.append(arr_advisory)

        return json.dumps(advisories, indent=4, ensure_ascii=False)

    def convert_json_to_csv(self):
        """ Convert json to csv """
        advisories = json.loads(self.get_advisories())
        csv = "Title;Advisory URL;" \
              "Severity;CVE;GHSA;Package Name;" \
              "Affected Version;Patched Version;Patch;\n"
        for advisory in advisories:
            csv += f"{advisory['title']};" \
                   f"{advisory['advisory_url']};" \
                   f"{advisory['severity']};" \
                   f"{advisory['cve_id']};" \
                   f"{advisory['ghsa_id']};" \
                   f"{advisory['package_name']};" \
                   f"{advisory['affected']};" \
                   f"{advisory['patched']};" \
                   f"{advisory['patch']};\n"

        # Формируем csv-файл и отдаем на скачивание
        with open("advisories.csv", "w", encoding="UTF-8") as file:
            file.write(csv)

        return csv
