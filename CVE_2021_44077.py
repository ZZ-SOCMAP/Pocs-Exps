# title: Zoho ManageEngine ServiceDesk Plus - Remote Code Execution CVE-2021-44077
# author: antx
# cveid: CVE-2021-44077

from poctools import BasicPoc


class APoc(BasicPoc):
    def __init__(self):
        super(APoc, self).__init__()
        self.name = 'A-Poc'

    def verify(self, url: str):
        url = url.rstrip("/")
        target = f"{url}/RestAPI/ImportTechnicians"
        try:
            resp = self.get(target)
            if resp.status_code == 200 and '<form name="ImportTechnicians"' in resp.text:
                return True
        except Exception as e:
            pass
        return False


if __name__ == '__main__':
    target = 'http://127.0.0.1'
    tp = APoc()
    result = tp.run(url=target)
    print(f'{target} -> {result}')