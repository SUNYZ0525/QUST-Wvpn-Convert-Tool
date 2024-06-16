import re
from Crypto.Cipher import AES
from urllib.parse import urlparse
import webbrowser

# 本工具参照开源工具开发，并未深入了解加密算法，可能存在潜在问题
# https://wpn.citrons.cc/

VPN_ROOT_URL = "https://wvpn.qust.edu.cn"
KEY = b'wrdvpnisthebest!'
IV = b'wrdvpnisthebest!'
PROTOCOLS = ['http', 'https', 'ssh', 'vnc', 'telnet', 'rdp']

def text_right_append(text, mode):
    segment_byte_size = 16 if mode == 'utf8' else 32
    append_length = segment_byte_size - (len(text) % segment_byte_size)
    return text.ljust(len(text) + append_length, '0')

def create_aes_cfb(key, iv):
    return AES.new(key, AES.MODE_CFB, iv, segment_size=128)

def encrypt_text(text, key, iv):
    aes_cfb = create_aes_cfb(key, iv)
    text_bytes = text_right_append(text, 'utf8').encode('utf-8')
    encrypt_bytes = aes_cfb.encrypt(text_bytes)
    return iv.hex() + encrypt_bytes.hex()[:len(text) * 2]

def decrypt_text(text, key, iv):
    aes_cfb = create_aes_cfb(key, iv)
    text_length = (len(text) - len(iv) * 2) // 2
    decrypt_bytes = aes_cfb.decrypt(bytes.fromhex(text_right_append(text[2 * len(iv):], 'hex')))
    try:
        return decrypt_bytes.decode('utf-8', errors='ignore')[:text_length]
    except UnicodeDecodeError:
        return 'Decoding error'

def extract_protocol_and_url(url):
    for protocol in PROTOCOLS:
        proto_length = len(protocol) + 3
        if url[:proto_length].lower() == protocol + '://':
            return {'protocol': protocol, 'url': url[proto_length:]}
    return {'protocol': 'http', 'url': url}

def encrypt_url(raw_url, key=KEY, iv=IV):
    protocol_and_url = extract_protocol_and_url(raw_url)
    protocol, url_string = protocol_and_url['protocol'], protocol_and_url['url']
    ipv6 = ''
    url_string = re.sub(r'\[[0-9a-fA-F:]+?\]', lambda match: ipv6 + match.group(), url_string)
    segments = url_string.split('?')[0].split(':')
    port = ''
    if len(segments) > 1:
        port = segments[1].split('/')[0]
        url_string = url_string[:len(segments[0])] + url_string[len(segments[0]) + len(port) + 1:]
    i = url_string.find('/')
    if i == -1:
        host, path = url_string, ''
    else:
        host, path = url_string[:i], url_string[i:]
    host = encrypt_text(host, key, iv)
    if ipv6:
        host = ipv6
    if port:
        return f'/{protocol}-{port}/{host}{path}'
    else:
        return f'/{protocol}/{host}{path}'
    
def decrypt_url(encrypted_url, key=KEY, iv=IV):
    try:
        if not encrypted_url:
            return {'url': '', 'error': None}
        url = urlparse(encrypted_url)
        segments = url.path.split('/')
        protocol, port = segments[1].split('-') if '-' in segments[1] else (segments[1], None)
        decrypted_host = decrypt_text(segments[2], key, iv)
        remaining_segments = '/'.join(segments[3:])
        return f"{protocol}://{decrypted_host}{(':' + port) if port else ''}/{remaining_segments}"
    except Exception as error:
        print(error)
        return 'Unknown error, check your URL.'


def url_i2p(internal_url):
    wvpn_url = "https://wvpn.qust.edu.cn"
    encrypted_url = encrypt_url(internal_url)
    public_url = wvpn_url + encrypted_url
    return public_url

def url_p2i(public_url):
    wvpn_url = "https://wvpn.qust.edu.cn"
    encrypted_url = public_url[len(wvpn_url):]
    internal_url = decrypt_url(encrypted_url)
    if isinstance(internal_url, dict):
        if 'error' in internal_url:
            return "Decryption Error:", internal_url['error']
        else:
            return "Decrypted URL:", internal_url['url']
    else:
        return internal_url

if __name__ == "__main__":

    
    # url = "ssh://10.9.21.236:25995"
    # url - "https://wvpn.qust.edu.cn/ssh-25995/77726476706e69737468656265737421a1a70fc56962391e2c5bdf"
    
    print("Welcome to QUST Wvpn Convert Tool!")
    print("1. 内网URL转公网")
    print("2. 公网URL转内网")

    choice = input("Please enter your choice (1 or 2): ")

    if choice == "1":
        url_internal = input("输入内网URL: ")
        public_url = url_i2p(url_internal)
        print("公网URL: ", public_url)
        webbrowser.open(public_url)

    elif choice == "2":
        public_url = input("输入公网URL: ")
        url_internal = url_p2i(public_url)
        print("内网URL: ", url_internal)

    else:
        print("Invalid choice. Please enter either 1 or 2.")