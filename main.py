import hashlib
import re
import rsa
from lxml import html
import requests
import base64

URL = 'https://www.dns-shop.ru/product/c0c695dfa0d83330/marsrutizator-mikrotik-hex-rb750gr3-5xgbe/'
FINGERPRINT = 'a6c67adbf25ff2552f856d5d33e906c4'


def md5(data, salt=''):
    bdata = data + salt
    return hashlib.md5(bytes(bdata, 'UTF-8')).hexdigest().lower()


def rsa_decrypt(data, key):
    pk = rsa.key.PrivateKey.load_pkcs1(bytes(key, 'UTF-8'), 'PEM')
    return rsa.decrypt(base64.decodebytes(bytes(data, 'UTF-8')), pk).decode('UTF-8')


def test_md5():
    data = 'hello'
    rhash = '5d41402abc4b2a76b9719d911017c592'
    mhash = md5(data)
    if rhash == mhash:
        print('test md5 ok')
    else:
        print(f'test md5 fail! {rhash} != {mhash}')


def print_headers(headers):
    for header in headers:
        print(f'\t{header}: {headers.get(header)}')


def get_dom(url):
    session = requests.session()

    session.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.141 YaBrowser/22.3.2.644 Yowser/2.5 Safari/537.36'
    session.headers['Host'] = 'www.dns-shop.ru'
    session.headers['Accept-Language'] = 'ru, en; q = 0.9'
    session.headers['Accept-Encoding'] = 'gzip, deflate, br'
    session.headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
    session.headers['sec-ch-ua'] = '" Not A;Brand";v="99", "Chromium";v="98", "Yandex";v="22"'
    session.headers['sec-ch-ua-mobile'] = '?0'
    session.headers['sec-ch-ua-platform'] = '"Windows"'
    session.headers['Sec-Fetch-Dest'] = 'document'
    session.headers['Sec-Fetch-Mode'] = 'navigate'
    session.headers['Sec-Fetch-Site'] = 'none'
    session.headers['Sec-Fetch-User'] = '?1'
    session.headers['Upgrade-Insecure-Requests'] = '1'
    session.headers['Cache-Control'] = 'no-cache'

    response = session.get(url)

    print('request #1 headers:')
    print_headers(response.request.headers)
    print('response #1 headers:')
    print_headers(response.headers)

    with open('index1.html', 'wb') as f:
        f.write(response.content)

    content = response.content.decode('UTF-8')

    # parse rsa key
    m = re.search('decrypt.setPrivateKey\(\"([^"]*)\"', content)
    rsa_key = m.group(1)
    print(f'rsa_key="{rsa_key}"')

    # parse rda encrypted data
    m = re.search('decrypt.decrypt\(\"([^"]*)\"', content)
    rsa_data = m.group(1)
    print(f'rsa_data="{rsa_data}"')

    # parse ipp_uid
    m = re.search('document.cookie=\"ipp_uid=([^;]*);', content)
    ipp_uid = m.group(1)
    print(f'ipp_uid="{ipp_uid}"')

    # parse salt
    # m = re.search('salt=\"([^"]*)\"', content)
    # salt = m.group(1)
    # print(f'salt="{salt}"')

    # decrypt data
    decrypted_data = rsa_decrypt(rsa_data, '-----BEGIN RSA PRIVATE KEY-----\n' + rsa_key + '\n-----END RSA PRIVATE KEY-----')
    print(f'decrypted_data="{decrypted_data}"')

    # fp_md5 = md5(FINGERPRINT, salt)
    # print(f'md5(fingerprint+salt)="{fp_md5}"')

    session.cookies.set('ipp_key', decrypted_data, domain='www.dns-shop.ru', path='/')
    session.cookies.set('ipp_uid', ipp_uid, domain='www.dns-shop.ru', path='/')
    # session.cookies.set('ipp_sign', FINGERPRINT + '_' + salt + '_' + fp_md5, domain='www.dns-shop.ru', path='/')

    response = session.get(url)

    print('request #2 headers:')
    print_headers(response.request.headers)
    print('response #2 headers:')
    print_headers(response.headers)

    #dom = html.fromstring(response.content)
    with open('index2.html', 'wb') as f:
        f.write(response.content)


if __name__ == '__main__':
    #test_md5()
    get_dom(URL)
    # print(rsa_decrypt(RSA_DATA, RSA_PRIV_KEY))
