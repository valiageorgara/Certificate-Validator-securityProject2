import ssl
import socket
import sys
import pem
import argparse
from datetime import datetime
import OpenSSL
from colorama import Fore
import requests
import re

_PEM_RE = re.compile(b'-----BEGIN CERTIFICATE-----\r?.+?\r?-----END CERTIFICATE-----\r?\n?', re.DOTALL)
CA_PATH = '/home/valia/PycharmProjects/decurity_new/venv/lib/python3.9/site-packages/certifi/cacert.pem'


def parse_chain(chain):
    # returns a list of certificates
    return [c.group() for c in _PEM_RE.finditer(chain)]


if __name__ == '__main__':

    # # Initialize parser
    # parser = argparse.ArgumentParser()
    #
    # # Adding optional argument
    # parser.add_argument("-url", "--Output", help="Show Output")
    #
    # # Read arguments from command line
    # args = parser.parse_args()
    # hostname = args.Output
    #
    # # check format of hostname
    # hostname = hostname.replace('http://', '').replace('https://', '').replace('/', '')
    # port = 443
    # if ':' in hostname:
    #     hostname, port = hostname.split(':')
    #
    # # check if the website exists
    # try:
    #     response = requests.get("http://" + hostname)
    #     print(Fore.GREEN + "URL is valid and exists on the internet")
    # except requests.ConnectionError as exception:
    #     sys.exit(Fore.RED + "URL does not exist on Internet")
    #
    # print("Searching validity for host: % s" % hostname)
    # print(" ")
    hostname = 'www.facebook.com'
    port = 443
    context = ssl.create_default_context()
    conn = socket.create_connection((hostname, port))
    sock = context.wrap_socket(conn, server_hostname=hostname)
    try:
        der_cert = sock.getpeercert(True)  # non-binary form
        der_cert_dict = sock.getpeercert(False)  # dictionary form
    except Exception as e:
        print('ERORRRRR')
        der_cert = b''
        der_cert_dict = {}
    finally:
        sock.close()

    pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
    byte_pem_cert = bytes(pem_cert, 'UTF-8')
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, byte_pem_cert)

    cert_subject = x509.get_subject()

    domain = cert_subject.CN
    organization = cert_subject.O
    issuer_common_name = x509.get_issuer().commonName
    issuer_country_name = x509.get_issuer().countryName
    issuer_organization_name = x509.get_issuer().organizationName
    issuer_organization_unit_name = x509.get_issuer().organizationalUnitName
    sha1_fingerprint = x509.digest('sha1').decode()
    signature_algorithm = x509.get_signature_algorithm().decode()
    # public_key = x509.get_pubkey()
    not_before = datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
    not_after = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
    valid_days_left = (not_after - datetime.now()).days
    valid_for = (not_after - not_before).days
    expiration = x509.has_expired()
    version = x509.get_version()
    serial_number = x509.get_serial_number()
    extension_count = x509.get_extension_count()

    sans = ''
    subject_alternative_names = []
    for i in range(0, extension_count):
        extension = x509.get_extension(i)
        if 'subjectAltName' in str(extension.get_short_name()):
            sans = extension.__str__().replace('DNS', '').replace(':', '')
    if sans:
        subject_alternative_names = sans.split(',')

    print(Fore.LIGHTGREEN_EX + pem_cert)
    print(Fore.LIGHTGREEN_EX + 'Domain: ' + domain)
    print(Fore.LIGHTGREEN_EX + 'Company name: ' + organization)
    print(Fore.LIGHTGREEN_EX + 'Country: ' + issuer_country_name)
    print(Fore.LIGHTGREEN_EX + 'Issuer Organization Name: ' + issuer_organization_name)
    print(Fore.LIGHTGREEN_EX + 'Version: ' + str(version))
    print(Fore.LIGHTGREEN_EX + 'Serial number: ' + str(serial_number))
    print(Fore.LIGHTGREEN_EX + 'SHA1 Fingerprint: ' + sha1_fingerprint)
    print(Fore.LIGHTGREEN_EX + 'Key Algorithm: ' + signature_algorithm)
    # Validate certificate expiration
    print(Fore.LIGHTGREEN_EX + 'Not before: ' + str(not_before))
    print(Fore.LIGHTGREEN_EX + 'Not after: ' + str(not_after))
    print(Fore.LIGHTGREEN_EX + 'Total valid for: ' + str(valid_for) + ' days ')
    print(Fore.LIGHTGREEN_EX + 'Days left: ' + str(valid_days_left))
    print(Fore.LIGHTGREEN_EX + 'Expired: ' + str(expiration))
    print(Fore.LIGHTGREEN_EX + 'Subject Alternative Names: ')
    for dns_name in subject_alternative_names:
        print(Fore.LIGHTGREEN_EX + '  DNS Name: ' + dns_name)
    print(" ")

    ca_issuers = str(der_cert_dict['caIssuers']).replace("'", "").replace("(", "").replace(")", "").replace(",", "")
    print(ca_issuers)

    with open(CA_PATH, 'rb') as file:
        ca_file = file.read()

    store = OpenSSL.crypto.X509Store()

    for _cert in pem.parse(ca_file):
        # print(_cert)
        store.add_cert(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, _cert.as_bytes()))
    # store.add_cert(x509)
    store_ctx = OpenSSL.crypto.X509StoreContext(store, x509)
    store_ctx.verify_certificate()
    # try:
    #     store_ctx.verify_certificate()
    #     print("Verify - OK")
    # except OpenSSL.crypto.X509StoreContextError as e:
    #     print(Fore.LIGHTRED_EX + "CA doesn't match, got the " 'following error from pyOpenSSL: ' + Fore.WHITE +
    #           e.args[0][2])





