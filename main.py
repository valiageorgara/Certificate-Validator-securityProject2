import sys
from socket import socket
import certifi
from OpenSSL import SSL
import idna
import argparse
from datetime import datetime
from colorama import Fore
import requests
import sys
from requests.exceptions import ConnectionError

if __name__ == '__main__':

    # Initialize parser
    parser = argparse.ArgumentParser(prog='main.py', description="example: main.py -url facebook.com")

    # Adding optional argument
    parser.add_argument("-url", "--url", help="hostname as input")

    # Read arguments from command line
    args = parser.parse_args()
    hostname = args.url

    # check format of hostname
    hostname = hostname.replace('http://', '').replace('https://', '').replace('/', '')
    port = 443
    if ':' in hostname:
        hostname, port = hostname.split(':')

    print(" ")
    print(Fore.LIGHTMAGENTA_EX + "=======================================================")
    print(Fore.LIGHTMAGENTA_EX + "Searching validity for host: % s" % hostname)
    print(Fore.LIGHTMAGENTA_EX + "=======================================================")
    print(" ")

    hostname_idna = idna.encode(hostname)
    sock = socket()

    try:
        sock.connect((hostname, port))
    except OSError as e:
        print(Fore.LIGHTRED_EX + "Caught exception: " + str(e))
        sys.exit()

    peer_name = sock.getpeername()

    ctx = SSL.Context(SSL.SSLv23_METHOD)  # most compatible
    ctx.load_verify_locations(cafile=certifi.where())

    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE

    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(hostname_idna)
    sock_ssl.do_handshake()
    chain=sock_ssl.get_peer_cert_chain()

    print(Fore.LIGHTMAGENTA_EX + "Certificate trusted chain:")
    print(Fore.LIGHTMAGENTA_EX + "=======================================================")

    for (idx, cert) in enumerate(chain):
        # print(f'{idx} subject: {cert.get_subject()}')
        # print(f'  issuer: {cert.get_issuer()}')
        # print(f'  fingerprint: {cert.digest("sha1")}')
        root_issuer = cert.get_issuer().CN
        print(Fore.RESET + root_issuer)

    cert = sock_ssl.get_peer_certificate()
    cert_subject = cert.get_subject()

    domain = cert_subject.CN
    organization = cert_subject.O
    issuer_common_name = cert.get_issuer().commonName
    issuer_country_name = cert.get_issuer().countryName
    issuer_organization_name = cert.get_issuer().organizationName
    issuer_organization_unit_name = cert.get_issuer().organizationalUnitName
    sha1_fingerprint = cert.digest('sha1').decode()
    signature_algorithm = cert.get_signature_algorithm().decode()
    not_before = datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
    not_after = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
    valid_days_left = (not_after - datetime.now()).days
    valid_for = (not_after - not_before).days
    expiration = cert.has_expired()
    version = cert.get_version()
    serial_number = cert.get_serial_number()
    extension_count = cert.get_extension_count()

    sans = ''
    subject_alternative_names = []
    for i in range(0, extension_count):
        extension = cert.get_extension(i)
        if 'subjectAltName' in str(extension.get_short_name()):
            sans = extension.__str__().replace('DNS', '').replace(':', '')
    if sans:
        subject_alternative_names = sans.split(',')

    print(" ")
    print(Fore.LIGHTMAGENTA_EX + "Certificate Information:")
    print(Fore.LIGHTMAGENTA_EX + "=======================================================")
    print(Fore.LIGHTBLUE_EX + 'Domain: ' + Fore.RESET + str(domain))
    print(Fore.LIGHTBLUE_EX + 'Company name: ' + Fore.RESET + str(organization))
    print(Fore.LIGHTBLUE_EX + 'Country: ' + Fore.RESET + str(issuer_country_name))
    print(Fore.LIGHTBLUE_EX + 'Issuer Organization Name: ' + Fore.RESET + str(issuer_organization_name))
    print(Fore.LIGHTBLUE_EX + 'Version: ' + Fore.RESET + str(version))
    print(Fore.LIGHTBLUE_EX + 'Serial number: ' + Fore.RESET + str(serial_number))
    print(Fore.LIGHTBLUE_EX + 'SHA1 Fingerprint: ' + Fore.RESET + sha1_fingerprint)
    print(Fore.LIGHTBLUE_EX + 'Key Algorithm: ' + Fore.RESET + signature_algorithm)
    print(Fore.LIGHTBLUE_EX + 'Not before: ' + Fore.RESET + str(not_before))
    print(Fore.LIGHTBLUE_EX + 'Not after: ' + Fore.RESET + str(not_after))
    print(Fore.LIGHTBLUE_EX + 'Total valid for: ' + Fore.RESET + str(valid_for) + ' days ')
    print(Fore.LIGHTBLUE_EX + 'Days left: ' + Fore.RESET + str(valid_days_left))
    if expiration:
        print(Fore.LIGHTBLUE_EX + 'Expired: ' + Fore.LIGHTRED_EX + str(expiration))
    else:
        print(Fore.LIGHTBLUE_EX + 'Expired: ' + Fore.LIGHTGREEN_EX + str(expiration))
    print(Fore.LIGHTBLUE_EX + 'Subject Alternative Names: ')
    for dns_name in subject_alternative_names:
        print(Fore.RESET + '  DNS Name: ' + dns_name)
    print(" ")

    with open('ca_trusted.txt') as f:
        print(Fore.LIGHTMAGENTA_EX + "===========================")
        print(Fore.LIGHTMAGENTA_EX + "Checking CA trusted list...")
        print(Fore.LIGHTMAGENTA_EX + "===========================")

        if root_issuer in f.read():
            print(Fore.LIGHTGREEN_EX + "Issuer is valid.")
        else:
            print(Fore.LIGHTRED_EX + "Issuer is not valid.")






