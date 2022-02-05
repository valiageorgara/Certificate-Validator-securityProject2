# SSL Checker (Time validity and CA trusted list)
#### Python script that collects SSL/TLS information from hosts, prints the information and checks if the certificate is valid

## Requirements
`pip install -r requirements.txt`

`pip install pyOpenSSL`

## Usage
```
python3 main.py -h

usage: main.py [-h] [-url URL]

example: main.py -url facebook.com

optional arguments:
  -h, --help           show this help message and exit
  -url URL, --url URL  hostname as input
```

## Example 1
```
valia@valia-Vostro-5590:~/PycharmProjects/securityProject2$ python3 main.py -url facebook.com
 
=======================================================
Searching validity for host: facebook.com
=======================================================
  
Certificate trusted chain:
=======================================================
DigiCert SHA2 High Assurance Server CA
DigiCert High Assurance EV Root CA
 
Certificate Information:
=======================================================
Domain: *.facebook.com
Company name: Facebook, Inc.
Country: US
Issuer Organization Name: DigiCert Inc
Version: 2
Serial number: 16235483839307697575305838698429658230
SHA1 Fingerprint: 2D:E1:3A:04:9D:54:9E:48:2E:7C:99:61:D4:CC:7D:5B:EC:A9:82:B4
Key Algorithm: sha256WithRSAEncryption
Not before: 2021-11-14 00:00:00
Not after: 2022-02-12 23:59:59
Total valid for: 90 days 
Days left: 7
Expired: False
Subject Alternative Names: 
  DNS Name: *.facebook.com
  DNS Name:  *.facebook.net
  DNS Name:  *.fbcdn.net
  DNS Name:  *.fbsbx.com
  DNS Name:  *.m.facebook.com
  DNS Name:  *.messenger.com
  DNS Name:  *.xx.fbcdn.net
  DNS Name:  *.xy.fbcdn.net
  DNS Name:  *.xz.fbcdn.net
  DNS Name:  facebook.com
  DNS Name:  messenger.com
 
===========================
Checking CA trusted list...
===========================
Issuer is valid.
```

## Example 2
```
valia@valia-Vostro-5590:~/PycharmProjects/securityProject2$ python3 main.py -url expired.badssl.com
 
=======================================================
Searching validity for host: expired.badssl.com
=======================================================
 
Certificate trusted chain:
=======================================================
COMODO RSA Domain Validation Secure Server CA
COMODO RSA Certification Authority
AddTrust External CA Root
 
Certificate Information:
=======================================================
Domain: *.badssl.com
Company name: None
Country: GB
Issuer Organization Name: COMODO CA Limited
Version: 2
Serial number: 99565320202650452861752791156765321481
SHA1 Fingerprint: 40:4B:BD:2F:1F:4C:C2:FD:EE:F1:3A:AB:DD:52:3E:F6:1F:1C:71:F3
Key Algorithm: sha256WithRSAEncryption
Not before: 2015-04-09 00:00:00
Not after: 2015-04-12 23:59:59
Total valid for: 3 days 
Days left: -2491
Expired: True
Subject Alternative Names: 
  DNS Name: *.badssl.com
  DNS Name:  badssl.com
 
===========================
Checking CA trusted list...
===========================
Issuer is not valid.
```
##Example 3
```
valia@valia-Vostro-5590:~/PycharmProjects/securityProject2$ python3 main.py -url damjan.softver.org.mk
 
=======================================================
Searching validity for host: damjan.softver.org.mk
=======================================================
 
Certificate trusted chain:
=======================================================
R3
ISRG Root X1
DST Root CA X3
 
Certificate Information:
=======================================================
Domain: d8c413ba-5af9-4837-8cd1-ff046c014b0c.pub.instances.scw.cloud
Company name: None
Country: US
Issuer Organization Name: Let's Encrypt
Version: 2
Serial number: 265947834694912360898141032548078323597081
SHA1 Fingerprint: 18:1A:B5:99:C4:F3:23:39:B1:58:13:45:40:29:96:81:A3:97:EB:AA
Key Algorithm: sha256WithRSAEncryption
Not before: 2022-01-07 03:47:59
Not after: 2022-04-07 03:47:58
Total valid for: 89 days 
Days left: 60
Expired: False
Subject Alternative Names: 
  DNS Name: d8c413ba-5af9-4837-8cd1-ff046c014b0c.pub.instances.scw.cloud
  DNS Name:  damjan.softver.org.mk
 
===========================
Checking CA trusted list...
===========================
Issuer is not valid.
```

##Example 4
```
valia@valia-Vostro-5590:~/PycharmProjects/securityProject2$ python3 main.py -url ca.ocsr.nl
 
=======================================================
Searching validity for host: ca.ocsr.nl
=======================================================
 
Caught exception: [Errno -5] No address associated with hostname

```

## Quick Summary
This script collects the host certificate, prints out basic information and:
1. checks time validity by calculating if the not_after date has passed, meaning that it has expired and also, as an extra, calculates how many days the certificate is valid for, by doing not_after - not_before.
2. checks if the issuer is in a trusted CA list. By running:
   `awk -v cmd='openssl x509 -noout -subject' '
    /BEGIN/{close(cmd)};{print | cmd}' < /etc/ssl/certs/ca-certificates.crt >> ca_trusted.txt` in the terminal, I pulled from my os the certificate authorities. Then I check if the certificate issuer exists in that file.

## Acknowledgments
I've used this space to list resources I have found helpful and would like to give credit to. 
[Command Line Arguments in Python](https://www.geeksforgeeks.org/command-line-arguments-in-python/)

[How can I retrieve the TLS/SSL peer certificate of a remote host using python?](https://stackoverflow.com/questions/7689941/how-can-i-retrieve-the-tls-ssl-peer-certificate-of-a-remote-host-using-python)

[Want to find difference, in days, between two dates, of different date format, in Python](https://stackoverflow.com/questions/48627387/want-to-find-difference-in-days-between-two-dates-of-different-date-format-i)

[SHA1 fingerprint](https://gist.github.com/alastairmccormack/e7b0bc65927b7987b7d4)

[List all available ssl ca certificates](https://unix.stackexchange.com/questions/97244/list-all-available-ssl-ca-certificates)

[Mozilla Included CA Certificate List](https://wiki.mozilla.org/CA/Included_Certificates)

[PyOpenSSL - how can I get SAN(Subject Alternative Names) list](https://stackoverflow.com/questions/49491732/pyopenssl-how-can-i-get-sansubject-alternative-names-list)

[Verifying peer in SSL using python](https://stackoverflow.com/questions/1519074/verifying-peer-in-ssl-using-python)

[Verifying X509 Certificate Chain of Trust in Python](https://aviadas.com/blog/2015/06/18/verifying-x509-certificate-chain-of-trust-in-python/)

[How to validate / verify an X509 Certificate chain of trust in Python?](https://stackoverflow.com/questions/30700348/how-to-validate-verify-an-x509-certificate-chain-of-trust-in-python)

[How to verify certificate signature in pyOpenSSL?](https://stackoverflow.com/questions/46553338/how-to-verify-certificate-signature-in-pyopenssl)

[checking client ssl certificate / from python](https://www.osso.nl/blog/checking-client-ssl-certificate-from-python/)

[DigiCert Trusted Root Authority Certificates](https://www.digicert.com/kb/digicert-root-certificates.htm#intermediates)

[TLS/SSL Certificate Authority (CA) Trust store verification](https://blog.cetinich.net/2021/2021-python-trusted-ca-store/)

[Python ssl.get_server_certificate() Examples](https://www.programcreek.com/python/example/62606/ssl.get_server_certificate)

[Getting certificate chain with Python 3.3 SSL module](https://stackoverflow.com/questions/19145097/getting-certificate-chain-with-python-3-3-ssl-module)

[SSL Checker](https://github.com/narbehaj/ssl-checker)

[SSL Check](https://gist.github.com/gdamjan/55a8b9eec6cf7b771f92021d93b87b2c)

