from django.core.management.base import BaseCommand, CommandError
from OpenSSL import crypto, SSL
from os.path import join
import random

CA_CRT = 'ca.crt'
CA_KEY = 'ca.key'

class Command(BaseCommand):
    help = 'Generates new CA'

    def add_arguments(self, parser):
        parser.add_argument('--key_size', type=int, default=4096)
        parser.add_argument('--country')
        parser.add_argument('--state')
        parser.add_argument('--city')
        parser.add_argument('--organization')
        parser.add_argument('--ou', '--organizational-unit')
        parser.add_argument('--cn')
        parser.add_argument('--validity') # timedelta?

    def handle(self, *args, **options):
        key_size = options['key_size']

        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, key_size)
        serialnumber = random.getrandbits(64)
        cert = crypto.X509()
        """
        cert.get_subject().C = input("Country: ")
        cert.get_subject().ST = input("State: ")
        cert.get_subject().L = input("City: ")
        cert.get_subject().O = input("Organization: ")
        cert.get_subject().OU = input("Organizational Unit: ")
        cert.get_subject().CN = CN
        """
        cert.set_serial_number(serialnumber)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(31536000) #315360000 is in seconds.
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha512')
        crt_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
        with open(CA_CRT,"wt") as f:
            f.write(crt_pem.decode("utf-8"))
        with open(CA_KEY, "wt") as f:
            f.write(key_pem.decode("utf-8"))
        self.stdout.write(self.style.SUCCESS('Successfully generated CA'))
