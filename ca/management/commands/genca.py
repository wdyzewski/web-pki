import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.core.management.base import BaseCommand

CA_CRT = 'ca.crt'
CA_KEY = 'ca.key'
CA_CN = 'Wojciech Dyzewski CA'

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

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        # Write our key to disk for safe keeping
        with open(CA_KEY, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        builder = x509.CertificateBuilder()
        # TODO add country, state, city... (if passed)
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, CA_CN)
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, CA_CN),
        ]))
        builder = builder.not_valid_before(datetime.datetime.now())
        builder = builder.not_valid_after(datetime.datetime.now() + datetime.timedelta(days=365 * 10)) # TODO --validity
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(key.public_key())
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )
        certificate = builder.sign(
            private_key=key, algorithm=hashes.SHA256()
        )
        with open("ca.crt", "wb") as f:
            f.write(certificate.public_bytes(
                encoding=serialization.Encoding.PEM
            ))

        self.stdout.write(self.style.SUCCESS('Successfully generated CA'))
