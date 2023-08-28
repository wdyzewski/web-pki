import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Generates new CA'

    def add_arguments(self, parser):
        parser.add_argument('--key_size', type=int, default=4096)
        parser.add_argument('--country', required=False)
        parser.add_argument('--state', required=False)
        parser.add_argument('--city', required=False)
        parser.add_argument('--organization', required=False)
        parser.add_argument('--organizational_unit', '--ou', required=False)
        parser.add_argument('--common_name', '--cn', required=True)
        parser.add_argument('--validity', type=int, help='CA validity (numer of days)', default=10*365)
        parser.add_argument('--path_prefix', help='Prefix of the path for CA certificate and key. Passing here `/home/admin/my_great_ca` will result in saving files `/home/admin/my_great_ca.{crt,key}`', default='ca')

    def _get_x509_subject_name(self, options):
        name = []
        mapping = [
            (NameOID.COUNTRY_NAME, 'country'),
            (NameOID.STATE_OR_PROVINCE_NAME, 'state'),
            (NameOID.LOCALITY_NAME, 'city'),
            (NameOID.ORGANIZATION_NAME, 'organization'),
            (NameOID.ORGANIZATIONAL_UNIT_NAME, 'organizational_unit'),
            (NameOID.COMMON_NAME, 'common_name')
        ]
        for oid, key in mapping:
            if key in options and options[key] is not None:
                print(f'Using value for {key}: `{options[key]}`')
                name.append(x509.NameAttribute(oid, options[key]))
        return name
    
    @staticmethod
    def _get_ca_cert_builder(key, subject, validity):
        return x509.CertificateBuilder().subject_name(
            x509.Name(subject)
        ).issuer_name(
            x509.Name(subject)
        ).not_valid_before(
            datetime.datetime.utcnow() - datetime.timedelta(minutes=10)
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=validity)
        ).serial_number(
            x509.random_serial_number()
        ).public_key(
            key.public_key()
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )

    def handle(self, *args, **options):
        self.stdout.write(f'Generating {options["key_size"]} bytes key...')
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=options['key_size']
        )
        # Write our key to disk for safe keeping
        with open(options['path_prefix'] + '.key', "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        self.stdout.write(self.style.SUCCESS('Successfully generated and saved key'))

        subject_name = self._get_x509_subject_name(options)
        builder = self._get_ca_cert_builder(key, subject_name, options['validity'])
        certificate = builder.sign(
            private_key=key, algorithm=hashes.SHA256()
        )
        with open(options['path_prefix'] + '.crt', "wb") as f:
            f.write(certificate.public_bytes(
                encoding=serialization.Encoding.PEM
            ))

        self.stdout.write(self.style.SUCCESS('Successfully generated and saved CA'))
