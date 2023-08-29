import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.core.management.base import BaseCommand

from ca.models import CertificateAuthority

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
        parser.add_argument('--save', help='Save newly created CA files on disk. Requires passing prefix of the path for CA certificate and key, eg. passing here `/home/admin/my_great_ca` will result in saving files `/home/admin/my_great_ca.{crt,key}`')
        parser.add_argument('--import', action='store_true', help='Import newly created CA into the system')

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
        # Generating private key
        self.stdout.write(f'Generating {options["key_size"]} bytes key...')
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=options['key_size']
        )
        ca_private_key = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        # Generating self-signed CA (based on key `key`)
        subject_name = self._get_x509_subject_name(options)
        builder = self._get_ca_cert_builder(key, subject_name, options['validity'])
        certificate = builder.sign(
            private_key=key, algorithm=hashes.SHA256()
        )
        ca_certificate = certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode()

        if options.get('save'):
            key_file = options['save'] + '.key'
            with open(key_file, 'w') as f:
                f.write(ca_private_key)
            self.stdout.write(self.style.SUCCESS(f'Successfully saved key in {key_file}'))
            cert_file = options['save'] + '.crt'
            with open(cert_file, 'w') as f:
                f.write(ca_certificate)
            self.stdout.write(self.style.SUCCESS(f'Successfully saved CA certificate in {cert_file}'))

        if options.get('import'):
            ca = CertificateAuthority(
                private_key=ca_private_key,
                public_part=ca_certificate,
                shortname=certificate.subject.rfc4514_string(),
                longname=f'CA certificate for {certificate.subject.rfc4514_string()} imported via `genca.py --import`',
                comment="Put something here manually. Comment's content won't be readable for unprivileged users"
            )
            ca.save()
            self.stdout.write(self.style.SUCCESS('Successfully saved CA in database'))