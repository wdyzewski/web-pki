from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding
from datetime import datetime, timedelta

CRL_URI = 'https://example.com/crl.pem' # FIXME
DEFAULT_KEY_SIZE = 4096

def is_valid_csr(input : str) -> bool:
    try:
        x509.load_pem_x509_csr(input.encode())
        return True
    except ValueError:
        return False

def get_ca() -> x509.Certificate:
    with open('ca.crt', 'rb') as f: # FIXME
        ca = x509.load_pem_x509_certificate(f.read())
    return ca

def get_ca_private_key() -> rsa.RSAPrivateKey:
    with open('ca.key', 'rb') as f: # FIXME
        key = load_pem_private_key(f.read(), password=None)
    return key

def get_new_csr_private_key(common_name):
    """
    Generates (on behalf of user) and returns new CSR and matching private key.
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=DEFAULT_KEY_SIZE
    )
    private_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
    ])).sign(key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    return csr_pem, private_key_pem

def get_csr_info(csr_str : str) -> dict:
    csr = x509.load_pem_x509_csr(csr_str.encode())
    return {
        'Public key size': csr.public_key().key_size,
        'Certificate Sign Request (in PEM format)': csr_str,
        'Certifcate Authority': get_ca().subject.rfc4514_string(),
    }

def get_default_certificate_signer() -> x509.CertificateBuilder:
    now = datetime.utcnow()
    cert_validity = timedelta(days=10 * 365)
    return x509.CertificateBuilder().serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now - timedelta(minutes=10)
    ).not_valid_after(
        now + cert_validity
    ).add_extension(
        x509.CRLDistributionPoints([
            x509.DistributionPoint(
                [x509.UniformResourceIdentifier(CRL_URI)],
                relative_name=None,
                reasons=None,
                crl_issuer=None
            )
        ]),
        critical=False
    )

def sign_csr(csr_str : str) -> str:
    csr = x509.load_pem_x509_csr(csr_str.encode())
    ca = get_ca()
    # TODO make sure subject is correct
    cert = get_default_certificate_signer().subject_name(
        csr.subject
    ).issuer_name(
        ca.subject
    ).public_key(
        csr.public_key()
    ).sign(get_ca_private_key(), hashes.SHA256())

    return cert.public_bytes(Encoding.PEM).decode()

def revoke_cert():
    """TODO"""