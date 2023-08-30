from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding
from datetime import datetime, timedelta
from django.contrib.auth.models import User
from django.utils.timezone import now
from .models import Certificate, CertificateAuthority, SigningConfig, CertificateStatus

CRL_URI = 'https://example.com/crl.pem' # FIXME
DEFAULT_KEY_SIZE = 4096

def is_valid_csr(input : str) -> bool:
    try:
        x509.load_pem_x509_csr(input.encode())
        return True
    except ValueError:
        return False

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

def sign_csr(csr     : x509.CertificateSigningRequest,
             ca_cert : x509.Certificate,
             ca_priv : rsa.RSAPrivateKey) -> x509.Certificate:
    # TODO make sure subject is correct
    cert = get_default_certificate_signer().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).sign(ca_priv, hashes.SHA256())
    return cert

def refresh_x509_crl(crl     : x509.CertificateRevocationList,
                     ca_priv : rsa.RSAPrivateKey,
                     serial  : int) -> x509.CertificateRevocationList:
    builder = x509.CertificateRevocationListBuilder().issuer_name(
        crl.issuer
    ).last_update(
        crl.last_update
    ).next_update(
        datetime.utcnow() + timedelta(days=1)
    )
    # add revoked certs to the new CRL builder
    for cert in crl:
        builder = builder.add_revoked_certificate(cert)
    # add new certificate to the CRL (assuming serial <= 0 is only refreshing dates)
    if serial > 0:
        new_revoked_cert = x509.RevokedCertificateBuilder().serial_number(
            serial
        ).revocation_date(
            datetime.utcnow()
        ).build()
        builder = builder.add_revoked_certificate(
            new_revoked_cert    
        )

    return builder.sign(ca_priv)

def revoke_cert(certificate : Certificate):
    if certificate.status != CertificateStatus.SIGNED:
        return
    crl = x509.load_pem_x509_crl(certificate.ca.revoked_list.encode())
    serial = x509.load_der_x509_certificate(certificate.cert.encode()).serial_number
    ca_pkey = load_pem_private_key(certificate.ca.private_key.encode(), password=None)
    
    new_crl = refresh_x509_crl(crl, ca_pkey, serial)
    certificate.ca.revoked_list = new_crl.public_bytes(serialization.Encoding.PEM)
    certificate.ca.save()
    certificate.status = CertificateStatus.REVOKED
    certificate.save()

def check_ca_purpose(ca : CertificateAuthority, purpose : str) -> bool:
    return ca.get_signing_config(purpose) != SigningConfig.DISABLED

def sign_certificate(certificate : Certificate, signer : User):
    if certificate.status != CertificateStatus.READY_TO_SIGN:
        return
    csr = x509.load_pem_x509_csr(certificate.csr.encode())
    ca_cert = x509.load_pem_x509_certificate(certificate.ca.public_part.encode())
    ca_pkey = load_pem_private_key(certificate.ca.private_key.encode(), password=None)

    signed_cert = sign_csr(csr, ca_cert, ca_pkey)
    certificate.cert = signed_cert.public_bytes(Encoding.PEM).decode()
    certificate.status = CertificateStatus.SIGNED
    certificate.approver = signer
    certificate.sign_date = now()
    certificate.save()

def autosign(certificate : Certificate):
    """
    Signs CSR from Certificate object but only if CA is configured to autosign such certificate types.
    """
    if not certificate.ca.get_signing_config(certificate.purpose) == SigningConfig.AUTOSIGN:
        return
    sign_certificate(certificate, certificate.requester)