from django.db import models
from django.contrib.auth.models import User

class SigningConfig:
    AUTOSIGN = 'A'
    DISABLED = 'D'
    REQUIRES_APPROVAL = 'R'

SIGNING_CONFIG_CHOICES = [
    (SigningConfig.AUTOSIGN, 'Autosign'),
    (SigningConfig.DISABLED, 'Disabled'),
    (SigningConfig.REQUIRES_APPROVAL, 'Requires approval')
]

class CertificateAuthority(models.Model):
    private_key = models.TextField()
    public_part = models.TextField()
    revoked_list = models.TextField(blank=True)
    shortname = models.CharField(max_length=10, unique=True)
    longname = models.CharField(max_length=100)
    comment = models.CharField(max_length=300)
    personal_signing = models.CharField(max_length=1, choices=SIGNING_CONFIG_CHOICES, default=SigningConfig.DISABLED)
    server_signing = models.CharField(max_length=1, choices=SIGNING_CONFIG_CHOICES, default=SigningConfig.DISABLED)

    def get_signing_config(self, purpose):
        if purpose == CertificatePurpose.PERSONAL:
            return self.personal_signing
        elif purpose == CertificatePurpose.SERVER:
            return self.server_signing
        else:
            raise NotImplementedError('CA has no information about such purpose')

    def __str__(self) -> str:
        return f'{self.shortname}: {self.longname}'
    
    class Meta:
        verbose_name_plural = 'Certificate Authorities'


class CertificatePurpose:
    PERSONAL = 'P'
    SERVER = 'S'

CERTIFICATE_PURPOSE_CHOICES = [
    (CertificatePurpose.PERSONAL, 'Personal'),
    (CertificatePurpose.SERVER, 'Server'),
]

class CertificateStatus:
    CSR_UPLOADED = 'U'
    READY_TO_SIGN = 'T'
    SIGNED = 'S'
    EXPIRED = 'E'
    REVOKED = 'R'

CERTIFICATE_STATUS_CHOICES = [
    (CertificateStatus.CSR_UPLOADED, 'CSR uploaded'),
    (CertificateStatus.READY_TO_SIGN, 'Ready to sign'),
    (CertificateStatus.SIGNED, 'Signed'),
    (CertificateStatus.EXPIRED, 'Expired'),
    (CertificateStatus.REVOKED, 'Revoked')
]

class Certificate(models.Model):
    status = models.CharField(max_length=1, choices=CERTIFICATE_STATUS_CHOICES, default=CERTIFICATE_STATUS_CHOICES[0][0])
    requester = models.ForeignKey(User, null=True, related_name='%(class)s_certificate_requester', on_delete=models.CASCADE)
    csr = models.TextField()
    csr_upload_date = models.DateTimeField(auto_now=True)
    purpose = models.CharField(max_length=1, choices=CERTIFICATE_PURPOSE_CHOICES, default=CertificatePurpose.PERSONAL)
    cert = models.TextField(blank=True)
    sign_date = models.DateTimeField(null=True)
    approver = models.ForeignKey(User, null=True, related_name='%(class)s_certificate_approver', on_delete=models.CASCADE)
    ca = models.ForeignKey(CertificateAuthority, null=True, on_delete=models.CASCADE)

    def __str__(self) -> str:
        username = self.requester.username if self.requester else 'MISSING USERNAME'
        return f'[{self.get_status_display()}] Certificate requested by {username}'