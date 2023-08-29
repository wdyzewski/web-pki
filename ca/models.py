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
    shortname = models.CharField(max_length=10)
    longname = models.CharField(max_length=100)
    comment = models.CharField(max_length=300)
    personal_signing = models.CharField(max_length=1, choices=SIGNING_CONFIG_CHOICES, default=SigningConfig.DISABLED)
    server_signing = models.CharField(max_length=1, choices=SIGNING_CONFIG_CHOICES, default=SigningConfig.DISABLED)

    def __str__(self) -> str:
        return self.longname


CERTIFICATE_STATUS_CHOICES = [
    ('U', 'CSR uploaded'),
    ('T', 'Ready to sign'),
    ('S', 'Signed'),
    ('E', 'Expired'),
    ('R', 'Revoked')
]

class Certificate(models.Model):
    status = models.CharField(max_length=1, choices=CERTIFICATE_STATUS_CHOICES)
    requester = models.ForeignKey(User, related_name='%(class)s_certificate_requester', on_delete=models.CASCADE)
    csr = models.TextField()
    csr_upload_date = models.DateTimeField(auto_now=True)
    cert = models.TextField(blank=True)
    sign_date = models.DateTimeField(blank=True)
    approver = models.ForeignKey(User, related_name='%(class)s_certificate_approver', on_delete=models.CASCADE)
    ca = models.ForeignKey(CertificateAuthority, on_delete=models.CASCADE)


    def __str__(self) -> str:
        return f'{self.get_status_display()} Certificate requested by {self.requester.username}'