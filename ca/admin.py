from django.contrib import admin, messages
from .models import Certificate, CertificateAuthority
from .common import sign_certificate, revoke_cert

class CertificateAdmin(admin.ModelAdmin):
    actions = ['admin_sign_certificate', 'admin_revoke_certificate']

    @admin.action(description='Sign selected certificate requests')
    def admin_sign_certificate(self, request, queryset):
        for cert in queryset:
            sign_certificate(cert, request.user)
        self.message_user(
            request,
            f'{len(queryset)} certificates signed',
            messages.SUCCESS
        )

    @admin.action(description='Revoke selected certificates')
    def admin_revoke_certificate(self, request, queryset):
        for cert in queryset:
            revoke_cert(cert)
        self.message_user(
            request,
            f'{len(queryset)} certificates revoked',
            messages.SUCCESS
        )


admin.site.register(Certificate, CertificateAdmin)
admin.site.register(CertificateAuthority)