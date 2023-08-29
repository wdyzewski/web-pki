from django.contrib import admin
from .models import Certificate, CertificateAuthority

@admin.action(description='Sign selected certificates')
def sign_certificate(modeladmin, request, queryset):
    print('Called admin.sign_certificate(...)')

@admin.action(description='Revoke selected certificates')
def revoke_certificate(modeladmin, request, queryset):
    print('Called admin.revoke_certificate(...)')

class CertificateAdmin(admin.ModelAdmin):
    actions = [sign_certificate, revoke_certificate]


admin.site.register(Certificate, CertificateAdmin)
admin.site.register(CertificateAuthority)