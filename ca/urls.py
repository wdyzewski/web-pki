from django.urls import include, path
from .views import *

urlpatterns = [
    path('', list_user_certs, name='list_user_certificates'),
    path('upload_csr/', upload_csr, name='upload_csr'),
    path('gen_csr/', gen_csr, name='gen_csr'),
    path('details/<int:id>/', cert_details, name='cert_details'),
    path('submitted/<int:id>/', cert_submitted, name='cert_submitted'),
    path('download/<int:id>/', cert_download, name='cert_download'),
    path('revoke/<int:id>/', cert_revoke, name='cert_revoke'),
    path('ca/<str:cashortname>/pem', get_ca_pem, name='download_ca_pem'),
    path('ca/<str:cashortname>/crl', get_ca_crl, name='download_ca_crl'),
]