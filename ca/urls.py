from django.urls import include, path
from .views import *

urlpatterns = [
    path('sign/<int:id>/', sign, name='sign'),
    path('upload_csr/', upload_csr, name='upload_csr'),
    path('ca/<str:cashortname>/pem', get_ca_pem, name='download_ca_pem'),
    path('ca/<str:cashortname>/crl', get_ca_crl, name='download_ca_crl'),
]