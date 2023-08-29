from django.urls import include, path
from .views import *

urlpatterns = [
    path('', list_user_certs, name='list_user_certificates'),
    path('new/', new_csr, name='new_csr'),
    path('sign/<int:id>/', sign, name='sign'),
    path('ca/<str:cashortname>/pem', get_ca_pem, name='download_ca_pem'),
    path('ca/<str:cashortname>/crl', get_ca_crl, name='download_ca_crl'),
]