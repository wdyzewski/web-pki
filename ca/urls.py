from django.urls import include, path
from .views import *

urlpatterns = [
    path('sign/<int:id>/', sign, name='sign'),
    path('upload_csr/', upload_csr, name='upload_csr'),
]