from django.urls import include, path
from .views import *

urlpatterns = [
    path('sign/', sign),
]