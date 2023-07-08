from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class Certificate(models.Model):
    sign_date = models.DateTimeField(blank=True)
    csr = models.TextField()
    cert = models.TextField(blank=True)
    requested_by = models.ForeignKey(User, on_delete=models.CASCADE)