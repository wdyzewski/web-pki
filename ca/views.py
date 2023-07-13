from django.shortcuts import get_object_or_404, redirect, render
from django.contrib.auth.decorators import login_required
from django.utils import timezone
import hashlib
from .forms import CSRForm, SignForm
from .models import Certificate

# Create your views here.

@login_required
def upload_csr(request):
    if request.method == 'POST':
        form = CSRForm(request.POST, request.FILES)
        if form.is_valid():
            cert = Certificate(csr=form.cleaned_data['csr'])
            cert.requested_by = request.user
            cert.sign_date = timezone.now()
            print(cert)
            cert.save()
            return redirect('sign', id=cert.id)
    else:
        form = CSRForm()
    return render(request, 'upload_csr.html', {'form': form})

@login_required
def sign(request, id):
    cert = get_object_or_404(Certificate, id=id)
    checksum = hashlib.sha256(cert.csr.encode()).hexdigest()
    # TODO check permissions to view this cert
    if request.method == 'POST':
        form = SignForm(request.POST)
        if form.is_valid() and form.cleaned_data['csr_checksum'] == checksum:
            print('You have just signed a CSR!')
            # TODO
    # in case of any problem - just return to plain confirmation form
    form = SignForm({'csr_checksum': checksum})
    return render(request, 'sign.html', {'form': form})