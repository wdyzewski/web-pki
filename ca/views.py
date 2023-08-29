from django.shortcuts import get_object_or_404, redirect, render
from django.contrib.auth.decorators import login_required
from django.utils.timezone import now
import hashlib
from .forms import CSRForm, SignForm
from .models import Certificate
from .common import get_csr_info, sign_csr

# Create your views here.

@login_required
def upload_csr(request):
    if request.method == 'POST':
        form = CSRForm(request.POST, request.FILES)
        if form.is_valid():
            cert = Certificate(csr=form.cleaned_data['csr'])
            cert.requested_by = request.user
            cert.sign_date = now()
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
    csr_info = get_csr_info(cert.csr)
    if request.method == 'POST':
        form = SignForm(request.POST)
        if form.is_valid() and form.cleaned_data['csr_checksum'] == checksum:
            new_cert = sign_csr(cert.csr)
            print('You have just signed a CSR!')
            cert.sign_date = now()
            cert.cert = new_cert
            cert.save()
            # TODO redirect to certificate info page
    # in case of any problem - just return to plain confirmation form
    form = SignForm({'csr_checksum': checksum})
    return render(request, 'sign.html', {'info': csr_info, 'form': form})