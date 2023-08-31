from django import forms
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib.auth.decorators import login_required
from django.utils.timezone import now
from .forms import CSRForm, CertDetailsForm
from .models import Certificate, CertificateAuthority, CertificateStatus
from .common import get_new_csr_private_key, autosign, revoke_cert

# Create your views here.

@login_required
def list_user_certs(request):
    certificates = Certificate.objects.filter(requester=request.user)
    return render(request, 'list_user_certs.html', {'certificates': certificates})

@login_required
def upload_csr(request):
    if request.method == 'POST':
        form = CSRForm(request.POST, request.FILES)
        if form.is_valid():
            cert = Certificate(
                csr=form.cleaned_data['csr'],
                requester = request.user,
                csr_upload_date=now()
            )
            print(cert) # FIXME remove debug
            cert.save()
            return redirect('cert_details', id=cert.id)
    else:
        form = CSRForm()
    return render(request, 'upload_csr.html', {'form': form})


@login_required
def gen_csr(request):
    csr, pkey = get_new_csr_private_key(request.user.username)
    form = CSRForm(initial={'csr_text': csr})
    form.fields['csr_file'].widget = forms.HiddenInput()
    form.fields['csr_text'].widget.attrs['readonly'] = True
    context = {
        'private_key': pkey,
        'form': form
    }
    return render(request, 'generated_csr.html', context)

@login_required
def cert_details(request, id):
    cert = get_object_or_404(Certificate, id=id, requester=request.user)
    if request.method == 'POST':
        form = CertDetailsForm(request.POST, instance=cert)
        if form.is_valid():
            cert = form.save(commit=False) # don't write to DB, just get Certificate object
            cert.status = CertificateStatus.READY_TO_SIGN
            cert.save()
            return redirect('cert_submitted', id=cert.id)
    else:
        form = CertDetailsForm(instance=cert)
    return render(request, 'cert_details.html', {'form': form})

@login_required
def cert_submitted(request, id):
    cert = get_object_or_404(Certificate, id=id, requester=request.user)
    autosign(cert)
    return render(request, 'cert_submitted.html', {'cert': cert})

def pem_as_http_response(contents : str, filename : str):
    return HttpResponse(
        contents.replace('\r\n', '\n'),
        content_type='application/x-pem-file',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'}
    )

def get_ca_pem(request, cashortname):
    ca = get_object_or_404(CertificateAuthority, shortname=cashortname)
    return pem_as_http_response(ca.public_part, f'{cashortname}.pem')

@login_required
def cert_download(request, id):
    cert = get_object_or_404(Certificate, id=id, requester=request.user)
    return pem_as_http_response(cert.cert, f'{request.user.username}.pem')

@login_required
def cert_revoke(request, id):
    cert = get_object_or_404(Certificate, id=id, requester=request.user)
    revoke_cert(cert)
    return redirect('list_user_certificates')

def get_ca_crl(request, cashortname):
    ca = get_object_or_404(CertificateAuthority, shortname=cashortname)
    return pem_as_http_response(ca.revoked_list, f'{cashortname}.crl')