from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from .forms import CSRForm
from .models import Certificate

# Create your views here.

@login_required
def sign(request):
    print('Sign')
    if request.method == 'POST':
        form = CSRForm(request.POST, request.FILES)
        if form.is_valid():
            print('valid form sent')
            print(form.fields)
            cert = Certificate(csr=form.cleaned_data['csr'])
            cert.requested_by = request.user
            cert.sign_date = timezone.now()
            print(cert)
            cert.save()
    else:
        print('request.method != POST')
        form = CSRForm()
    print(f'form = {form.__dict__}')
    return render(request, 'sign.html', {'form': form})