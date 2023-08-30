from typing import Dict, Any
from django import forms
from .common import is_valid_csr, check_ca_purpose
from .models import Certificate


class CSRForm(forms.Form):
    csr_text = forms.CharField(widget=forms.Textarea(), required=False)
    csr_file = forms.FileField(required=False)

    def clean(self) -> Dict[str, Any]:
        cleaned_data = super().clean()
        if not cleaned_data.get('csr_text') and not cleaned_data.get('csr_file'):
            raise forms.ValidationError('Need to pass CSR as text or as file (in any form)')
        if cleaned_data.get('csr_text') and cleaned_data.get('csr_file'):
            raise forms.ValidationError('Need to pass CSR as text or as file (not both at the same time)')
        if cleaned_data.get('csr_text'):
            cleaned_data['csr'] = cleaned_data.pop('csr_text')
        else:
            with cleaned_data['csr_file'].open() as f:
                cleaned_data['csr'] = f.read().decode()
            cleaned_data.pop('csr_file')
        if not is_valid_csr(cleaned_data['csr']):
            raise forms.ValidationError('Passed text/file is not valid CSR in PEM format')
        return cleaned_data

class CertDetailsForm(forms.ModelForm):
    class Meta:
        model = Certificate
        fields = ['csr', 'purpose', 'ca']
        widgets = {
            'csr': forms.Textarea(attrs={'readonly': True})
        }
    
    def clean(self) -> Dict[str, Any]:
        cleaned_data = super().clean()
        if not check_ca_purpose(cleaned_data['ca'], cleaned_data['purpose']):
            raise forms.ValidationError('This CA is currently not available for signing this type of certificates')
        return cleaned_data