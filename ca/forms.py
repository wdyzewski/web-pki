from typing import Dict, Any
from django import forms
from .models import Certificate

#class CSRForm(ModelForm):
#    class Meta:
#        model = Certificate
#        fields = ['csr']


class CSRForm(forms.Form):
    csr_text = forms.CharField(widget=forms.Textarea(), required=False)
    csr_file = forms.FileField(required=False)

    def clean(self) -> Dict[str, Any]:
        cleaned_data = super().clean()
        print(cleaned_data)
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
        return cleaned_data