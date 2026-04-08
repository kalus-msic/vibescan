from django import forms
from .validator import validate_scan_url, SSRFError


class ScanForm(forms.Form):
    url = forms.CharField(
        widget=forms.TextInput(attrs={
            "placeholder": "tvujweb.cz",
            "class": "bg-transparent flex-1 outline-none focus:ring-0 border-none text-slate-900 placeholder-slate-400 text-sm font-medium",
            "autofocus": True,
        }),
        label="URL adresa webu",
    )
    ephemeral = forms.BooleanField(
        required=False,
        label="Jednorázový sken",
        widget=forms.CheckboxInput(attrs={
            "class": "peer hidden",
        }),
    )

    def clean_url(self):
        url = self.cleaned_data.get("url", "").strip()
        try:
            return validate_scan_url(url)
        except SSRFError as e:
            raise forms.ValidationError(str(e))
        except ValueError as e:
            raise forms.ValidationError(str(e))
