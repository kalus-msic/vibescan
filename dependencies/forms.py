from django import forms

MAX_CONTENT_SIZE = 500 * 1024  # 500 KB


class DependencyCheckForm(forms.Form):
    content = forms.CharField(
        widget=forms.Textarea(attrs={
            "placeholder": "Vložte obsah requirements.txt, package.json nebo composer.json",
            "class": "w-full h-48 bg-transparent outline-none focus:ring-0 border-none text-slate-900 placeholder-slate-400 text-sm font-mono resize-none",
            "spellcheck": "false",
        }),
        label="Obsah souboru se závislostmi",
    )

    def clean_content(self):
        content = self.cleaned_data.get("content", "").strip()
        if not content:
            raise forms.ValidationError("Obsah nesmí být prázdný.")
        if len(content.encode("utf-8")) > MAX_CONTENT_SIZE:
            raise forms.ValidationError("Obsah je příliš velký (max 500 KB).")
        return content
