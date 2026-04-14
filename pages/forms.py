from django import forms


class NewsletterForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={
            "placeholder": "vas@email.cz",
            "class": "w-full bg-transparent outline-none focus:ring-0 border-none text-white placeholder-slate-400 text-sm",
        }),
    )
