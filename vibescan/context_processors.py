from django.conf import settings


def gtm(request):
    return {"gtm_id": getattr(settings, "GTM_ID", "")}
