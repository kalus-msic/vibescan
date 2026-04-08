from django.http import HttpResponse
from django.views.decorators.http import require_http_methods


@require_http_methods(["POST"])
def check_dependencies(request):
    return HttpResponse("stub")
