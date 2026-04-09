import logging

from django.shortcuts import render
from django.views.decorators.http import require_http_methods
from django_ratelimit.decorators import ratelimit

from .forms import DependencyCheckForm
from .parsers import parse_dependencies, UnknownFormatError
from .osv_client import check_vulnerabilities, OsvError, CheckResult

logger = logging.getLogger(__name__)


def _session_key(group, request):
    if not request.session.session_key:
        request.session.create()
    return request.session.session_key


@ratelimit(key="ip", rate="60/h", method="POST", block=True, group="depcheck-ip")
@ratelimit(key=_session_key, rate="20/h", method="POST", block=True, group="depcheck-session")
@require_http_methods(["POST"])
def check_dependencies(request):
    form = DependencyCheckForm(request.POST)

    if not form.is_valid():
        error = form.errors.get("content", ["Neplatný vstup."])[0]
        return render(request, "dependencies/partials/error.html", {"error": error})

    content = form.cleaned_data["content"]

    try:
        deps = parse_dependencies(content)
    except UnknownFormatError:
        return render(request, "dependencies/partials/error.html", {
            "error": "Nepodařilo se rozpoznat formát. Podporujeme requirements.txt, package.json a composer.json.",
        })

    if not deps:
        return render(request, "dependencies/partials/error.html", {
            "error": "Nepodařilo se rozpoznat formát. Podporujeme requirements.txt, package.json a composer.json.",
        })

    try:
        result = check_vulnerabilities(deps)
    except OsvError as e:
        return render(request, "dependencies/partials/error.html", {"error": str(e)})

    return render(request, "dependencies/partials/results.html", {
        "vulnerabilities": result.vulnerabilities,
        "total_deps": len(deps),
        "affected_count": len({v.package_name for v in result.vulnerabilities}),
        "vuln_count": len(result.vulnerabilities),
        "last_modified": result.last_modified,
    })
