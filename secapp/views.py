"""
Views that reproduce, endpoint-by-endpoint, the six rows of the paper's
Table 2 (Empirical Results) and the four rows of Table 3 (Performance
Overhead) so both tables can be regenerated with real, script-measured
numbers instead of illustrative estimates.

Toggle behavior via the SECURITY_LEVEL environment variable read in
testproject/settings.py: baseline | headers | sanitization | full.
"""
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_GET, require_POST
from django.views.decorators.csrf import ensure_csrf_cookie

from .models import Comment, UserProfile

try:
    import bleach
except ImportError:  # pragma: no cover
    bleach = None

ALLOWED_HTML_TAGS = ["b", "i", "strong", "em", "p", "code"]
ALLOWED_ATTRIBUTES = {"a": ["href", "title"]}


# ---------------------------------------------------------------------
# Table 3 (Performance Overhead): a minimal endpoint to benchmark the
# per-request cost of whatever middleware stack is active for this
# SECURITY_LEVEL run. Keep the handler itself trivial so the measured
# latency reflects middleware/header/config overhead, not view logic.
# ---------------------------------------------------------------------
@ensure_csrf_cookie
@require_GET
def ping_view(request):
    return JsonResponse({"status": "ok", "security_level": settings.SECURITY_LEVEL})


# ---------------------------------------------------------------------
# Table 2, row "Reflected XSS"
# ---------------------------------------------------------------------
@require_POST
def submit_comment_view(request):
    raw_input = request.POST.get("content", "")
    if settings.SANITIZE_INPUT and bleach is not None:
        cleaned = bleach.clean(
            raw_input,
            tags=ALLOWED_HTML_TAGS,
            attributes=ALLOWED_ATTRIBUTES,
            strip=True,
        )
    else:
        cleaned = raw_input  # baseline / headers-only: no sanitization layer yet

    Comment.objects.create(content=cleaned)
    # Echoed back as raw HTML on purpose, simulating an endpoint whose
    # output is later rendered by a client without further escaping
    # (e.g. a JSON/comment API consumed by a rich-text widget) -- the
    # exact bypass scenario described in the paper's XSS section.
    return HttpResponse(cleaned, content_type="text/html")


# ---------------------------------------------------------------------
# Table 2, row "SQL Injection"
# ---------------------------------------------------------------------
@require_GET
def user_search_view(request):
    user_input = request.GET.get("username", "")

    if settings.SECURITY_LEVEL == "baseline":
        # --- VULNERABLE: string interpolation into raw SQL (as in the
        # paper's unsafe_user_search) -- intentionally reproduced here,
        # for THIS local test app only, to measure and confirm the
        # exploit before/after hardening. Never do this in a real app.
        query = f"SELECT id, username FROM secapp_userprofile WHERE username = '{user_input}'"
        with connection.cursor() as cursor:
            try:
                cursor.execute(query)
                rows = cursor.fetchall()
            except Exception as exc:  # malformed injection can also just error
                return JsonResponse({"match_found": False, "error": str(exc)})
    else:
        # --- SECURE: parameterized query via the ORM
        rows = list(UserProfile.objects.filter(username=user_input).values_list("id", "username"))

    return JsonResponse({"match_found": len(rows) > 0, "row_count": len(rows)})


# ---------------------------------------------------------------------
# Table 2, row "Data-at-rest exposure" (write side)
# ---------------------------------------------------------------------
@require_POST
def save_profile_view(request):
    username = request.POST.get("username", "")
    note = request.POST.get("note", "")
    profile, _ = UserProfile.objects.update_or_create(
        username=username,
        defaults={
            "password_hash": make_password("placeholder-not-a-real-password"),
            "sensitive_note": note,
        },
    )
    return JsonResponse({"id": profile.id, "username": profile.username})


@require_GET
def read_profile_view(request, pk):
    try:
        profile = UserProfile.objects.get(pk=pk)
    except UserProfile.DoesNotExist:
        return JsonResponse({"error": "not found"}, status=404)
    # Reading through the ORM always decrypts (from_db_value) when
    # encryption is active -- this endpoint is the "legitimate app read"
    # path. run_attack_tests.py separately reads db.sqlite3 directly with
    # the sqlite3 module to simulate "direct inspection of a database
    # dump" and confirm the stored bytes are ciphertext, not plaintext.
    return JsonResponse({"id": profile.id, "username": profile.username, "note": profile.sensitive_note})


# ---------------------------------------------------------------------
# Table 2, row "Clickjacking"
# ---------------------------------------------------------------------
@require_GET
def frame_target_view(request):
    return HttpResponse("<html><body>frame target</body></html>", content_type="text/html")
