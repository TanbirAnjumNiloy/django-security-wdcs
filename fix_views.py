import pathlib

p = pathlib.Path(r"C:\Users\searc\Desktop\django_test_kit\secapp\views.py")
text = p.read_text(encoding="utf-8")

old = '''from django.views.decorators.http import require_GET, require_POST'''

new = '''from django.views.decorators.http import require_GET, require_POST
from django.views.decorators.csrf import ensure_csrf_cookie'''

if old not in text:
    print("PATCH1_FAILED")
else:
    text = text.replace(old, new, 1)
    print("PATCH1_OK")

old2 = '''@require_GET
def ping_view(request):
    return JsonResponse({"status": "ok", "security_level": settings.SECURITY_LEVEL})'''

new2 = '''@ensure_csrf_cookie
@require_GET
def ping_view(request):
    return JsonResponse({"status": "ok", "security_level": settings.SECURITY_LEVEL})'''

if old2 not in text:
    print("PATCH2_FAILED")
else:
    text = text.replace(old2, new2, 1)
    print("PATCH2_OK")

p.write_text(text, encoding="utf-8")
print("VIEWS_PATCH_DONE")