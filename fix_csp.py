import pathlib

p = pathlib.Path(r"C:\Users\searc\Desktop\django_test_kit\testproject\settings.py")
text = p.read_text(encoding="utf-8")

old = '''    CSP_DEFAULT_SRC = ("'self'",)
    CSP_SCRIPT_SRC = ("'self'",)
    CSP_STYLE_SRC = ("'self'",)
    CSP_FRAME_ANCESTORS = ("'none'",)'''

new = '''    CONTENT_SECURITY_POLICY = {
        "DIRECTIVES": {
            "default-src": ("'self'",),
            "script-src": ("'self'",),
            "style-src": ("'self'",),
            "frame-ancestors": ("'none'",),
        }
    }'''

if old not in text:
    print("CSP_PATCH_FAILED")
else:
    p.write_text(text.replace(old, new), encoding="utf-8")
    print("CSP_PATCH_OK")