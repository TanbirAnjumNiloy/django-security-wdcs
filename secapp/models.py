import os
from django.conf import settings
from django.db import models
from cryptography.fernet import Fernet

_cipher_suite = Fernet(os.environ["FIELD_ENCRYPTION_KEY"].encode())


class EncryptedTextField(models.TextField):
    """Model field that transparently encrypts values at rest.

    This is the corrected version from the paper: get_prep_value()
    encrypts on WRITE, from_db_value() decrypts on READ.
    """

    def get_prep_value(self, value):
        if value is not None:
            return _cipher_suite.encrypt(value.encode()).decode()
        return value

    def from_db_value(self, value, expression, connection):
        if value is not None:
            return _cipher_suite.decrypt(value.encode()).decode()
        return value


class UserProfile(models.Model):
    username = models.CharField(max_length=150, unique=True)
    password_hash = models.CharField(max_length=255)
    # Encrypted only when SECURITY_LEVEL == "full"; otherwise stored as
    # plain TextField so the "data-at-rest exposure" test in
    # run_attack_tests.py can show the real difference.
    if getattr(settings, "ENCRYPT_SENSITIVE_FIELDS", False):
        sensitive_note = EncryptedTextField(blank=True, default="")
    else:
        sensitive_note = models.TextField(blank=True, default="")

    class Meta:
        app_label = "secapp"


class Comment(models.Model):
    content = models.TextField()

    class Meta:
        app_label = "secapp"
