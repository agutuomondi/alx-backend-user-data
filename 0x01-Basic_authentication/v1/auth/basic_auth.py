#!/usr/bin/env python3
"""Basic authentication module for the API.
"""

import re
import base64
import binascii
from typing import Tuple, TypeVar

from .auth import Auth
from models.user import User


class BasicAuth(Auth):
    """Basic authentication class."""

    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """Extracts the Base64 part of the Authorization header for a Basic Authentication."""
        if isinstance(authorization_header, str):
            match = re.fullmatch(r'Basic (?P<token>.+)', authorization_header.strip())
            if match:
                return match.group('token')
        return None

    def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:
        """Decodes a base64-encoded authorization header."""
        if isinstance(base64_authorization_header, str):
            try:
                decoded = base64.b64decode(base64_authorization_header, validate=True)
                return decoded.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None
        return None

    def extract_user_credentials(self, decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """Extracts user credentials from a base64-decoded authorization header."""
        if isinstance(decoded_base64_authorization_header, str):
            match = re.fullmatch(r'(?P<user>[^:]+):(?P<password>.+)', decoded_base64_authorization_header.strip())
            if match:
                return match.group('user'), match.group('password')
        return None, None

    def user_object_from_credentials(self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """Retrieves a user based on the user's authentication credentials."""
        if isinstance(user_email, str) and isinstance(user_pwd, str):
            try:
                users = User.search({'email': user_email})
                if users and users[0].is_valid_password(user_pwd):
                    return users[0]
            except Exception:
                pass
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Retrieves the user from a request."""
        auth_header = self.authorization_header(request)
        if auth_header:
            b64_auth_token = self.extract_base64_authorization_header(auth_header)
            if b64_auth_token:
                auth_token = self.decode_base64_authorization_header(b64_auth_token)
                if auth_token:
                    email, password = self.extract_user_credentials(auth_token)
                    return self.user_object_from_credentials(email, password)
        return None

