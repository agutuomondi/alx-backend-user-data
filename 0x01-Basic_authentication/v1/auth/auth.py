#!/usr/bin/env python3
"""Authentication module for the API.
"""

import re
from typing import List, TypeVar
from flask import request


class Auth:
    """Authentication class."""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Checks if a path requires authentication."""
        if path is None or excluded_paths is None:
            return True

        for exclusion_path in map(lambda x: x.strip(), excluded_paths):
            pattern = self._generate_pattern(exclusion_path)
            if re.match(pattern, path):
                return False
        return True

    def _generate_pattern(self, exclusion_path: str) -> str:
        """Generates a regex pattern for path matching."""
        if exclusion_path.endswith('*'):
            return '{}.*'.format(exclusion_path[:-1])
        if exclusion_path.endswith('/'):
            return '{}/*'.format(exclusion_path[:-1])
        return '{}/*'.format(exclusion_path)

    def authorization_header(self, request=None) -> str:
        """Gets the authorization header field from the request."""
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Gets the current user from the request."""
        return None

