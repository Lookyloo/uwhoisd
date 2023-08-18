#!/usr/bin/env python3


class UWhoisdException(Exception):
    pass


class MissingEnv(UWhoisdException):
    pass


class CreateDirectoryException(UWhoisdException):
    pass


class ConfigError(UWhoisdException):
    pass
