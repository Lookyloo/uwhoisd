#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class UWhoisdException(Exception):
    pass


class CreateDirectoryException(UWhoisdException):
    pass


class MissingEnv(UWhoisdException):
    pass
