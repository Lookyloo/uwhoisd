#!/usr/bin/env python
# -*- coding: utf-8 -*-

from uwhois import Uwhois


def test_queries():
    w = Uwhois()
    w.query('google.com')
    w.query('8.8.8.8')
    w.query('laposte.net')
