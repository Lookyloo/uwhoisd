#!/usr/bin/env python
# -*- coding: utf-8 -*-

from uwhois import Uwhois

def test_queries():
    w = Uwhois()
    print(w.query('google.com'))
    print(w.query('8.8.8.8'))
    print(w.query('laposte.net'))
