#!/usr/bin/env python
from distutils.core import setup

setup(
    name = 'mongoengine-privileges',
    description = '''Mixin for MongoEngine that manages object-level privileges.''',
    version = 0.1,
    author = 'Paul Uithol - Progressive Company',
    author_email = 'paul.uithol@progressivecompany.nl',
    url = 'http://github.com/ProgressiveCompany/mongoengine-privileges',
    packages=['mongoengine_privileges'],
    requires=[
        'mongoengine',
        'mongoengine_relational',
        'pyramid',
        'inspect',
    ],
    install_requires=[
        'mongoengine',
        'mongoengine_relational',
        'pyramid',
        'inspect',
    ],
    classifiers = [
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Framework :: Pyramid',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Utilities'
    ],
)
