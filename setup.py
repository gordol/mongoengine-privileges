import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.md')).read()

requires=[
    'mongoengine',
    'mongoengine_relational',
    'pyramid',
    'inspect',
]

setup(
    name = 'mongoengine-privileges',
    version = 0.1,
    description = '''Mixin for MongoEngine that manages object-level privileges.''',
    long_description = README,
    author = 'Paul Uithol - Progressive Company',
    author_email = 'paul.uithol@progressivecompany.nl',
    url = 'http://github.com/ProgressiveCompany/mongoengine-privileges',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    requires=requires,
    install_requires=requires,
    tests_require=requires,
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
