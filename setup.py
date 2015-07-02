"""
Flask-ApiHmac
--------------

Basic Request a signature authentication for Flask routes.
"""
from setuptools import setup


setup(
    name='Flask-ApiHmac',
    version='0.0.1',
    url='http://github.com/yoncan/flask-httpauth/',
    license='MIT',
    author='YangCan',
    author_email='yoncan@qq.com',
    description='Basic Request a signature authentication for Flask routes.',
    long_description=__doc__,
    py_modules=['flask_apihmac'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Flask'
    ],
    test_suite = "None",
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
