#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: YangCan
"""
~~~ Basic Request a signature authentication for Flask routes.

example:
    ~~~ app.py
    from flask import Flask
    from flask.ext.ApiHmac import ApiHmac
    app = Flask(__name__)

    app.config.update(
        DOGO_HMAC_TIME = 3600,
        DOGO_HMAC_ENABLED = True
    )

    dogoHmac = ApiHmac(app)

    ~~~ views.py
    from app import app, dogoHmac

    secretInfo = {
        secretid: secretkey
    } 

    # callback
    @dogoHmac.get_secret_key
    def get_secret_key(secretid):
        if secretid:
            return secretInfo.get(secretid)
        return None


    @app.route('/index', methods=['GET', 'POST'])
    @dogoHmac.validate_hmac
    def index():
        return 'hello world!'

"""

import hashlib
import hmac
import json
from functools import wraps
import binascii
from flask import request, jsonify
import time


class ApiHmacError(Exception):
    """
        Error
    """

    def __init__(self, code=400, message=u'Request Error', *args, **kwargs):
        self.code = code
        self.message = message
        self.data = {'code': self.code, 'message': self.message}
        super(ApiHmacError, self).__init__(*args, **kwargs)

    def __str__(self):
        return repr(self.data)


class ApiHmac(object):
    """docstring for ApiHmac"""

    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)


    def init_app(self, app):
        self.hmac_time = app.config.get('DOGO_HMAC_TIME', 3600)
        self.hmac_enable = app.config.get('DOGO_HMAC_ENABLED', True)


    def get_secret_key(self, callback):
        """
            callback
        """
        self.get_secretkey_callback = callback
        return callback


    def _get_request_params(self, request_data):
        """
            get request params
        """
        if request_data:
            str_params = "&".join(
                key + "=" + str(request_data[key]) for key in sorted(request_data) if key != 'Signature')
            return str_params

    def _check_request_time(self, request_data):
        """
            Time must be less than 30 minutes
        """
        try:
            diff_time = int(int(time.time()) - int(request_data.get('Timestamp', 0)))
            if diff_time <= int(self.hmac_time):
                return True
            return False
        except:
            return False


    def _check_request_rate(self):
        """
            check request rate per minutes
        """
        pass

    def _args_is_ok(self, request_data):
        """
            check request args is ok
        """
        __field__ = ('Signature', 'Action', 'SecretId', 'Timestamp', 'Nonce')

        if request_data:
            s = [x for x in __field__ if x not in request_data.keys() or len(request_data.get(x, '')) == 0]
            if len(s): return False

            return True
        return False


    def _split_request_info(self):
        """
            split request info
        """
        self.requestMethod = request.method
        self.requestPath = request.path
        self.requestHost = request.host

        if self.requestMethod == 'POST':
            self.request_data = request.form
        elif self.requestMethod == 'GET':
            self.request_data = request.args
        else:
            # not operation
            return False


    def _sign(self, secret_key, source):
        """
            _sign
        """
        hashed = hmac.new(secret_key, source, hashlib.sha1)
        signText = binascii.b2a_base64(hashed.digest())[:-1]
        return signText


    def _validate(self):
        """
            check request validate
        """
        st = self._split_request_info()

        if st is False:
            raise ApiHmacError(400, u'Unsupported Operation Error')

        # not request params
        if len(self.request_data) == 0:
            raise ApiHmacError(400, u'Missing Parameter Error')


        # check request params is ok
        if self._args_is_ok(self.request_data) is False:
            raise ApiHmacError(400, u'Invalid Parameter Error')

        # check request params time value is ok
        if self._check_request_time(self.request_data) is False:
            raise ApiHmacError(400, u'TimeOut Or Time Error')

        # check request params signature value is ok
        self.signature = self.request_data['Signature'] if len(self.request_data.get('Signature', '')) != 0 else ''
        if not self.signature:
            raise ApiHmacError(400, u'Invalid Parameter Error')

        # check request params secretid
        self.secretid = self.request_data['SecretId'] if len(self.request_data.get('SecretId', '')) != 0 else ''
        if not self.secretid:
            raise ApiHmacError(400, u'Invalid Parameter Error')

        # get secretkey callback
        if self.get_secretkey_callback:
            self.secretkey = self.get_secretkey_callback(self.secretid)
            if not self.secretkey:
                raise ApiHmacError(400, u'Invalid AccessKeyId Error')
        else:
            raise ApiHmacError(400, u'Invalid AccessKeyId Error')

        self.str_params = self._get_request_params(self.request_data)
        source = '%s%s%s?%s' % (
            self.requestMethod,
            self.requestHost,
            self.requestPath,
            self.str_params
        )

        if self._sign(self.secretkey, source) != self.signature:
            raise ApiHmacError(400, u'Authentication Error')

        return True


    def validate_hmac(self, func):
        """
            decorated
        """

        @wraps(func)
        def decorated_view_function(*args, **kwargs):
            if not self.hmac_enable:
                # hmac is disabled
                return func(*args, **kwargs)
            try:
                if self._validate():
                    return func(*args, **kwargs)
            except ApiHmacError as ex:
                response = jsonify(ex.data)
                response.status_code = 444
                return json.dumps(message)

        return decorated_view_function

