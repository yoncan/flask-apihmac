# flask-apihmac
Basic Request a signature authentication for Flask routes.

# example
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
