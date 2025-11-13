import logging.config
import json
import warnings
import hashlib
import hmac
from io import BytesIO

import flask as f
from flask import jsonify, request

from polyswarm_engine import log_config
from polyswarm_engine.backend import CeleryBackend
from polyswarm_engine.settings import PSENGINE_WEBHOOK_SECRET

logger = logging.getLogger(__name__)
logging.config.dictConfig(log_config.get_logging())
backend = CeleryBackend()
web = f.Flask('engines-webservice')


def response(msg, status=200):
    return jsonify(msg), status


@web.route('/', methods=['GET', 'POST'])
def ping():
    return response({'status': 'OK'})


@web.route('/<engine_queue>', methods=['GET'])
def ping_engine(engine_queue):
    return response({'status': 'OK'})


@web.route('/<engine_queue>', methods=['POST'])
def bounty_engine(engine_queue):
    event = request.headers.environ.get('HTTP_X_POLYSWARM_EVENT', '<not provided>')
    if event == 'bounty':
        backend.analyze(request.json, queue=engine_queue)
        return response({'status': 'ACCEPTED'}, 202)
    elif event == 'ping':
        return response({'status': 'OK'})
    else:
        return response({'X-POLYSWARM-EVENT': f'event ({event}) not supported'}, 400)


class ValidateSenderMiddleware:
    """
    WSGI midleware that validates the bounties coming from PolySwarm.

    It uses the `secret`, defaulted to PSENGINE_WEBHOOK_SECRET envvar,
    as key generate the HMAC digest of HTTP bodies
    and compare it to the `X-Polyswarm-Signature` received
    as HTTP header.
    """

    def __init__(self, app, secret=PSENGINE_WEBHOOK_SECRET, safe_verbs={'GET', 'HEAD'}):
        self.app = app
        self.safe_verbs = safe_verbs
        self.webhook_secret = secret
        if not secret:
            warnings.warn(
                'No secret provided, nor PSENGINE_WEBHOOK_SECRET env set. '
                'Bounties will not be checked for source authenticity'
            )

    def __call__(self, environ, start_response):
        if environ['REQUEST_METHOD'] in self.safe_verbs or not self.webhook_secret:
            return self.app(environ, start_response)

        # the environment variable CONTENT_LENGTH may be empty or missing
        try:
            content_length = int(environ.get('CONTENT_LENGTH', 0))
        except ValueError:
            content_length = 0

        wsgi_input = environ['wsgi.input'].read(content_length)
        try:
            # added .encode().decode() to make this work in python 3.8+
            # else hmac.compare_digest() complains about non-ascii chars
            signature = environ['HTTP_X_POLYSWARM_SIGNATURE'].encode('utf-8').decode('utf-8')
        except KeyError:
            message = json.dumps(
                {'X-POLYSWARM-SIGNATURE': 'Signature not included in headers'},
            ).encode('utf-8')
            start_response(
                '400 Bad Request',
                [('Content-Length', f'{len(message)}'), ('Content-Type', 'application/json')],
            )
            return [message]

        if self._valid_signature(wsgi_input, signature, self.webhook_secret):
            environ['wsgi.input'] = BytesIO(wsgi_input)
            return self.app(environ, start_response)
        else:
            message = json.dumps({'X-POLYSWARM-SIGNATURE': 'Signature does not match body'}).encode('utf-8')
            start_response(
                '401 Not Authorized',
                [('Content-Length', f'{len(message)}'), ('Content-Type', 'application/json')],
            )
            return [message]

    @staticmethod
    def _valid_signature(body, signature, secret) -> bool:
        return signature_is_valid(body, signature, secret)


def signature_is_valid(body, signature, secret) -> bool:
    """Validates the PolySwarm signature on `X-POLYSWARM-SIGNATURE` request header"""
    digest = hmac.new(secret.encode('utf-8'), body, digestmod=hashlib.sha256).hexdigest()
    logger.debug(
        'Comparing computed digest "%s" (%d) vs given signature "%s" (%d)',
        digest,
        len(digest),
        signature,
        len(signature),
    )
    return hmac.compare_digest(digest, signature)


# Standard WSGI app named 'application'
application = web.wsgi_app
