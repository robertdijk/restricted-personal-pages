import datetime
import json
import logging
import os
import random
import string
from contextlib import contextmanager
from enum import Enum
from logging.config import dictConfig
from pathlib import Path

import yaml
from flask import Flask, render_template, request, make_response
from mailinglogger import MailingLogger

app = Flask(__name__)

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})

logging_template = """<html><head><style>
    tt {
      padding: 0;
      margin: 0;
      color: #444444;
    }
    tt.WARNING {
      color: #CC6600
    }
    tt.ERROR {
      color: #990000
    }
    tt.CRITICAL {
      color: #990000
    }
    </style></head>
    <body><pre>%s</pre></body></html>
"""

_mail_enabled = os.environ.get("MAIL_ENABLED", default="false")
MAIL_ENABLED = _mail_enabled.lower() in {"1", "t", "true"}
MAIL_ADRES = os.environ.get("MAIL_ADRES", default=None)
MAIL_HOST = os.environ.get("MAIL_HOST", default=None)
MAIL_PORT = os.environ.get("MAIL_PORT", default=None)
MAIL_SUBJECT = os.environ.get("MAIL_SUBJECT", default=None)
MAIL_USERNAME = os.environ.get("MAIL_USERNAME", default=None)
MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", default=None)

if not app.debug and MAIL_ENABLED:
    mail_handler = MailingLogger(
        fromaddr=MAIL_ADRES,
        toaddrs=[MAIL_ADRES],
        mailhost=(MAIL_HOST, int(MAIL_PORT)),
        subject=MAIL_SUBJECT,
        username=MAIL_USERNAME,
        password=MAIL_PASSWORD,
        secure=True,
        template=logging_template,
        content_type='text/html'
    )
    mail_handler.setLevel(logging.INFO)
    formatter = logging.Formatter(
        '<tt class="%(levelname)s">%(asctime)s %(levelname)-8s %(message)s</tt>',
        '%Y-%m-%d %H:%M:%S'
    )
    mail_handler.setFormatter(formatter)
    app.logger.addHandler(mail_handler)
    app.logger.info(f"Added mailinglogger for {[MAIL_ADRES]}")


class ForbiddenReason(Enum):
    NO_NAME = 1
    NO_PAGE = 2
    IP_ALREADY_USED = 3
    MAX_IPS_REACHED = 4
    COOKIE_ALREADY_USED = 5
    INVALID_COOKIE = 6
    MAX_COOKIES_REACHED = 6


@app.route('/')
def index():
    """ Displays the index page accessible at '/'
    """
    return render_template('index.html')


@app.route('/page')
def page():
    with open_config() as config:
        if request.args.get('name', None) is None:
            return forbidden(config, ForbiddenReason.NO_NAME)

        page_item = None

        name = request.args['name']

        for config_name in config['pages']:
            if name.lower() == config_name or name.lower() in config['pages'][config_name]['aliases']:
                page_item = config_name

        if not page_item:
            return forbidden(config, ForbiddenReason.NO_PAGE)

        remote_ip = request.remote_addr

        if remote_ip not in config['pages'][page_item]['ips']:
            for config_name in config['pages']:
                if config_name == page_item:
                    continue
                if remote_ip in config['pages'][config_name]['ips']:
                    return forbidden(config, ForbiddenReason.IP_ALREADY_USED)

            if len(config['pages'][page_item]['ips']) >= config['pages'][page_item]['max_ips']:
                return forbidden(config, ForbiddenReason.MAX_IPS_REACHED)

            config['pages'][page_item]['ips'].append(remote_ip)

        cookie = request.cookies.get('super_secret')

        if cookie:
            for config_name in config['pages']:
                if config_name == page_item:
                    continue
                if cookie in config['pages'][config_name]['cookies']:
                    return forbidden(config, ForbiddenReason.COOKIE_ALREADY_USED)

            if cookie not in config['pages'][page_item]['cookies']:
                return forbidden(config, ForbiddenReason.INVALID_COOKIE)
        else:
            if len(config['pages'][page_item]['cookies']) >= config['pages'][page_item]['max_cookies']:
                return forbidden(config, ForbiddenReason.MAX_COOKIES_REACHED)

            cookie = ''.join(random.choices(string.ascii_lowercase, k=30))
            config['pages'][page_item]['cookies'].append(cookie)

        resp = make_response(render_template(f"pages/{config['pages'][page_item]['page']}"))
        exp = datetime.datetime.now()
        exp.replace(year=exp.year + 1)
        resp.set_cookie('super_secret', cookie, expires=exp, httponly=True)
        return resp


def forbidden(config, reason: ForbiddenReason):
    message = {'reason': reason.name}

    if request.args.get('name', None):
        message['entered_name'] = request.args['name']

    remote_ip = request.remote_addr
    message['request_ip'] = remote_ip

    message['ip_names'] = []

    for config_name in config['pages']:
        if remote_ip in config['pages'][config_name]['ips']:
            message['ip_names'].append(config_name)

    cookie = request.cookies.get('super_secret')
    message['cookie'] = cookie

    message['cookie_names'] = []

    if cookie:
        for config_name in config['pages']:
            if cookie in config['pages'][config_name]['cookies']:
                message['cookie_names'].append(config_name)

    app.logger.warning(f"Blocked request:\n\n{json.dumps(message, indent=4)}")

    return render_template('forbidden.html')


if __name__ == '__main__':
    app.run()


@contextmanager
def open_config():
    path = Path('config.yaml')
    with path.open(mode='r+', ) as file:
        doc = yaml.load(file, Loader=yaml.FullLoader)
        try:
            yield doc
        finally:
            file.seek(0)
            file.truncate()
            file.write(yaml.dump(doc))
