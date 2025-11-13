import os
import builtins
import datetime as dt
import functools
import inspect
import importlib
import json
import logging
import pathlib
import typing as t

import click

import polyswarm_engine.settings
from polyswarm_engine.bounty import forge_local_bounty
from polyswarm_engine.constants import (
    ARTIFACT_TYPES,
    BENIGN,
    EICAR_CONTENT,
    FILE_ARTIFACT,
    MALICIOUS,
    UNKNOWN,
    URL_ARTIFACT,
)
from polyswarm_engine.utils import is_fifo

logger = logging.getLogger(__name__)

# Artifact type for manually constructed bounties
BOUNTY_ARTIFACT = "bounty"


@click.group()
def engine_cli():
    from logging.config import dictConfig

    from polyswarm_engine import log_config

    dictConfig(log_config.get_logging(handler='click'))


@engine_cli.command("devserver")
@click.option('--port', '-p', help='Server port', type=int, default=8000, show_default=True)
@click.option('--secret', '-s', help='Webhook secret  [env: PSENGINE_WEBHOOK_SECRET]', envvar='PSENGINE_WEBHOOK_SECRET')
@click.pass_obj
def devserver(engine, port, secret, **kwargs):
    """
    Simple HTTP server only usable during development
    """
    from logging.config import dictConfig
    from wsgiref.simple_server import make_server

    from polyswarm_engine import log_config
    from polyswarm_engine.wsgi import ValidateSenderMiddleware, application as wsgi_app

    dictConfig(log_config.get_logging())

    wsgi_app = ValidateSenderMiddleware(wsgi_app, secret=secret)
    with make_server('', port, wsgi_app) as httpd:
        print("Serving {} on port {}, control-C to stop".format(engine.name, port))
        httpd.serve_forever()


@engine_cli.command('create-vhost', context_settings=dict(show_default=True))
@click.option('--vhost', envvar='PSENGINE_BROKER_VHOST', default='engines')
@click.option('--broker', envvar='PSENGINE_BROKER_URL', default='amqp://user:password@rabbitmq:5672')
def create_vhost(vhost: str, broker: str):
    """Ensure that a vhost exists in the RabbitMQ broker"""
    from urllib import parse
    import requests
    from polyswarm_engine.celeryconfig import CeleryConfig

    broker_url = CeleryConfig(broker=broker, vhost=vhost).broker_url
    parsed_url = parse.urlparse(broker_url)
    vhost = vhost or parsed_url.path.strip(' /')

    if vhost:
        logger.info("Creating '%s' vhost", vhost)
        create_url = parse.urlunparse(
            ('http', f'{parsed_url.hostname}:1{parsed_url.port}', f'/api/vhosts/{vhost}', '', '', '')
        )
        r = requests.put(create_url, auth=(parsed_url.username, parsed_url.password))
        r.raise_for_status()
        click.echo(f'Successfully create vhost {vhost}')
    else:
        click.echo('No vhost defined for the celery broker')


def _gather_analyses(backend, artifacts, artifact_type):
    futures = list()
    for artifact in artifacts:
        bounty = _make_bounty(artifact, artifact_type)
        analysis = backend.analyze(bounty)
        result = (artifact, bounty, analysis)

        # If our result is already ready, print it immediately
        if analysis.ready():
            yield result
        else:
            futures.append(result)

    yield from futures


@engine_cli.command("analyze", help="Analyze artifacts")
@click.option("-v", "--verbose", count=True)
@click.option("--check-empty", help="Verify this engine can analyze an empty bounty", default=False, is_flag=True)
@click.option("--check-eicar", help="Verify this engine can analyze EICAR test file", default=False, is_flag=True)
@click.option(
    '--check-wicar',
    '--check-exploit-url',
    help='Verify this engine can analyze the WICAR exploit kit URL',
    default=False,
    is_flag=True,
)
@click.option(
    "--artifact-type",
    "-t",
    type=click.Choice([BOUNTY_ARTIFACT, *ARTIFACT_TYPES], case_sensitive=False),
    default=FILE_ARTIFACT,
    help="Artifact type to use when constructing bounties. "
    f"'{BOUNTY_ARTIFACT}' loads manually constructed bounties, "
    "treating each argument as the path to a JSON-encoded bounty object"
)
@click.argument("artifacts", nargs=-1)
@click.pass_obj
def analyze(engine, artifacts, artifact_type, verbose, check_eicar, check_empty, check_wicar, **kwargs):
    # force celery backend to be eager when running local analyze
    os.environ['PSENGINE_TASK_ALWAYS_EAGER'] = '1'
    importlib.reload(polyswarm_engine.settings)

    with engine.create_backend() as backend:
        if check_eicar:
            analysis = backend.analyze(_make_bounty(EICAR_CONTENT, FILE_ARTIFACT)).get()
            _check_analysis(analysis, expected={MALICIOUS})

        if check_empty:
            analysis = backend.analyze(_make_bounty(b'', FILE_ARTIFACT)).get()
            _check_analysis(analysis, expected={BENIGN, UNKNOWN})

        if check_wicar:
            # MS05-054 Microsoft Internet Explorer JavaScript OnLoad Handler
            url = "http://malware.wicar.org/data/ms05_054_onload.html"
            analysis = backend.analyze(_make_bounty(url, URL_ARTIFACT)).get()
            _check_analysis(analysis, expected={MALICIOUS})

        for artifact, bounty, future in _gather_analyses(backend, artifacts, artifact_type):
            if artifact and len(artifacts) > 1:
                _echo(f"{artifact:-^80}", ostream="stderr")

            if verbose:
                _echo("Bounty: ", nl=False, ostream="stderr")
                _echo(bounty, bold=True, ostream="stderr")
                _echo("Analysis: ", nl=False, ostream="stderr")

            _echo(future.get(), bold=bool(verbose))


def _check_analysis(analysis, expected):
    _echo(analysis)
    assert isinstance(analysis, t.Mapping)
    assert analysis["verdict"] in expected, f"Received '{analysis['verdict']}' instead of {' or '.join(expected)}"


def _make_bounty(artifact, artifact_type, **kwargs):
    forge = functools.partial(forge_local_bounty, artifact_type=artifact_type, **kwargs)

    if artifact_type == BOUNTY_ARTIFACT:
        return json.load(click.open_file(artifact, "rb"))
    elif isinstance(artifact, bytes):
        return forge(data=artifact)
    elif artifact == "-" or is_fifo(artifact):
        return forge(stream=click.open_file(artifact, "rb"))
    elif artifact_type == URL_ARTIFACT:
        return forge(data=artifact)
    elif artifact_type == FILE_ARTIFACT:
        return forge(path=artifact)
    else:
        raise ValueError(f"Invalid artifact: {artifact}")


@engine_cli.command("create-bounty", help="Make a fresh bounty from a file or URL artifact")
@click.option(
    "--artifact-type",
    "-t",
    type=click.Choice(list(ARTIFACT_TYPES), case_sensitive=False),
    default=FILE_ARTIFACT,
    help="Artifact type to use when constructing bounties. "
)
@click.option("--expiration", type=int, default=60 * 60 * 24 * 365, help="Number of seconds until bounty expiration")
@click.option("--response-url", help="The URL to send results to")
@click.argument("artifact")
def create_bounty(artifact, artifact_type, expiration, response_url):
    bounty = _make_bounty(artifact, artifact_type, expiration=dt.timedelta(seconds=expiration))

    if response_url:
        bounty["response_url"] = response_url

    _echo(bounty)


@engine_cli.command(
    "worker",
    help="Start celery worker",
    context_settings=dict(ignore_unknown_options=True),
)
@click.argument("celery_args", nargs=-1)
@click.pass_obj
def worker(engine, celery_args, **kwargs):
    from logging.config import dictConfig

    from polyswarm_engine import log_config

    dictConfig(log_config.get_logging())

    with engine.create_backend() as backend:
        backend.app.worker_main(argv=["worker", *celery_args])


class EngineCommandsGroup(click.MultiCommand):
    def list_commands(self, ctx):
        return ctx.obj.cmd

    def get_command(self, ctx, name):
        engine = ctx.obj
        cmd = engine.cmd[name]
        func = cmd["func"]
        argspec = inspect.getfullargspec(func)
        docstr = cmd["doc"]

        def callback(**params):
            args = []

            for arg in set(argspec.args) & set(params.keys()):
                args.append(params.pop(arg))

            if argspec.varargs in params:
                args.extend(params.pop(argspec.varargs))

            with engine.create_backend():
                result = func(*args, **params)
                _echo(result, fg="black", bold=True)

        return click.Command(
            name=name,
            callback=callback,
            help=docstr or name,
            short_help=docstr.split("\n")[0] or None,
            params=list(self._argspec_to_params(argspec)),
        )

    @staticmethod
    def _argspec_to_params(spec: "inspect.FullArgSpec") -> "t.Iterator[click.Parameter]":
        """Convert the function signature of a command to `click.Parameter` objects"""

        def get_type(param_name):
            if not spec.annotations:
                return None

            typ = spec.annotations.get(param_name)

            if isinstance(typ, str):
                if hasattr(builtins, typ):
                    return getattr(builtins, typ)
                elif typ == "Path" or typ == "pathlib.Path":
                    return pathlib.Path
                else:
                    return None

            return typ

        # `kwonlyargs` is a list of keyword-only parameter names in declaration order
        if spec.kwonlyargs:
            for name in spec.kwonlyargs:
                # `kwonlydefaults` holds dictionary mapping parameter names from `kwonlyargs`
                # to the default values used if no argument is supplied
                if spec.kwonlydefaults and name in spec.kwonlydefaults:
                    yield click.Option([f"--{name}"], default=spec.kwonlydefaults[name], type=get_type(name))
                else:
                    yield click.Option([f"--{name}"], required=True, type=get_type(name))

        # `args` is a list of the positional parameter names
        if spec.args:
            # `defaults` is an n-tuple of default argument values for the last n positional parameters
            if spec.defaults:
                index = len(spec.args) - len(spec.defaults)

                # yield each of the positional args w/o any associated defaults
                for name in spec.args[:index]:
                    yield click.Argument([name], required=True, type=get_type(name))

                # ... and then the rest of the positional args w/ default values
                for name, default in zip(spec.args[index:], spec.defaults):
                    yield click.Argument([name], default=default, type=get_type(name))
            else:
                for name in spec.args:
                    yield click.Argument([name], required=True, type=get_type(name))

        # `varargs` is the name of the * parameter or `None` if not accepted.
        if spec.varargs:
            yield click.Argument([spec.varargs], nargs=-1)


engine_cli.add_command(EngineCommandsGroup(name="commands", help="Engine commands"))


def _echo(msg, **echo_options):
    if msg is None:
        return
    elif isinstance(msg, dict):
        msg = json.dumps(msg, indent=2)

    if "ostream" in echo_options:
        echo_options["file"] = click.get_text_stream(echo_options.pop("ostream"))

    click.secho(msg, **echo_options)
