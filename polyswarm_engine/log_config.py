from datetime import datetime, timezone as tz
import logging

from polyswarm_engine.settings import LOG_LEVEL, LOG_FORMAT

try:
    from pythonjsonlogger import jsonlogger
except ImportError:
    jsonlogger = None
else:

    class JSONFormatter(jsonlogger.JsonFormatter):
        """
        Class to add custom JSON fields to our logger.
        Presently just adds a timestamp if one isn't present and the log level.
        INFO: https://github.com/madzak/python-json-logger#customizing-fields
        """

        def add_fields(self, log_record, record, message_dict):
            super(JSONFormatter, self).add_fields(log_record, record, message_dict)
            if not log_record.get('timestamp'):
                # this doesn't use record.created, so it is slightly off
                now = datetime.now(tz.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                log_record['timestamp'] = now
            if log_record.get('level'):
                log_record['level'] = log_record['level'].upper()
            else:
                log_record['level'] = record.levelname


try:
    import click
    import click_log
except ImportError:
    click_log = None
else:
    # adding color to INFO log messages as well
    click_log.core.ColorFormatter.colors['info'] = dict(fg='green')

    class NamedColorFormatter(logging.Formatter):
        colors = {
            'error': dict(fg='red'),
            'exception': dict(fg='red'),
            'critical': dict(fg='red'),
            'debug': dict(fg='blue'),
            'warning': dict(fg='yellow'),
            'info': dict(fg='green'),
        }

        def format(self, record):
            if not record.exc_info:
                level = record.levelname.lower()
                msg = logging.Formatter.format(self, record)
                if level in self.colors:
                    sopts = self.colors[level]
                    lines = msg.splitlines()
                    msg = '\n'.join(click.style(x, **sopts) for x in lines)  # type: ignore
                return msg
            return logging.Formatter.format(self, record)


def get_logging(log_level=None, handler='console'):
    log_level = log_level or LOG_LEVEL
    return {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {
            'text': {
                'format': '%(asctime)s - %(levelname)-2s [%(filename)s:%(lineno)d][%(funcName)1s] %(message)s',
            },
            'json': {
                'format': '%(asctime)s %(levelname) %(message) %(filename) %(lineno) %(funcName)',
                'class': 'polyswarm_engine.log_config.JSONFormatter',
            },
            'click': {
                'format': '%(asctime)s - %(levelname)-2s [%(filename)s:%(lineno)d][%(funcName)1s] %(message)s',
                'class': 'polyswarm_engine.log_config.NamedColorFormatter',
            },
        },
        'handlers': {
            'console': {
                'level': log_level,
                'class': 'logging.StreamHandler',
                'formatter': LOG_FORMAT,
            },
            'click': {
                'level': log_level,
                'class': 'click_log.core.ClickHandler',
                'formatter': 'click',
            },
        },
        'loggers': {
            'polyswarm_engine': {
                'level': log_level,
            },
            'celery': {
                'level': log_level,
            },
        },
        'root': {
            'handlers': [handler],
            'level': log_level,
        }
    }
