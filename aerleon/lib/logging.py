import logging
from multiprocessing import current_process

LOG_FORMAT = (
    '%(asctime)s.%(msecs)03d - %(process)s - %(levelname)s - %(filename)s:%(lineno)d] %(message)s'
)
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'


def get_worker_config(queue, log_level):
    return {
        'version': 1,
        'handlers': {
            'queue': {
                'class': 'logging.handlers.QueueHandler',
                'queue': queue,
            }
        },
        'root': {'handlers': ['queue'], 'level': log_level},
    }


def get_root_config(log_level):
    return {
        'version': 1,
        # 'disable_existing_loggers': True,
        'formatters': {'default': {'format': LOG_FORMAT, 'datefmt': DATE_FORMAT}},
        'handlers': {
            'console': {
                # **Use your custom LogHandler here:**
                'class': 'aerleon.lib.logging.LogHandler',
                'level': log_level,
                'formatter': 'default',
            },
        },
        'root': {'handlers': ['console'], 'level': log_level},
    }


class LogHandler(logging.StreamHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cache = set()

    def emit(self, record):
        if record.name == "root":
            logger = logging.getLogger()
        else:
            logger = logging.getLogger(record.name)

        if logger.isEnabledFor(record.levelno):
            record.processName = '{} (for {})'.format(current_process().name, record.processName)
            emit_once = getattr(record, "emit_once", False)
            if emit_once:
                msg_to_check = record.getMessage()
                if msg_to_check in self.cache:
                    return
                else:
                    self.cache.add(msg_to_check)

            # **Crucially, use the formatter to format the record into a string:**
            formatted_message = self.format(record)
            self.stream.write(formatted_message + self.terminator)
            self.stream.flush()  # Important to flush, especially for testing
