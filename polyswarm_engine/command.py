import inspect

from .utils import get_func_name, get_func_qual


class CommandRegistry:

    def __init__(self):
        self._metadata = dict()

    def __iter__(self):
        return iter(self._metadata)

    def __getitem__(self, name):
        return {"func": self.__dict__[name], **self._metadata[name]}

    def __getattr__(self, name):
        # XXX: This is here to make sure that `mypy` doesn't raise an error for items inside `self.__dict__`
        ...

    def _add(self, func, name=None):
        module, fnname = get_func_qual(func)
        name = name or fnname

        if name.startswith('_'):
            raise ValueError("Cannot use a command name starting with '_'")

        self._metadata[name] = {
            "name": name,
            "qualname": get_func_name(func),
            "module": module,
            "doc": inspect.getdoc(func) or "",
        }
        self.__dict__[name] = func
