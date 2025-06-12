from abc import ABCMeta, abstractmethod
from typing import Any, Callable, List, MutableMapping, Optional


class AbstractOption(metaclass=ABCMeta):
    def __init__(self, config: MutableMapping, *args, **kwargs):
        self.config_ref = config

    def __repr__(self):
        return f"{self.__class__.__name__}({self.getKey()})"

    @abstractmethod
    def ingest(self, token: str) -> bool:
        # should return true if token is ingested
        pass

    @abstractmethod
    def complete(self) -> bool:
        pass

    @abstractmethod
    def getKey(self) -> str:
        pass


class BooleanKeywordOption(AbstractOption):
    true_value = True

    def __init__(self, key: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key = key

    def withTrueValue(self, value: Any):
        self.true_value = value
        return self

    def getKey(self) -> str:
        return self.key

    def ingest(self, token: str) -> bool:
        got_token = False
        if token == self.key:
            self.config_ref[self.key] = self.true_value  # perl
            got_token = True
        return got_token

    def complete(self) -> bool:
        return True


class AbstractValueOption(AbstractOption, metaclass=ABCMeta):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key_ingested = False
        self.any_value_ingested = False

    @abstractmethod
    def tokenValidationTemplateMethod(self, token: str) -> bool:
        pass

    def canAcceptValues(self):
        return self.key_ingested and not self.any_value_ingested

    def configInsertTemplateMethod(self, token: str):
        self.config_ref[self.getKey()] = token

    def ingest(self, token: str) -> bool:
        got_token = False
        if token == self.getKey():
            self.key_ingested, got_token = True, True
        elif self.canAcceptValues() and self.tokenValidationTemplateMethod(token):
            self.any_value_ingested, got_token = True, True
            self.configInsertTemplateMethod(token)
        else:
            # reset so that we don't accept values after other tokens
            self.key_ingested, self.any_value_ingested = False, False
        return got_token

    def complete(self) -> bool:
        return (
            (self.key_ingested, self.any_value_ingested) == (False, False)
            or self.key_ingested
            and self.any_value_ingested
        )


class ValueOption(AbstractValueOption):
    def __init__(self, *args, **kwargs: List[str]):
        super().__init__(*args, **kwargs)
        self.key = list(kwargs.keys())[0]
        self.values = kwargs[self.key]

    def getKey(self) -> str:
        return self.key

    def tokenValidationTemplateMethod(self, token: str) -> bool:
        return token in self.values


class ArbitraryValueOption(AbstractValueOption):
    def __init__(self, key: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key = key

    def getKey(self) -> str:
        return self.key

    def tokenValidationTemplateMethod(self, token: str) -> bool:
        return token != self.key  # accept anything but key


class MultiValueOption(ValueOption):
    def canAcceptValues(self):
        return self.key_ingested

    def configInsertTemplateMethod(self, token: str):
        if self.getKey() not in self.config_ref.keys():
            self.config_ref[self.getKey()] = []
        self.config_ref[self.getKey()].append(token)
        self.config_ref[self.getKey()].sort()


class NumberValueOption(AbstractValueOption):
    def __init__(self, key: str, lower: float, upper: float, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key = key
        self.lower = lower
        self.upper = upper

    def getKey(self) -> str:
        return self.key

    def tokenValidationTemplateMethod(self, token: str) -> bool:
        return token.isdecimal() and self.lower <= float(token) <= self.upper


class OptionError(Exception):
    pass


def ProcessOptions(
    options_lambda: Callable[[MutableMapping], List[AbstractOption]],
    tokens: List[str],
    with_config: Optional[MutableMapping] = None,
):
    if with_config is None:
        with_config = dict()
    available_options = options_lambda(with_config)
    for t in tokens:
        ingested_options = []
        for option in available_options:
            ingested_options.append(option.ingest(t))
        if not any(ingested_options):
            raise OptionError(f"incorrect filter option directive {t}")
    incomplete_options = list(filter(lambda o: not o.complete(), available_options))
    if incomplete_options:
        raise OptionError(f"missing or incorrect value for filter option(s) {incomplete_options}")
    return with_config
