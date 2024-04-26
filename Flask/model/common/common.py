from datetime import datetime

from sqlalchemy import MetaData
from sqlalchemy.inspection import inspect
from sqlalchemy.orm import declarative_base, registry, DeclarativeMeta

Base = declarative_base()


class SerializableModel:

    def to_dict(self, with_prefix: bool = False, prefix: str = None) -> dict[str, str]:
        data: dict = {}
        # Získanie verejných atribútov objektu
        for attr in dir(self):
            if not attr.startswith("_") and not callable(getattr(self, attr)):
                value = getattr(self, attr)
                if with_prefix:
                    attr = f'{prefix}{attr}'
                # Kontrola, či hodnota nie je inštancia MetaData
                if not isinstance(value, MetaData) and not isinstance(value, registry):
                    data[attr] = value

        # Konverzia hodnôt datetime na ich ISO formát
        for key, value in data.items():
            if isinstance(value, datetime):
                data[key] = value.isoformat()

        return data

    @classmethod
    def from_dict(cls, attributes: dict, date_conversion: bool = True, calculated_attrs: list[str] = []):
        from utils.string_utils import convert_iso_to_datetime
        # Get the constructor's parameter names
        if isinstance(cls, DeclarativeMeta):
            constructor_params = inspect(cls).attrs.keys()
        else:
            constructor_params = cls.__init__.__code__.co_varnames

        # Filter attributes to match the constructor's parameters
        constructor_attributes = {}
        for k, v in attributes.items():
            if k in constructor_params and k not in calculated_attrs:
                if isinstance(v, str) and 'T' in v and date_conversion:
                    constructor_attributes[k] = convert_iso_to_datetime(v)
                else:
                    constructor_attributes[k] = v
        instance = cls(**constructor_attributes)
        if len(calculated_attrs) != 0:
            for attr in calculated_attrs:
                setattr(instance, attr, attributes.get(attr))
        return instance

    def __eq__(self, other):
        return self.to_dict() == other.to_dict()


class SerializableDBModel(Base, SerializableModel):
    __abstract__ = True

    def __init__(self, **kwargs):
        super(SerializableDBModel, self).__init__(**kwargs)
