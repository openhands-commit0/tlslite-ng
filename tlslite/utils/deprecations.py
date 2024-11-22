"""Methods for deprecating old names for arguments or attributes."""
import warnings
import inspect
from functools import wraps

def deprecated_class_name(old_name, warn="Class name '{old_name}' is deprecated, please use '{new_name}'"):
    """
    Class decorator to deprecate a use of class.

    :param str old_name: the deprecated name that will be registered, but
       will raise warnings if used.

    :param str warn: DeprecationWarning format string for informing the
       user what is the current class name, uses 'old_name' for the deprecated
       keyword name and the 'new_name' for the current one.
       Example: "Old name: {old_nam}, use '{new_name}' instead".
    """
    def decorator(cls):
        new_name = cls.__name__
        def wrapper(*args, **kwargs):
            warnings.warn(warn.format(old_name=old_name, new_name=new_name),
                        DeprecationWarning, stacklevel=2)
            return cls(*args, **kwargs)
        globals()[old_name] = wrapper
        return cls
    return decorator

def deprecated_params(names, warn="Param name '{old_name}' is deprecated, please use '{new_name}'"):
    """Decorator to translate obsolete names and warn about their use.

    :param dict names: dictionary with pairs of new_name: old_name
        that will be used for translating obsolete param names to new names

    :param str warn: DeprecationWarning format string for informing the user
        what is the current parameter name, uses 'old_name' for the
        deprecated keyword name and 'new_name' for the current one.
        Example: "Old name: {old_name}, use {new_name} instead".
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for new_name, old_name in names.items():
                if old_name in kwargs:
                    warnings.warn(warn.format(old_name=old_name, new_name=new_name),
                                DeprecationWarning, stacklevel=2)
                    kwargs[new_name] = kwargs.pop(old_name)
            return func(*args, **kwargs)
        return wrapper
    return decorator

def deprecated_instance_attrs(names, warn="Attribute '{old_name}' is deprecated, please use '{new_name}'"):
    """Decorator to deprecate class instance attributes.

    Translates all names in `names` to use new names and emits warnings
    if the translation was necessary. Does apply only to instance variables
    and attributes (won't modify behaviour of class variables, static methods,
    etc.

    :param dict names: dictionary with paris of new_name: old_name that will
        be used to translate the calls
    :param str warn: DeprecationWarning format string for informing the user
        what is the current parameter name, uses 'old_name' for the
        deprecated keyword name and 'new_name' for the current one.
        Example: "Old name: {old_name}, use {new_name} instead".
    """
    def decorator(cls):
        old_getattr = cls.__getattr__ if hasattr(cls, '__getattr__') else None
        old_setattr = cls.__setattr__ if hasattr(cls, '__setattr__') else None

        def __getattr__(self, name):
            for new_name, old_name in names.items():
                if name == old_name:
                    warnings.warn(warn.format(old_name=old_name, new_name=new_name),
                                DeprecationWarning, stacklevel=2)
                    return getattr(self, new_name)
            if old_getattr:
                return old_getattr(self, name)
            raise AttributeError(name)

        def __setattr__(self, name, value):
            for new_name, old_name in names.items():
                if name == old_name:
                    warnings.warn(warn.format(old_name=old_name, new_name=new_name),
                                DeprecationWarning, stacklevel=2)
                    return setattr(self, new_name, value)
            if old_setattr:
                return old_setattr(self, name, value)
            return object.__setattr__(self, name, value)

        cls.__getattr__ = __getattr__
        cls.__setattr__ = __setattr__
        return cls
    return decorator

def deprecated_attrs(names, warn="Attribute '{old_name}' is deprecated, please use '{new_name}'"):
    """Decorator to deprecate all specified attributes in class.

    Translates all names in `names` to use new names and emits warnings
    if the translation was necessary.

    Note: uses metaclass magic so is incompatible with other metaclass uses

    :param dict names: dictionary with paris of new_name: old_name that will
        be used to translate the calls
    :param str warn: DeprecationWarning format string for informing the user
        what is the current parameter name, uses 'old_name' for the
        deprecated keyword name and 'new_name' for the current one.
        Example: "Old name: {old_name}, use {new_name} instead".
    """
    class DeprecatedAttrMetaclass(type):
        def __new__(cls, name, bases, attrs):
            for new_name, old_name in names.items():
                if old_name in attrs:
                    warnings.warn(warn.format(old_name=old_name, new_name=new_name),
                                DeprecationWarning, stacklevel=2)
                    attrs[new_name] = attrs.pop(old_name)
            return super(DeprecatedAttrMetaclass, cls).__new__(cls, name, bases, attrs)

    def decorator(cls):
        return DeprecatedAttrMetaclass(cls.__name__, cls.__bases__, dict(cls.__dict__))

def deprecated_method(message):
    """Decorator for deprecating methods.

    :param ste message: The message you want to display.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            warnings.warn(message, DeprecationWarning, stacklevel=2)
            return func(*args, **kwargs)
        return wrapper
    return decorator