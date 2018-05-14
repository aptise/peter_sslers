def set_bool_setting(settings, key):
    # make sure to pass in config.registry.settings
    _bool = False
    if (key in settings) and (settings[key].lower() in ('1', 'true', )):
        _bool = True
    settings[key] = _bool
    return _bool


def set_int_setting(settings, key, default=None):
    # make sure to pass in config.registry.settings
    value = default
    if key in settings:
        value = int(settings[key])
    else:
        value = int(default)
    settings[key] = value
    return value


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -


__all__ = ('set_bool_setting',
           'set_int_setting',
           )
