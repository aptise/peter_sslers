EVENTS_USE_ALT = False


def get_dbSessionLogItem(ctx):
    """
    at one point this library tried to send certain tables to a separate logger
    that is a little bit beyond out scope now
    """
    dbSession = ctx.dbSessionLogger if EVENTS_USE_ALT else ctx.dbSession
    return dbSession
