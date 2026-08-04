"""Route blueprints. register_all(app) mendaftarkan semua blueprint."""

from . import core, tools1, tools2, tools3, misc

_BLUEPRINTS = [core.bp, tools1.bp, tools2.bp, tools3.bp, misc.bp]


def register_all(app):
    for bp in _BLUEPRINTS:
        app.register_blueprint(bp)
