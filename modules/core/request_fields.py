"""Reading a field out of a JSON request body, without guessing what it meant.

`bool(value)` is not "parse a boolean": in Python every non-empty string is
true, so ``bool("false")`` is True. A client that sends a boolean as a string —
trivial in a shell, in an Ansible or Terraform template, or from an agent
filling a tool schema by hand — asked for one thing and got its opposite, with
a 200.

`resources_backup.py` found this once, for `include_secrets`, where the
opposite meant a backup carrying every private key in plaintext instead of the
masked archive the caller asked for. This is that rule, in one place, for every
boolean the API reads: a JSON boolean is accepted, its absence falls back to the
documented default, and anything else is refused rather than interpreted.
"""


def json_bool(data, field, default=None):
    """Read *field* from *data* as a JSON boolean.

    Returns ``(value, None)`` for a real boolean or an absent field (which
    yields *default*), and ``(None, message)`` for anything else — a string, a
    number, null — so the caller can answer 400 with the message.

    ``default=None`` means the field is required: absent is an error too.
    """
    if not isinstance(data, dict) or field not in data:
        if default is None:
            return None, f'{field} is required and must be a JSON boolean (true or false)'
        return default, None
    value = data[field]
    if isinstance(value, bool):
        return value, None
    return None, (
        f'{field} must be a JSON boolean (true or false), not '
        f'{_describe(value)}. It is read as written: a string is not a boolean, '
        'so "false" would otherwise mean true.'
    )


def _describe(value):
    if value is None:
        return 'null'
    if isinstance(value, str):
        return f'the string {value!r}'
    return f'{type(value).__name__} {value!r}'


def json_booleans(**fields):
    """Decorator: refuse a request whose boolean fields are not booleans.

    ``@json_booleans(force=False)`` validates ``force`` before the view runs
    and leaves the parsed value in ``request.json_booleans['force']``; an
    absent field takes the default given here. A view therefore reads a value
    that is already a boolean, and does not grow a branch for the refusal —
    which matters, because the closures these views live in carry a complexity
    budget that only comes down.

    Returns ``({'error': ..., 'code': 'INVALID_REQUEST'}, 400)``, which Flask
    and flask-restx both serialise the same way.
    """
    from functools import wraps

    from flask import request

    def decorator(view):
        @wraps(view)
        def guarded(*args, **kwargs):
            data = request.get_json(silent=True)
            parsed = {}
            for name, default in fields.items():
                value, err = json_bool(data, name, default=default)
                if err:
                    return {'error': err, 'code': 'INVALID_REQUEST'}, 400
                parsed[name] = value
            request.json_booleans = parsed
            return view(*args, **kwargs)
        return guarded
    return decorator
