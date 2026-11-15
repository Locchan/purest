from purest.config import get_config


def _inherit_endp_flags(wrapper, wrapped):
    if getattr(wrapped, "_purest_websocket", False) or getattr(wrapped, "_lrd_websocket", False):
        wrapper._purest_websocket = True
        wrapper._lrd_websocket = True  # LoRaD registration still checks this name


###
#    Preferred decorator order
#    - @auth
#    - @feat_req
#    - @validate
#    - @api_endp          # REST
#    - @websocket         # instead of api_endp: impl_GET(headers, ws)
###

# Decorators above @api_endp should return {"rc": ..., "data": ...}
# (optional "content-type"). Below @api_endp, return whatever.


def feat_req(feat_needed):
    def decorator(func):
        def wrp(*args, **kwargs):
            cfg = get_config()
            checker = cfg.feature_enabled
            if checker is None:
                return {
                    "rc": 405,
                    "data": {"error": f"{feat_needed} feature is not enabled. Enable it in order to use this endpoint."},
                }
            if isinstance(feat_needed, str):
                if checker(feat_needed):
                    return func(*args, **kwargs)
            elif isinstance(feat_needed, list):
                for afeature in feat_needed:
                    if checker(afeature):
                        return func(*args, **kwargs)
            return {
                "rc": 405,
                "data": {"error": f"{feat_needed} feature is not enabled. Enable it in order to use this endpoint."},
            }

        _inherit_endp_flags(wrp, func)
        return wrp

    return decorator


def api_endp(func):
    def wrp(*args, **kwargs):
        logger = get_config().logger
        try:
            result = func(*args, **kwargs)
            if isinstance(result, tuple):
                return {"rc": result[0], "data": result[1]}
            elif isinstance(result, dict):
                if "rc" in result:
                    return result
                else:
                    return {"rc": 200, "data": result}
            elif isinstance(result, str):
                return {"rc": 200, "data": result}
            elif isinstance(result, (bytes, bytearray)):
                return {"rc": 200, "data": bytes(result), "content-type": "application/octet-stream"}
            else:
                return {"rc": 500, "data": {"error": "Incorrect output from the endpoint function."}}
        except Exception as e:
            logger.exception(e)
            return {"rc": 500, "data": {"error": f"Error ({e.__class__.__name__}). Details are in the server log."}}

    return wrp


def validate(validate_func):
    def decorator(func):
        def wrp(*args, **kwargs):
            validate_error = validate_func(*args, **kwargs)
            if isinstance(validate_error, dict):
                if "rc" in validate_error:
                    return validate_error
            if validate_error is not None:
                return {"rc": 400, "data": {"error": validate_error}}
            else:
                return func(*args, **kwargs)

        _inherit_endp_flags(wrp, func)
        return wrp

    return decorator


def auth(cap_required):
    def decorator(func):
        def wrp(*args, **kwargs):
            backend = get_config().auth_backend
            if backend is None:
                return {"rc": 500, "data": {"error": "Auth backend is not configured."}}
            headers = dict(args[0]._headers)
            if "Authorization" in headers:
                auth_split = headers["Authorization"].split(",")
                if len(auth_split) != 2:
                    return {"rc": 400, "data": {"error": "Incorrect 'Authorization' header."}}
                username = auth_split[0].strip()
                token = auth_split[1].strip()
                if backend.validate_token(username, token):
                    if backend.check_capability(username, cap_required):
                        return func(*args, **kwargs)
                    else:
                        return {"rc": 403, "data": {"error": "Insufficient permissions"}}
                else:
                    return {"rc": 401, "data": {"error": "Unauthorized"}}
            else:
                return {"rc": 401, "data": {"error": "Unauthorized"}}

        _inherit_endp_flags(wrp, func)
        return wrp

    return decorator


def websocket(func):
    """Upgrade GET to a WebSocket. Use instead of @api_endp.

    impl_GET(headers, ws): ws is a purest.websocket.WebSocket.
    Auth/feature wrappers still run as HTTP before the 101 handshake.
    """

    def wrp_ws(headers, ws=None, *args, **kwargs):
        if ws is None:
            return {"rc": 101, "websocket": True}
        logger = get_config().logger
        try:
            func(headers, ws, *args, **kwargs)
        except Exception as e:
            logger.exception(e)
        finally:
            try:
                if ws.open:
                    ws.close()
            except Exception:
                pass
        return {"rc": 101, "websocket": True, "done": True}

    wrp_ws._purest_websocket = True
    wrp_ws._lrd_websocket = True
    return wrp_ws
