from purest.config import get_config


def generate_swagger_path(anendpoint):
    path_item = {}

    for method in ["get", "post", "put", "delete"]:
        impl_name = f"impl_{method.upper()}"
        if hasattr(anendpoint, impl_name):
            parameters = []

            if hasattr(anendpoint, "REQUIRED_FIELDS") and method.upper() in anendpoint.REQUIRED_FIELDS:
                for field in anendpoint.REQUIRED_FIELDS[method.upper()]:
                    parameters.append({
                        "name": field,
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string"},
                    })

            if hasattr(anendpoint, "OPTIONAL_FIELDS") and method.upper() in anendpoint.OPTIONAL_FIELDS:
                for field in anendpoint.OPTIONAL_FIELDS[method.upper()]:
                    parameters.append({
                        "name": field,
                        "in": "query",
                        "required": False,
                        "schema": {"type": "string"},
                    })

            operation = {
                "summary": anendpoint.DOCSTRING.get(method.upper(), ""),
                "parameters": parameters,
                "responses": {
                    "200": {
                        "description": "Successful response"
                    }
                },
            }

            if getattr(anendpoint, "LOGIN_REQUIRED", False):
                operation["security"] = [{"AuthHeader": []}]

            path_item[method] = operation

    return {anendpoint.ENDP_PATH: path_item}


def generate_full_openapi_spec(endpoint_modules, title=None, version=None):
    cfg = get_config()
    paths = {}
    for endpoint in endpoint_modules:
        paths.update(generate_swagger_path(endpoint))

    return {
        "openapi": "3.0.0",
        "info": {
            "title": title if title is not None else cfg.openapi_title,
            "version": version if version is not None else cfg.openapi_version,
        },
        "paths": paths,
        "components": {
            "securitySchemes": {
                "AuthHeader": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "Authorization",
                    "description": "Format: `username, token`",
                }
            }
        },
    }
