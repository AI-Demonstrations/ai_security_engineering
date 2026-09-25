"""Minimal JSON Schema checker — standard library only.

Covers the keywords a message contract usually needs: type, const, enum, required,
properties, additionalProperties: false, minimum/maximum, minLength, pattern.
For full JSON Schema support use the `jsonschema` package; the harness only needs a list
of violations per message.
"""

import re

TYPES = {"object": dict, "string": str, "boolean": bool, "array": list}


def _type_ok(value, t):
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    return isinstance(value, TYPES[t])


def validate(value, schema, path="$"):
    """Return a list of human-readable violations (empty list = valid)."""
    errs = []
    if "type" in schema and not _type_ok(value, schema["type"]):
        return [f"{path}: expected {schema['type']}, got {type(value).__name__}"]
    if "const" in schema and value != schema["const"]:
        errs.append(f"{path}: must equal {schema['const']!r}, got {value!r}")
    if "enum" in schema and value not in schema["enum"]:
        errs.append(f"{path}: {value!r} not one of {schema['enum']}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errs.append(f"{path}: {value} < minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errs.append(f"{path}: {value} > maximum {schema['maximum']}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errs.append(f"{path}: shorter than {schema['minLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errs.append(f"{path}: {value!r} does not match {schema['pattern']}")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                errs.append(f"{path}: missing required field '{key}'")
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in props:
                    errs.append(f"{path}: unexpected field '{key}'")
        for key, sub in props.items():
            if key in value:
                errs += validate(value[key], sub, f"{path}.{key}")
    return errs
