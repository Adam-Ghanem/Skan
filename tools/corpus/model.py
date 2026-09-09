from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import re
from typing import Any, Mapping
import unicodedata

from tools.corpus.sources import SourcePolicy


SCHEMA_VERSION = 2
_ID = re.compile(r"^skan-db-v2-[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_GENERAL_TEXT_BYTES = 4096
_SHORT_TEXT_BYTES = 128
_REGEX_BYTES = 512
_PATTERN_BYTES = 4096
_BINARY_PATTERN_BYTES = 3000
_ACTIVE_PAYLOAD_BYTES = 4000
_UDP_PAYLOAD_BYTES = 512
_MAX_PORTS = 256
_MAX_FALLBACKS = 16
_MAX_CPE = 64
_MAX_SIGNATURES = 64
_MAX_PROVENANCE = 32
_IMMUTABLE_REVISION = re.compile(
    r"^(?:git:[0-9a-f]{40}|rfc:[1-9][0-9]*|version:[A-Za-z0-9][A-Za-z0-9._+-]{0,127})$"
)
_RUNTIME_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,127}$")
_PROBE_NAME = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

_RECORD_FIELDS = {
    "schema_version",
    "id",
    "kind",
    "body",
    "provenance",
    "first_imported_revision",
    "last_verified_revision",
    "status",
    "notes",
}
_PROVENANCE_FIELDS = {
    "source_id",
    "source_record_id",
    "source_revision",
    "source_url",
    "source_license",
    "snapshot_hash",
    "record_hash",
}
_SERVICE_FIELDS = {
    "probe_name",
    "matcher_type",
    "pattern",
    "pattern_hex",
    "strength",
    "service",
    "product",
    "version_template",
    "extra",
    "hostname_template",
    "tunnel",
    "confidence",
    "rule_order",
    "cpe",
}
_ACTIVE_FIELDS = {
    "probe_name",
    "transport",
    "payload_hex",
    "rarity",
    "priority",
    "timeout_ms",
    "ports",
    "fallback_probe_names",
    "declaration_order",
}
_UDP_FIELDS = {
    "name",
    "destination_port",
    "protocol_hint",
    "max_response_bytes",
    "payload_hex",
    "declaration_order",
}
_OS_FIELDS = {
    "runtime_id",
    "name",
    "vendor",
    "os_family",
    "os_generation",
    "device_type",
    "address_family",
    "specificity",
    "signatures",
}
_SIGNATURE_FIELDS = {"field", "operator", "value"}
_KINDS = {"active_probe", "service_matcher", "os_fingerprint", "udp_probe"}
_STATUSES = {"verified", "imported", "experimental", "suppressed", "deprecated"}
_MATCHER_TYPES = {"exact", "prefix", "suffix", "substring", "regex"}
_MATCH_STRENGTHS = {"hard", "soft"}
_TRANSPORTS = {"tcp", "udp"}

_SIGNATURE_COMPATIBILITY = {
    "ttl": {"eq", "range"},
    "dont_fragment": {"bool"},
    "window": {"eq", "range"},
    "mss": {"eq"},
    "window_scale": {"eq"},
    "sack_permitted": {"bool"},
    "timestamps": {"bool"},
    "tcp_options": {"tcp_options"},
    "tcp_flags": {"eq"},
    "ack_behavior": {"text"},
    "sequence_behavior": {"text"},
    "response_behavior": {"text"},
    "icmp_ttl": {"eq", "range"},
    "icmp_type": {"eq"},
    "icmp_code": {"eq"},
    "udp_payload_length": {"eq", "range"},
    "udp_response_behavior": {"text"},
    "response_presence": {"bool"},
}
_NUMERIC_SIGNATURE_BOUNDS = {
    "ttl": (0, 255),
    "window": (0, 65535),
    "mss": (0, 65535),
    "window_scale": (0, 255),
    "tcp_flags": (0, 255),
    "icmp_ttl": (0, 255),
    "icmp_type": (0, 255),
    "icmp_code": (0, 255),
    "udp_payload_length": (0, 65535),
}
_BEHAVIOR_VALUES = {
    "ack_behavior": {
        "NO_ACK",
        "ACKNOWLEDGES_SYN",
        "ACKNOWLEDGES_PAYLOAD",
        "RST_WITHOUT_ACK",
    },
    "sequence_behavior": {"ZERO", "INCREMENTAL", "RANDOMIZED", "TIME_BASED"},
    "response_behavior": {
        "SYN_ACK",
        "RST",
        "ECHO_REPLY",
        "UDP_RESPONSE",
        "PORT_UNREACHABLE",
        "NO_RESPONSE",
        "MALFORMED",
    },
    "udp_response_behavior": {
        "UDP_RESPONSE",
        "PORT_UNREACHABLE",
        "NO_RESPONSE",
        "MALFORMED",
    },
}


class CanonicalRecordError(ValueError):
    """A canonical corpus record violated schema or source policy."""


@dataclass(frozen=True)
class Provenance:
    source_id: str
    source_record_id: str
    source_revision: str
    source_url: str
    source_license: str
    snapshot_hash: str | None
    record_hash: str


@dataclass(frozen=True)
class ServiceMatcherSemantics:
    probe_name: str
    matcher_type: str
    pattern: str | None
    pattern_hex: str | None
    strength: str
    service: str
    product: str | None
    version_template: str | None
    extra: str | None
    hostname_template: str | None
    tunnel: str | None
    confidence: float
    rule_order: int
    cpe: tuple[str, ...]


@dataclass(frozen=True)
class ActiveProbeSemantics:
    probe_name: str
    transport: str
    payload_hex: str
    rarity: int
    priority: int
    timeout_ms: int | None
    ports: tuple[int, ...]
    fallback_probe_names: tuple[str, ...]
    declaration_order: int


@dataclass(frozen=True)
class UDPProbeSemantics:
    name: str
    destination_port: int
    protocol_hint: str
    max_response_bytes: int
    payload_hex: str
    declaration_order: int


SignatureValue = int | bool | str | tuple[int, int] | tuple[str, ...]


@dataclass(frozen=True)
class OSSignature:
    field: str
    operator: str
    value: SignatureValue


@dataclass(frozen=True)
class OSFingerprintSemantics:
    runtime_id: str
    name: str
    vendor: str
    os_family: str
    os_generation: str
    device_type: str
    address_family: str
    specificity: int
    signatures: tuple[OSSignature, ...]


RecordBody = (
    ServiceMatcherSemantics
    | ActiveProbeSemantics
    | UDPProbeSemantics
    | OSFingerprintSemantics
)


@dataclass(frozen=True)
class CanonicalRecord:
    schema_version: int
    id: str
    kind: str
    body: RecordBody
    provenance: tuple[Provenance, ...]
    first_imported_revision: str
    last_verified_revision: str
    status: str
    notes: str


def _exact_fields(value: Mapping[str, Any], expected: set[str], context: str) -> None:
    unknown = sorted(set(value) - expected)
    if unknown:
        raise CanonicalRecordError(f"{context}: unknown fields: {', '.join(unknown)}")
    missing = sorted(expected - set(value))
    if missing:
        raise CanonicalRecordError(f"{context}: missing fields: {', '.join(missing)}")


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CanonicalRecordError(f"{context} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise CanonicalRecordError(f"{context} keys must be strings")
    return value


def _checked_text(
    value: Any,
    field: str,
    *,
    maximum_bytes: int = _GENERAL_TEXT_BYTES,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        requirement = "a string" if allow_empty else "a non-empty string"
        raise CanonicalRecordError(f"{field} must be {requirement}")
    if unicodedata.normalize("NFC", value) != value:
        raise CanonicalRecordError(f"{field} must be NFC-normalized")
    if any(unicodedata.category(character) == "Cs" for character in value):
        raise CanonicalRecordError(f"{field} contains a surrogate code point")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise CanonicalRecordError(f"{field} contains unsafe control characters")
    if len(value.encode("utf-8")) > maximum_bytes:
        raise CanonicalRecordError(f"{field} exceeds {maximum_bytes} bytes")
    return value


def _text(
    value: Mapping[str, Any],
    key: str,
    context: str,
    *,
    maximum_bytes: int = _GENERAL_TEXT_BYTES,
    allow_empty: bool = False,
) -> str:
    return _checked_text(
        value.get(key),
        f"{context}.{key}",
        maximum_bytes=maximum_bytes,
        allow_empty=allow_empty,
    )


def _optional_text(
    value: Mapping[str, Any],
    key: str,
    context: str,
    *,
    maximum_bytes: int = _GENERAL_TEXT_BYTES,
) -> str | None:
    item = value.get(key)
    if item is None:
        return None
    return _checked_text(item, f"{context}.{key}", maximum_bytes=maximum_bytes)


def _integer(
    value: Mapping[str, Any],
    key: str,
    context: str,
    minimum: int,
    maximum: int,
) -> int:
    item = value.get(key)
    if type(item) is not int or not minimum <= item <= maximum:
        raise CanonicalRecordError(
            f"{context}.{key} must be an integer in range {minimum}..{maximum}"
        )
    return item


def _optional_integer(
    value: Mapping[str, Any],
    key: str,
    context: str,
    minimum: int,
    maximum: int,
) -> int | None:
    if value.get(key) is None:
        return None
    return _integer(value, key, context, minimum, maximum)


def _runtime_token(value: Any, field: str) -> str:
    token = _checked_text(value, field, maximum_bytes=_SHORT_TEXT_BYTES)
    if _RUNTIME_TOKEN.fullmatch(token) is None:
        raise CanonicalRecordError(f"{field} must be a runtime token")
    return token


def _probe_name(value: Any, field: str) -> str:
    name = _checked_text(value, field, maximum_bytes=_SHORT_TEXT_BYTES)
    if _PROBE_NAME.fullmatch(name) is None:
        raise CanonicalRecordError(
            f"{field}: fallback probe name is not runtime-compatible"
        )
    return name


def _runtime_line_text(
    value: Any,
    field: str,
    *,
    allow_empty: bool,
    class_component: bool = False,
) -> str:
    text = _checked_text(
        value,
        field,
        maximum_bytes=_SHORT_TEXT_BYTES,
        allow_empty=allow_empty,
    )
    if text != text.strip():
        raise CanonicalRecordError(f"{field} must not have edge whitespace")
    delimiters = "#|" if class_component else "#"
    if any(delimiter in text for delimiter in delimiters):
        raise CanonicalRecordError(f"{field} contains a runtime delimiter")
    return text


def _immutable_revision(value: Mapping[str, Any], key: str, context: str) -> str:
    revision = _text(value, key, context, maximum_bytes=256)
    if _IMMUTABLE_REVISION.fullmatch(revision) is None:
        raise CanonicalRecordError(
            f"{key} must identify an immutable revision"
        )
    return revision


def _string_list(
    value: Mapping[str, Any],
    key: str,
    context: str,
    maximum_count: int,
    *,
    maximum_text_bytes: int = _SHORT_TEXT_BYTES,
    sort_values: bool = False,
) -> tuple[str, ...]:
    item = value.get(key)
    if not isinstance(item, list):
        raise CanonicalRecordError(f"{context}.{key} must be an array")
    if len(item) > maximum_count:
        raise CanonicalRecordError(f"{key} exceeds {maximum_count} entries")
    result = tuple(
        _checked_text(
            entry,
            f"{context}.{key}[{index}]",
            maximum_bytes=maximum_text_bytes,
        )
        for index, entry in enumerate(item)
    )
    if len(result) != len(set(result)):
        raise CanonicalRecordError(f"{key} contains duplicates")
    return tuple(sorted(result)) if sort_values else result


def _ports(value: Mapping[str, Any], key: str, context: str) -> tuple[int, ...]:
    item = value.get(key)
    if not isinstance(item, list):
        raise CanonicalRecordError(f"{context}.{key} must be an array")
    if len(item) > _MAX_PORTS:
        raise CanonicalRecordError(f"{key} exceeds {_MAX_PORTS} entries")
    if any(type(port) is not int or not 1 <= port <= 65535 for port in item):
        raise CanonicalRecordError(f"{key} must contain integers in range 1..65535")
    result = tuple(item)
    if len(result) != len(set(result)):
        raise CanonicalRecordError(f"{key} contains duplicates")
    return tuple(sorted(result))


def _hex_payload(
    value: Mapping[str, Any],
    key: str,
    context: str,
    maximum_bytes: int,
    *,
    allow_empty: bool,
) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise CanonicalRecordError(f"{context}.{key} must be lowercase hexadecimal")
    if (not allow_empty and not item) or len(item) % 2 or re.fullmatch(r"[0-9a-f]*", item) is None:
        raise CanonicalRecordError(f"{context}.{key} must be lowercase even-length hexadecimal")
    if len(item) // 2 > maximum_bytes:
        raise CanonicalRecordError(f"{context}.{key} exceeds {maximum_bytes} decoded bytes")
    return item


def _parse_service(value: Any) -> ServiceMatcherSemantics:
    context = "service_matcher body"
    body = _mapping(value, context)
    _exact_fields(body, _SERVICE_FIELDS, context)
    matcher_type = _text(body, "matcher_type", context, maximum_bytes=16)
    if matcher_type not in _MATCHER_TYPES:
        raise CanonicalRecordError(f"{context}.matcher_type is unsupported")
    pattern: str | None
    pattern_hex: str | None
    if matcher_type == "regex":
        pattern = _text(body, "pattern", context, maximum_bytes=_REGEX_BYTES)
        if body.get("pattern_hex") is not None:
            raise CanonicalRecordError(f"{context}: regex matchers cannot use pattern_hex")
        pattern_hex = None
    else:
        raw_pattern = body.get("pattern")
        raw_pattern_hex = body.get("pattern_hex")
        if (raw_pattern is None) == (raw_pattern_hex is None):
            raise CanonicalRecordError(
                f"{context}: exactly one of pattern or pattern_hex is required"
            )
        if raw_pattern is not None:
            pattern = None
            pattern_hex = _checked_text(
                raw_pattern,
                f"{context}.pattern",
                maximum_bytes=_BINARY_PATTERN_BYTES,
            ).encode("utf-8").hex()
        else:
            pattern = None
            pattern_hex = _hex_payload(
                body,
                "pattern_hex",
                context,
                _BINARY_PATTERN_BYTES,
                allow_empty=False,
            )
    strength = _text(body, "strength", context, maximum_bytes=16)
    if strength not in _MATCH_STRENGTHS:
        raise CanonicalRecordError(f"{context}.strength is unsupported")
    confidence = body.get("confidence")
    if (
        type(confidence) not in (int, float)
        or not math.isfinite(float(confidence))
        or not 0.0 <= float(confidence) <= 1.0
    ):
        raise CanonicalRecordError(f"{context}.confidence must be finite and within 0.0..1.0")
    return ServiceMatcherSemantics(
        probe_name=_probe_name(body.get("probe_name"), f"{context}.probe_name"),
        matcher_type=matcher_type,
        pattern=pattern,
        pattern_hex=pattern_hex,
        strength=strength,
        service=_text(body, "service", context, maximum_bytes=_SHORT_TEXT_BYTES),
        product=_optional_text(body, "product", context, maximum_bytes=_SHORT_TEXT_BYTES),
        version_template=_optional_text(
            body, "version_template", context, maximum_bytes=_SHORT_TEXT_BYTES
        ),
        extra=_optional_text(body, "extra", context, maximum_bytes=_SHORT_TEXT_BYTES),
        hostname_template=_optional_text(
            body, "hostname_template", context, maximum_bytes=_SHORT_TEXT_BYTES
        ),
        tunnel=_optional_text(body, "tunnel", context, maximum_bytes=_SHORT_TEXT_BYTES),
        confidence=float(confidence),
        rule_order=_integer(body, "rule_order", context, 0, 65535),
        cpe=_string_list(
            body,
            "cpe",
            context,
            _MAX_CPE,
            maximum_text_bytes=256,
            sort_values=True,
        ),
    )


def _parse_active(value: Any) -> ActiveProbeSemantics:
    context = "active_probe body"
    body = _mapping(value, context)
    _exact_fields(body, _ACTIVE_FIELDS, context)
    transport = _text(body, "transport", context, maximum_bytes=8)
    if transport not in _TRANSPORTS:
        raise CanonicalRecordError(f"{context}.transport is unsupported")
    return ActiveProbeSemantics(
        probe_name=_probe_name(body.get("probe_name"), f"{context}.probe_name"),
        transport=transport,
        payload_hex=_hex_payload(
            body,
            "payload_hex",
            context,
            _ACTIVE_PAYLOAD_BYTES,
            allow_empty=True,
        ),
        rarity=_integer(body, "rarity", context, 1, (1 << 32) - 1),
        priority=_integer(body, "priority", context, 1, 100),
        timeout_ms=_optional_integer(body, "timeout_ms", context, 1, 60000),
        ports=_ports(body, "ports", context),
        fallback_probe_names=tuple(
            _probe_name(name, f"{context}.fallback_probe_names[{index}]")
            for index, name in enumerate(
                _string_list(body, "fallback_probe_names", context, _MAX_FALLBACKS)
            )
        ),
        declaration_order=_integer(body, "declaration_order", context, 0, 65535),
    )


def _parse_udp(value: Any) -> UDPProbeSemantics:
    context = "udp_probe body"
    body = _mapping(value, context)
    _exact_fields(body, _UDP_FIELDS, context)
    name = _runtime_token(body.get("name"), f"{context}.name")
    destination_port = _integer(body, "destination_port", context, 0, 65535)
    if (destination_port == 0) != (name == "DEFAULT"):
        raise CanonicalRecordError(f"{context}: port 0 is reserved for DEFAULT")
    return UDPProbeSemantics(
        name=name,
        destination_port=destination_port,
        protocol_hint=_runtime_token(
            body.get("protocol_hint"), f"{context}.protocol_hint"
        ),
        max_response_bytes=_integer(
            body, "max_response_bytes", context, 1, 1 << 20
        ),
        payload_hex=_hex_payload(
            body,
            "payload_hex",
            context,
            _UDP_PAYLOAD_BYTES,
            allow_empty=False,
        ),
        declaration_order=_integer(body, "declaration_order", context, 0, 65535),
    )


def _signature_number(field: str, value: Any, context: str) -> int:
    bounds = _NUMERIC_SIGNATURE_BOUNDS.get(field)
    if bounds is None or type(value) is not int or not bounds[0] <= value <= bounds[1]:
        raise CanonicalRecordError(f"{context}.value is outside the field domain")
    return value


def _parse_signature(value: Any, index: int) -> OSSignature:
    context = f"os_fingerprint body.signatures[{index}]"
    item = _mapping(value, context)
    _exact_fields(item, _SIGNATURE_FIELDS, context)
    field = _text(item, "field", context, maximum_bytes=32)
    operator = _text(item, "operator", context, maximum_bytes=16)
    if field not in _SIGNATURE_COMPATIBILITY:
        raise CanonicalRecordError(f"{context}.field is unsupported")
    if operator not in _SIGNATURE_COMPATIBILITY[field]:
        raise CanonicalRecordError(f"{context}: operator is incompatible with field")

    raw_value = item.get("value")
    parsed_value: SignatureValue
    if operator == "eq":
        parsed_value = _signature_number(field, raw_value, context)
    elif operator == "range":
        if not isinstance(raw_value, list) or len(raw_value) != 2:
            raise CanonicalRecordError(f"{context}.value must contain a two-value range")
        minimum = _signature_number(field, raw_value[0], context)
        maximum = _signature_number(field, raw_value[1], context)
        if minimum > maximum:
            raise CanonicalRecordError("signature minimum must not exceed maximum")
        parsed_value = (minimum, maximum)
    elif operator == "bool":
        if type(raw_value) is not bool:
            raise CanonicalRecordError(f"{context}.value must be boolean")
        parsed_value = raw_value
    elif operator == "text":
        parsed_value = _runtime_line_text(
            raw_value,
            f"{context}.value",
            allow_empty=False,
        )
        allowed_values = _BEHAVIOR_VALUES[field]
        if parsed_value not in allowed_values:
            raise CanonicalRecordError(
                f"{context}.value is not a recognized runtime behavior"
            )
    else:
        if not isinstance(raw_value, list) or not 1 <= len(raw_value) <= 16:
            raise CanonicalRecordError(
                f"{context}.value must contain 1..16 TCP options"
            )
        allowed_options = {"NOP", "MSS", "WS", "SACK", "TS"}
        options = tuple(
            _checked_text(
                option,
                f"{context}.value[{option_index}]",
                maximum_bytes=32,
            )
            for option_index, option in enumerate(raw_value)
        )
        if any(option not in allowed_options for option in options):
            raise CanonicalRecordError(f"{context}.value contains unsupported TCP options")
        parsed_value = options
    return OSSignature(field=field, operator=operator, value=parsed_value)


def _parse_os(value: Any) -> OSFingerprintSemantics:
    context = "os_fingerprint body"
    body = _mapping(value, context)
    _exact_fields(body, _OS_FIELDS, context)
    raw_signatures = body.get("signatures")
    if not isinstance(raw_signatures, list) or not 1 <= len(raw_signatures) <= _MAX_SIGNATURES:
        raise CanonicalRecordError(
            f"{context}.signatures must contain 1..{_MAX_SIGNATURES} entries"
        )
    signatures = tuple(
        _parse_signature(signature, index)
        for index, signature in enumerate(raw_signatures)
    )
    fields = tuple(signature.field for signature in signatures)
    if len(fields) != len(set(fields)):
        raise CanonicalRecordError(f"{context}.signatures contains duplicate fields")
    address_family = _text(body, "address_family", context, maximum_bytes=8)
    if address_family not in {"ipv4", "ipv6"}:
        raise CanonicalRecordError(f"{context}.address_family is unsupported")
    if address_family == "ipv6" and "dont_fragment" in fields:
        raise CanonicalRecordError(f"{context}: IPv6 fingerprints cannot contain dont_fragment")
    os_generation = _runtime_line_text(
        body.get("os_generation"),
        f"{context}.os_generation",
        allow_empty=True,
        class_component=True,
    )
    device_type = _runtime_line_text(
        body.get("device_type"),
        f"{context}.device_type",
        allow_empty=True,
        class_component=True,
    )
    if device_type and not os_generation:
        raise CanonicalRecordError(f"{context}: device_type requires os_generation")
    return OSFingerprintSemantics(
        runtime_id=_runtime_line_text(
            body.get("runtime_id"), f"{context}.runtime_id", allow_empty=False
        ),
        name=_runtime_line_text(
            body.get("name"), f"{context}.name", allow_empty=False
        ),
        vendor=_runtime_line_text(
            body.get("vendor"),
            f"{context}.vendor",
            allow_empty=False,
            class_component=True,
        ),
        os_family=_runtime_line_text(
            body.get("os_family"),
            f"{context}.os_family",
            allow_empty=False,
            class_component=True,
        ),
        os_generation=os_generation,
        device_type=device_type,
        address_family=address_family,
        specificity=_integer(body, "specificity", context, 1, 65535),
        signatures=tuple(sorted(signatures, key=lambda signature: signature.field)),
    )


def _parse_body(kind: str, value: Any) -> RecordBody:
    if kind == "service_matcher":
        return _parse_service(value)
    if kind == "active_probe":
        return _parse_active(value)
    if kind == "udp_probe":
        return _parse_udp(value)
    if kind == "os_fingerprint":
        return _parse_os(value)
    raise CanonicalRecordError(f"unsupported kind: {kind}")


def _body_mapping(body: RecordBody) -> dict[str, Any]:
    if isinstance(body, ServiceMatcherSemantics):
        return {
            "probe_name": body.probe_name,
            "matcher_type": body.matcher_type,
            "pattern": body.pattern,
            "pattern_hex": body.pattern_hex,
            "strength": body.strength,
            "service": body.service,
            "product": body.product,
            "version_template": body.version_template,
            "extra": body.extra,
            "hostname_template": body.hostname_template,
            "tunnel": body.tunnel,
            "confidence": body.confidence,
            "rule_order": body.rule_order,
            "cpe": list(body.cpe),
        }
    if isinstance(body, ActiveProbeSemantics):
        return {
            "probe_name": body.probe_name,
            "transport": body.transport,
            "payload_hex": body.payload_hex,
            "rarity": body.rarity,
            "priority": body.priority,
            "timeout_ms": body.timeout_ms,
            "ports": list(body.ports),
            "fallback_probe_names": list(body.fallback_probe_names),
            "declaration_order": body.declaration_order,
        }
    if isinstance(body, UDPProbeSemantics):
        return {
            "name": body.name,
            "destination_port": body.destination_port,
            "protocol_hint": body.protocol_hint,
            "max_response_bytes": body.max_response_bytes,
            "payload_hex": body.payload_hex,
            "declaration_order": body.declaration_order,
        }
    return {
        "runtime_id": body.runtime_id,
        "name": body.name,
        "vendor": body.vendor,
        "os_family": body.os_family,
        "os_generation": body.os_generation,
        "device_type": body.device_type,
        "address_family": body.address_family,
        "specificity": body.specificity,
        "signatures": [
            {
                "field": signature.field,
                "operator": signature.operator,
                "value": list(signature.value)
                if isinstance(signature.value, tuple)
                else signature.value,
            }
            for signature in body.signatures
        ],
    }


def stable_record_id(value: CanonicalRecord | Mapping[str, Any]) -> str:
    if isinstance(value, CanonicalRecord):
        schema_version = value.schema_version
        kind = value.kind
        body = value.body
    else:
        schema_version = value.get("schema_version")
        kind = value.get("kind")
        if type(schema_version) is not int or schema_version != SCHEMA_VERSION:
            raise CanonicalRecordError(f"schema_version must be {SCHEMA_VERSION}")
        if not isinstance(kind, str) or kind not in _KINDS:
            raise CanonicalRecordError(f"unsupported kind: {kind}")
        body = _parse_body(kind, value.get("body"))
    payload = {
        "schema_version": schema_version,
        "kind": kind,
        "body": _body_mapping(body),
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "skan-db-v2-" + hashlib.sha256(encoded).hexdigest()


def record_to_mapping(record: CanonicalRecord) -> dict[str, Any]:
    return {
        "schema_version": record.schema_version,
        "id": record.id,
        "kind": record.kind,
        "body": _body_mapping(record.body),
        "provenance": [
            {
                "source_id": item.source_id,
                "source_record_id": item.source_record_id,
                "source_revision": item.source_revision,
                "source_url": item.source_url,
                "source_license": item.source_license,
                "snapshot_hash": item.snapshot_hash,
                "record_hash": item.record_hash,
            }
            for item in record.provenance
        ],
        "first_imported_revision": record.first_imported_revision,
        "last_verified_revision": record.last_verified_revision,
        "status": record.status,
        "notes": record.notes,
    }


def _parse_provenance(
    value: Any,
    index: int,
    kind: str,
    sources: Mapping[str, SourcePolicy],
) -> Provenance:
    context = f"provenance[{index}]"
    item = _mapping(value, context)
    _exact_fields(item, _PROVENANCE_FIELDS, context)
    source_id = _text(item, "source_id", context, maximum_bytes=64)
    policy = sources.get(source_id)
    if policy is None:
        raise CanonicalRecordError(f"{context}: unknown source_id: {source_id}")
    if not policy.redistribution_allowed:
        raise CanonicalRecordError(
            f"{context}: source does not permit redistribution"
        )
    if kind not in policy.approved_data_classes or kind in policy.blocked_data_classes:
        raise CanonicalRecordError(f"{context}: source is not authorized for kind: {kind}")

    source_revision = _text(item, "source_revision", context, maximum_bytes=256)
    if source_revision != policy.pinned_revision:
        raise CanonicalRecordError(f"{context}: source_revision does not match manifest")
    source_url = _text(item, "source_url", context)
    if source_url != policy.source_url:
        raise CanonicalRecordError(f"{context}: source_url does not match manifest")
    source_license = _text(item, "source_license", context, maximum_bytes=128)
    if source_license != policy.license_spdx_or_policy:
        raise CanonicalRecordError(f"{context}: source_license does not match manifest")

    snapshot_hash = item.get("snapshot_hash")
    if snapshot_hash is not None:
        snapshot_hash = _checked_text(
            snapshot_hash, f"{context}.snapshot_hash", maximum_bytes=71
        )
        if _SHA256.fullmatch(snapshot_hash) is None:
            raise CanonicalRecordError(f"{context}.snapshot_hash must be sha256")
    if snapshot_hash != policy.expected_hash:
        raise CanonicalRecordError(f"{context}: snapshot_hash does not match manifest")

    record_hash = _text(item, "record_hash", context, maximum_bytes=71)
    if _SHA256.fullmatch(record_hash) is None:
        raise CanonicalRecordError(f"{context}.record_hash must be sha256")
    return Provenance(
        source_id=source_id,
        source_record_id=_text(
            item, "source_record_id", context, maximum_bytes=256
        ),
        source_revision=source_revision,
        source_url=source_url,
        source_license=source_license,
        snapshot_hash=snapshot_hash,
        record_hash=record_hash,
    )


def parse_record(
    value: Mapping[str, Any],
    sources: Mapping[str, SourcePolicy],
) -> CanonicalRecord:
    record = _mapping(value, "record")
    _exact_fields(record, _RECORD_FIELDS, "record")
    schema_version = record.get("schema_version")
    if type(schema_version) is not int or schema_version != SCHEMA_VERSION:
        raise CanonicalRecordError(f"schema_version must be {SCHEMA_VERSION}")
    kind = _text(record, "kind", "record", maximum_bytes=32)
    if kind not in _KINDS:
        raise CanonicalRecordError(f"unsupported kind: {kind}")
    record_id = record.get("id")
    if not isinstance(record_id, str) or not record_id:
        raise CanonicalRecordError("id is required")
    if _ID.fullmatch(record_id) is None:
        raise CanonicalRecordError("id must be skan-db-v2-<64 lowercase hex chars>")
    body = _parse_body(kind, record.get("body"))

    raw_provenance = record.get("provenance")
    if not isinstance(raw_provenance, list) or not 1 <= len(raw_provenance) <= _MAX_PROVENANCE:
        raise CanonicalRecordError(
            f"provenance must contain 1..{_MAX_PROVENANCE} entries"
        )
    provenance = tuple(
        _parse_provenance(item, index, kind, sources)
        for index, item in enumerate(raw_provenance)
    )
    identities = tuple((item.source_id, item.source_record_id) for item in provenance)
    if len(identities) != len(set(identities)):
        raise CanonicalRecordError("provenance contains duplicate source contributions")

    status = _text(record, "status", "record", maximum_bytes=32)
    if status not in _STATUSES:
        raise CanonicalRecordError(f"unsupported status: {status}")
    result = CanonicalRecord(
        schema_version=schema_version,
        id=record_id,
        kind=kind,
        body=body,
        provenance=provenance,
        first_imported_revision=_immutable_revision(
            record, "first_imported_revision", "record"
        ),
        last_verified_revision=_immutable_revision(
            record, "last_verified_revision", "record"
        ),
        status=status,
        notes=_text(record, "notes", "record", allow_empty=True),
    )
    expected_id = stable_record_id(result)
    if record_id != expected_id:
        raise CanonicalRecordError(
            f"id does not match semantic fingerprint: expected {expected_id}"
        )
    return result
