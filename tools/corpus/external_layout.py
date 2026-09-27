from __future__ import annotations

from types import MappingProxyType
from typing import Mapping


EXTERNAL_KIND_FILES: Mapping[str, str] = MappingProxyType(
    {
        "service_matcher": "services.jsonl",
        "active_probe": "services.jsonl",
        "os_fingerprint": "os.jsonl",
        "udp_probe": "udp.jsonl",
        "web_fingerprint": "web.jsonl",
        "device_fingerprint": "devices.jsonl",
        "port_registry": "registry.jsonl",
        "product_record": "products.jsonl",
        "product_alias": "products.jsonl",
        "product_vocab": "products.jsonl",
        "registry": "products.jsonl",
        "cpe_record": "cpe.jsonl",
    }
)

EXTERNAL_STORE_FILES = tuple(sorted(set(EXTERNAL_KIND_FILES.values())))
