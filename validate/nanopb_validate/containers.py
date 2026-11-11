"""Valid values for repeated fields, maps and google.protobuf.Any
(type_url candidates and payloads).
"""

import os
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Prefer pure-Python protobuf runtime to support loading generated *_pb2
# files built with older protoc versions (avoids descriptor runtime errors).
os.environ.setdefault('PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION', 'python')


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env  # noqa: E402
env.setup()
from schema import (AnyCandidate, MessageInfo, ProtoFieldInfo)  # noqa: E402


class ContainersMixin:
    """Valid values for repeated fields, maps and google.protobuf.Any
    (type_url candidates and payloads).

    Part of DataGenerator (datagen.py); uses its attributes through self.
    """

    def _count_window(
        self,
        field_info: ProtoFieldInfo,
        min_items: Optional[int],
        max_items: Optional[int],
    ) -> Tuple[int, int]:
        """Number of entries allowed by the rules and by (nanopb).max_count."""

        capacity = field_info.item_capacity()
        if field_info.fixed_count and capacity is not None:
            # A fixed_count array has no length field: it is always full.
            return capacity, capacity
        low = 1 if min_items is None else min_items
        high = 5 if max_items is None else max_items
        if max_items is not None and min_items is None:
            low = min(low, high)
        if capacity is not None:
            if low > capacity:
                raise ValueError(
                    "Field '%s' requires at least %d items but nanopb only allocates room "
                    "for %d; the generated data could never be decoded. Raise "
                    "(nanopb).max_count or lower the min_items rule."
                    % (field_info.name, low, capacity)
                )
            high = min(high, capacity)
        if low > high:
            raise ValueError(
                "Field '%s': min_items %d exceeds max_items %d" % (field_info.name, low, high)
            )
        return low, high

    def _generate_valid_repeated(
        self,
        field_info: ProtoFieldInfo,
        active_stack: Tuple[str, ...],
        count: Optional[int] = None,
    ) -> List[Any]:
        """Generate a valid repeated field value."""

        constraints = field_info.constraint_map()
        low, high = self._count_window(
            field_info, constraints.get('min_items'), constraints.get('max_items')
        )
        enforce_minimum = count is None
        if count is None:
            roll = self._random.random()
            count = low if roll < 0.15 else high if roll < 0.3 else self._random.randint(low, high)
        elements = self._element_constraints(field_info)
        unique = constraints.get('unique', False)

        items: List[Any] = []
        attempts = 0
        max_attempts = max(count * 30, 30)
        while len(items) < count and attempts < max_attempts:
            attempts += 1
            item = self._generate_valid_element(field_info, elements, active_stack)
            if item is None:
                break
            if unique and self._contains_equivalent(items, item):
                continue
            items.append(item)

        if enforce_minimum and len(items) < low and field_info.get_type_name() != 'message':
            raise ValueError(
                "Field '%s': could only generate %d distinct items but min_items is %d "
                "(rules %s)" % (field_info.name, len(items), low, sorted(elements))
            )
        return items

    def _generate_valid_map(
        self,
        field_info: ProtoFieldInfo,
        active_stack: Tuple[str, ...],
        count: Optional[int] = None,
    ) -> Dict[Any, Any]:
        """Generate a valid map<key, value> field as a dict."""

        constraints = field_info.constraint_map()
        low, high = self._count_window(
            field_info, constraints.get('min_items'), constraints.get('max_items')
        )
        enforce_minimum = count is None
        if count is None:
            count = self._random.randint(low, high)
        entry = self.registry.resolve_message(field_info.map_entry)
        key_info, value_info = entry.fields['key'], entry.fields['value']
        # map.keys / map.values rules are declared on the map field.
        key_constraints = key_info.constraint_map()
        key_constraints.update({c.rule_type: c.value for c in field_info.map_key_constraints})
        value_constraints = value_info.constraint_map()
        value_constraints.update({c.rule_type: c.value for c in field_info.map_value_constraints})

        pairs: Dict[Any, Any] = {}
        attempts = 0
        while len(pairs) < count and attempts < count * 30 + 30:
            attempts += 1
            key = self._generate_valid_element(key_info, key_constraints, active_stack)
            value = self._generate_valid_element(value_info, value_constraints, active_stack)
            if key is None or value is None or key in pairs:
                continue
            pairs[key] = value
        if enforce_minimum and len(pairs) < low:
            raise ValueError(
                "Field '%s': could only generate %d distinct map keys, min_pairs is %d"
                % (field_info.name, len(pairs), low)
            )
        return pairs

    @staticmethod
    def _contains_equivalent(items: Sequence[Any], candidate: Any) -> bool:
        """Check whether a candidate already exists in a list."""

        for item in items:
            if item == candidate:
                return True
        return False

    # -- google.protobuf.Any ------------------------------------------------

    def _any_limits(self) -> Tuple[Optional[int], Optional[int]]:
        """(type_url, value) capacity of the nanopb Any struct, if bounded."""

        any_info = self.registry.messages_by_full_name.get('google.protobuf.Any')
        if any_info is None:
            return None, None
        url_field = any_info.fields.get('type_url')
        value_field = any_info.fields.get('value')
        return (
            url_field.capacity() if url_field else None,
            value_field.capacity() if value_field else None,
        )

    def _build_any_value(self, type_url: str, message_info: MessageInfo,
                         active_stack: Tuple[str, ...]) -> Dict[str, Any]:
        """Generate a payload for ``message_info`` that fits Any.type_url/value."""

        url_limit, value_limit = self._any_limits()
        if url_limit is not None and len(type_url) > url_limit:
            raise ValueError(
                "type_url %r needs %d bytes but Any.type_url only holds %d; set a larger "
                "google.protobuf.Any.type_url max_size." % (type_url, len(type_url), url_limit)
            )
        last_error: Optional[ValueError] = None
        for _ in range(8):
            try:
                payload_data = self._generate_message(
                    message_info.full_name,
                    active_stack + (message_info.full_name,),
                )
                payload_bytes = self._build_message_from_data(
                    message_info.full_name, payload_data
                ).SerializeToString()
            except ValueError as exc:
                last_error = exc
                continue
            if value_limit is not None and len(payload_bytes) > value_limit:
                last_error = ValueError(
                    "Payload %s needs %d bytes but Any.value only holds %d"
                    % (message_info.full_name, len(payload_bytes), value_limit)
                )
                continue
            return {'type_url': type_url, 'value': payload_bytes}
        raise last_error if last_error else ValueError("Cannot generate Any payload")

    def _generate_valid_any(
        self,
        field_info: ProtoFieldInfo,
        constraints: Dict[str, Any],
        active_stack: Tuple[str, ...],
    ) -> Dict[str, Any]:
        """Generate a valid google.protobuf.Any payload."""

        candidates = self._get_any_candidates(field_info, active_stack, constraints)
        if not candidates:
            raise ValueError(f"No suitable concrete message found for Any field {field_info.name}")

        remaining = list(candidates)
        while remaining:
            candidate = remaining.pop(self._random.randrange(len(remaining)))
            try:
                return self._build_any_value(candidate.type_url, candidate.message_info, active_stack)
            except ValueError:
                continue

        raise ValueError(
            f"No suitable concrete message found for Any field {field_info.name} "
            "(no candidate fits the Any storage)"
        )

    def _get_any_candidates(
        self,
        field_info: ProtoFieldInfo,
        active_stack: Tuple[str, ...],
        constraints: Optional[Dict[str, Any]] = None,
    ) -> List[AnyCandidate]:
        """Resolve valid Any payload candidates."""

        if constraints is None:
            constraints = self._element_constraints(field_info)
        allowed_urls = list(constraints.get('in') or [])
        disallowed_urls = list(constraints.get('not_in') or [])
        disallowed_type_names = {self._extract_type_name(url) for url in disallowed_urls}

        candidates: List[AnyCandidate] = []
        if allowed_urls:
            for type_url in allowed_urls:
                message_info = self._resolve_any_type_url(type_url)
                if not message_info:
                    continue
                if message_info.full_name in active_stack:
                    continue
                if not self._is_any_candidate_message(message_info):
                    continue
                candidates.append(AnyCandidate(message_info=message_info, type_url=type_url))
            return candidates

        for message_info in self.registry.iter_messages():
            if not self._is_any_candidate_message(message_info):
                continue
            if message_info.full_name in active_stack:
                continue
            if message_info.full_name in disallowed_type_names:
                continue
            type_url = self._canonical_type_url(message_info.full_name)
            if type_url in disallowed_urls:
                continue
            candidates.append(AnyCandidate(message_info=message_info, type_url=type_url))

        return candidates

    def _is_any_candidate_message(self, message_info: MessageInfo) -> bool:
        """Check whether a message is a suitable Any payload candidate."""

        if message_info.descriptor_proto.options.map_entry:
            return False
        if message_info.full_name == 'google.protobuf.Any':
            return False
        if message_info.file_descriptor.name in self._SYSTEM_ANY_EXCLUDED_FILES:
            return False
        return True

    def _resolve_any_type_url(self, type_url: str) -> Optional[MessageInfo]:
        """Resolve a type_url to a concrete message."""

        type_name = self._extract_type_name(type_url)
        try:
            return self.registry.resolve_message(type_name)
        except ValueError:
            return None

    @staticmethod
    def _extract_type_name(type_url: str) -> str:
        """Extract the fully qualified protobuf type name from a type URL."""

        return str(type_url).rsplit('/', 1)[-1].lstrip('.')

    @staticmethod
    def _canonical_type_url(full_name: str) -> str:
        """Build the canonical type_url for a message."""

        return f"type.googleapis.com/{full_name.lstrip('.')}"

    # ------------------------------------------------------------------
    # Invalid data
    # ------------------------------------------------------------------
