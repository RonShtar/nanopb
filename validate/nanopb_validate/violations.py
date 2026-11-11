"""Invalid values: for each rule, a value that breaks exactly
that rule (numbers, strings, bytes, collections, timestamps, Any).
"""

import copy
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple, Union

# Prefer pure-Python protobuf runtime to support loading generated *_pb2
# files built with older protoc versions (avoids descriptor runtime errors).
os.environ.setdefault('PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION', 'python')


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env  # noqa: E402
env.setup()
from schema import (ProtoFieldInfo, ValidationConstraint, ValidationRuleNotViolatableError, _OMIT_FIELD)  # noqa: E402


class ViolationsMixin:
    """Invalid values: for each rule, a value that breaks exactly
    that rule (numbers, strings, bytes, collections, timestamps, Any).

    Part of DataGenerator (datagen.py); uses its attributes through self.
    """

    def _not_violatable(self, field_info: ProtoFieldInfo, rule: str, reason: str) -> ValidationRuleNotViolatableError:
        return ValidationRuleNotViolatableError(
            f"Cannot generate a decodable value violating '{rule}' for field "
            f"'{field_info.name}' of type '{field_info.get_type_name()}': {reason}"
        )

    def _generate_invalid_value(
        self,
        field_info: ProtoFieldInfo,
        constraint: ValidationConstraint,
        active_stack: Tuple[str, ...],
    ) -> Any:
        """Generate an invalid value that violates the given constraint."""

        rule_type = constraint.rule_type
        rule_value = constraint.value

        if rule_type in ('required', 'oneof_required'):
            # The only way to violate presence rules is to omit the field.
            return _OMIT_FIELD

        if rule_type.startswith('items.'):
            return self._generate_invalid_item(field_info, rule_type[len('items.'):], active_stack)

        if field_info.is_repeated() and rule_type in ('min_items', 'max_items', 'unique'):
            return self._generate_invalid_collection(field_info, rule_type, rule_value, active_stack)

        if field_info.is_repeated():
            # A scalar rule written on the repeated field itself applies per entry.
            return self._generate_invalid_item(field_info, rule_type, active_stack)

        if field_info.is_any():
            return self._generate_invalid_any_value(field_info, rule_type, rule_value, active_stack)

        if rule_type in ('gt_now', 'lt_now', 'within'):
            return self._generate_invalid_timestamp(field_info, rule_type, rule_value)

        elements = self._element_constraints(field_info)
        return self._invalid_scalar(field_info, elements, rule_type)

    def _generate_invalid_item(
        self,
        field_info: ProtoFieldInfo,
        rule_type: str,
        active_stack: Tuple[str, ...],
    ) -> Any:
        """A repeated field with one entry that breaks an item rule."""

        elements = self._element_constraints(field_info)
        if rule_type not in elements:
            raise self._not_violatable(field_info, rule_type, "rule is not active on the entries")
        if field_info.is_any():
            bad = self._generate_invalid_any_value(field_info, rule_type, elements[rule_type], active_stack)
        else:
            bad = self._invalid_scalar(field_info, elements, rule_type)
        constraints = field_info.constraint_map()
        low, high = self._count_window(field_info, constraints.get('min_items'), constraints.get('max_items'))
        if high < 1:
            raise self._not_violatable(field_info, rule_type, "the field cannot hold any entry")
        items = self._generate_valid_repeated(field_info, active_stack, count=max(1, low))
        if not items:
            items = [bad]
        else:
            items[self._random.randrange(len(items))] = bad
        return items

    def _generate_invalid_collection(
        self,
        field_info: ProtoFieldInfo,
        rule_type: str,
        rule_value: Any,
        active_stack: Tuple[str, ...],
    ) -> Any:
        """Violate min_items / max_items / unique of a repeated field or map."""

        constraints = field_info.constraint_map()
        capacity = field_info.item_capacity()

        def build(count: int) -> Any:
            if field_info.is_map():
                return self._generate_valid_map(field_info, active_stack, count=count)
            items = self._generate_valid_repeated_unbounded(field_info, active_stack, count)
            return items

        if field_info.fixed_count and capacity is not None:
            raise self._not_violatable(field_info, rule_type, "fixed_count arrays are always full")

        if rule_type == 'min_items':
            if int(rule_value) <= 0:
                raise self._not_violatable(field_info, rule_type, "min_items is 0")
            return build(int(rule_value) - 1)

        if rule_type == 'max_items':
            needed = int(rule_value) + 1
            if capacity is not None and needed > capacity:
                raise self._not_violatable(
                    field_info, rule_type,
                    "max_items %d needs %d entries but (nanopb).max_count is %d" % (rule_value, needed, capacity),
                )
            return build(needed)

        # unique: duplicate one entry.
        count = max(2, constraints.get('min_items', 0))
        if constraints.get('max_items') is not None:
            count = min(count, constraints['max_items'])
        if capacity is not None:
            count = min(count, capacity)
        if count < 2:
            raise self._not_violatable(field_info, rule_type, "needs room for two entries")
        items = build(count)
        if len(items) < 2:
            raise self._not_violatable(field_info, rule_type, "could not build two entries")
        items[1] = copy.deepcopy(items[0])
        return items

    def _generate_valid_repeated_unbounded(
        self,
        field_info: ProtoFieldInfo,
        active_stack: Tuple[str, ...],
        count: int,
    ) -> List[Any]:
        """Generate ``count`` valid entries, ignoring the count rules."""

        elements = self._element_constraints(field_info)
        unique = field_info.constraint_map().get('unique', False)
        items: List[Any] = []
        attempts = 0
        while len(items) < count and attempts < count * 30 + 30:
            attempts += 1
            item = self._generate_valid_element(field_info, elements, active_stack)
            if item is None or (unique and self._contains_equivalent(items, item)):
                continue
            items.append(item)
        return items

    # -- scalar violations -------------------------------------------------

    def _invalid_scalar(self, field_info: ProtoFieldInfo, constraints: Dict[str, Any], rule: str) -> Any:
        """Pick a decodable value that breaks ``rule`` (and ideally only it)."""

        type_name = field_info.get_type_name()
        if type_name in ('message', 'group', 'unknown'):
            raise self._not_violatable(field_info, rule, "rule cannot be violated for this type")
        if rule not in constraints and not (rule == 'defined_only' and type_name == 'enum'):
            raise self._not_violatable(field_info, rule, "rule is not set")
        if type_name in ('string', 'bytes'):
            is_text = type_name == 'string'
            candidates = self._blob_violation_candidates(field_info, constraints, rule, is_text)
            candidates = [v for v in candidates if self._blob_size(v) <= (field_info.capacity() or 10 ** 9)]
            violations = lambda v: self._blob_violations(field_info, constraints, v, is_text)
        elif type_name == 'bool':
            if rule != 'const' or 'const' not in constraints:
                raise self._not_violatable(field_info, rule, "only bool const can be violated")
            return not constraints['const']
        else:
            candidates = self._number_violation_candidates(field_info, constraints, rule)
            violations = lambda v: self._number_violations(field_info, constraints, v)

        unique_candidates = []
        for candidate in candidates:
            if candidate is not None and candidate not in unique_candidates:
                unique_candidates.append(candidate)
        self._random.shuffle(unique_candidates)

        exact = [v for v in unique_candidates if violations(v) == [rule]]
        if exact:
            return exact[0]
        loose = [v for v in unique_candidates if rule in violations(v)]
        if loose:
            return loose[0]
        raise self._not_violatable(
            field_info, rule,
            "every value that breaks it is outside what the nanopb storage can hold",
        )

    def _number_violation_candidates(
        self,
        field_info: ProtoFieldInfo,
        constraints: Dict[str, Any],
        rule: str,
    ) -> List[Any]:
        type_name = field_info.get_type_name()
        if type_name == 'enum':
            defined = self._enum_numbers(field_info)
            seeds = [v for v in constraints.values() if isinstance(v, int) and not isinstance(v, bool)]
            for value in constraints.values():
                if isinstance(value, list):
                    seeds.extend(int(v) for v in value)
            undefined = max(defined + seeds + [0]) + 1
            candidates = (
                [v + d for v in seeds for d in (-1, 0, 1)] + defined +
                [undefined, undefined + 98]
            )
            # pb_decode() reads enum values as unsigned unless the enum itself
            # declares a negative value ("integer too large" otherwise).
            if min(defined) >= 0:
                candidates = [c for c in candidates if c >= 0]
            return candidates

        is_float = type_name in ('float', 'double')
        if is_float:
            single = type_name == 'float'
            cast = self._to_float32 if single else (lambda v: v)
            anchors: List[float] = [0.0, 1.0, -1.0, 1e6, -1e6]
            for value in constraints.values():
                values = value if isinstance(value, list) else [value]
                anchors.extend(float(v) for v in values if not isinstance(v, bool))
            candidates: List[Any] = []
            for anchor in anchors:
                anchor = cast(anchor)
                candidates.extend([
                    anchor, self._float_step(anchor, True, single), self._float_step(anchor, False, single),
                    cast(anchor + 1.0), cast(anchor - 1.0), cast(anchor * 2 + 1), cast(anchor * 0.5 - 1),
                ])
            limit = 3.4028234663852886e38 if single else sys.float_info.max
            candidates = [c for c in candidates if abs(c) <= limit]
            return candidates

        low, high = field_info.integer_bounds()
        anchors_int = [0, 1, -1, low, high]
        for value in constraints.values():
            values = value if isinstance(value, list) else [value]
            anchors_int.extend(int(v) for v in values if not isinstance(v, bool))
        candidates = []
        for anchor in anchors_int:
            for delta in (-100, -10, -2, -1, 0, 1, 2, 10, 100):
                candidates.append(anchor + delta)
        candidates.append(self._random.randint(low, high))
        return [c for c in candidates if low <= c <= high]

    def _blob_violation_candidates(
        self,
        field_info: ProtoFieldInfo,
        constraints: Dict[str, Any],
        rule: str,
        is_text: bool,
    ) -> List[Any]:
        """Values that are likely to break ``rule`` but keep the other rules."""

        def sized(base_constraints: Dict[str, Any]) -> Optional[Any]:
            try:
                if is_text and any(base_constraints.get(k) for k in ('email', 'hostname', 'ip', 'ipv4', 'ipv6')):
                    return self._generate_formatted_string(field_info, base_constraints)
                return self._compose_blob(field_info, base_constraints, is_text)
            except ValueError:
                return None

        without = {k: v for k, v in constraints.items() if k != rule}
        empty: Union[str, bytes] = '' if is_text else b''
        filler: Union[str, bytes] = 'x' if is_text else b'\x7f'
        candidates: List[Any] = []

        def plain(length: int) -> Any:
            return filler * length

        valid_base = sized(without)
        length_free = {k: v for k, v in constraints.items() if k not in ('min_len', 'max_len')}

        def composed(base_constraints: Dict[str, Any], length: int) -> Optional[Any]:
            try:
                return self._compose_blob(field_info, base_constraints, is_text, length)
            except ValueError:
                return None

        def flipped(needle: Any, at_start: bool) -> Any:
            """Same-length text/bytes that differs from ``needle`` at one end."""
            index = 0 if at_start else len(needle) - 1
            if is_text:
                char = '~' if needle[index] != '~' else '^'
                return needle[:index] + char + needle[index + 1:]
            return needle[:index] + bytes([needle[index] ^ 0xFF]) + needle[index + 1:]

        if rule == 'min_len':
            target = int(constraints['min_len']) - 1
            if target >= 0:
                candidates.append(composed(length_free, target))
                candidates.append(plain(target))
                candidates.append(self._fit(valid_base, target, filler))
        elif rule == 'max_len':
            target = int(constraints['max_len']) + 1
            candidates.append(composed(length_free, target))
            candidates.append(plain(target))
            candidates.append(self._fit(valid_base, target, filler))
        elif rule == 'const':
            const = constraints['const']
            candidates.append(const + filler)
            if const:
                if is_text:
                    candidates.append(const[:-1] + ('y' if const[-1] != 'y' else 'z'))
                else:
                    candidates.append(const[:-1] + bytes([(const[-1] + 1) & 0xFF]))
            candidates.append(plain(max(0, len(const) - 1)))
            candidates.append(plain(len(const)))
        elif rule in ('prefix', 'suffix'):
            needle = constraints[rule]
            if needle:
                # Keep every other rule intact by composing with a corrupted affix.
                for _ in range(6):
                    candidates.append(sized(dict(without, **{rule: flipped(needle, rule == 'prefix')})))
            for length in (0, 1, len(needle) - 1):
                if length >= 0:
                    candidates.append(plain(length))
        elif rule == 'contains':
            needle = constraints['contains']
            for _ in range(8):
                candidate = valid_base if _ == 0 else sized(without)
                if candidate is not None and needle:
                    candidate = candidate.replace(needle, flipped(needle, True))
                candidates.append(candidate)
            for length in (0, 1, len(needle) - 1):
                if length >= 0:
                    candidates.append(plain(length))
        elif rule == 'ascii':
            if valid_base is not None and len(valid_base) >= 2:
                chars = list(valid_base)
                pos = self._random.randrange(len(chars) - 1)
                chars[pos:pos + 2] = ['é']      # two UTF-8 bytes, same byte length
                candidates.append(''.join(chars))
            candidates.append('é')
            candidates.append('é' * 2)
        elif rule in ('email', 'hostname', 'ip', 'ipv4', 'ipv6'):
            bad = {
                'email': ['no-at-sign', 'a@@b.c', '@host.com', 'a b@c.d', 'abc', 'a..b@c.d'],
                'hostname': ['-bad_host-', 'a..b', '.a.b', 'bad host', '_', 'a-'],
                'ip': ['999.1.1.1', 'not-an-ip', 'gg::1', '1.2.3', 'x'],
                'ipv4': ['256.1.1.1', '1.2.3', 'a.b.c.d', '1.2.3.4.5', 'x'],
                'ipv6': ['gggg:0:0:0:0:0:0:1', '1:2:3', ':::', '1.2.3.4', 'x'],
            }[rule]
            candidates.extend(bad)
            if valid_base is not None:
                candidates.extend(self._fit(item, self._blob_size(valid_base), 'a') for item in bad)
        elif rule == 'in':
            allowed = list(constraints['in'])
            pool: List[Any] = [filler * n for n in (1, 2, 3, 5, 8)]
            pool += [item + filler for item in allowed] + [item[:-1] for item in allowed if item]
            candidates.extend(pool)
        elif rule == 'not_in':
            candidates.extend(constraints['not_in'])
        return [c for c in candidates if c is not None]

    @staticmethod
    def _fit(value: Optional[Any], length: int, filler: Any) -> Optional[Any]:
        """Truncate or pad ``value`` to exactly ``length`` units."""

        if value is None:
            return None
        if len(value) >= length:
            return value[:length]
        return value + filler * (length - len(value))

    def _generate_invalid_timestamp(self, field_info: ProtoFieldInfo, rule: str, rule_value: Any) -> Dict[str, Any]:
        now = int(time.time())
        if rule == 'gt_now':
            return {'seconds': now - 10 * 86400, 'nanos': 0}
        if rule == 'lt_now':
            return {'seconds': now + 10 * 86400, 'nanos': 0}
        return {'seconds': now + int(rule_value) + 10 * 86400, 'nanos': 0}

    def _generate_invalid_any_value(
        self,
        field_info: ProtoFieldInfo,
        rule_type: str,
        rule_value: Any,
        active_stack: Tuple[str, ...],
    ) -> Dict[str, Any]:
        """Generate an invalid Any value for type allow/deny-list rules."""

        url_limit, _ = self._any_limits()
        placeholder = {'type_url': 'type.googleapis.com/invalid.Payload', 'value': b''}
        if url_limit is not None and len(placeholder['type_url']) > url_limit:
            placeholder['type_url'] = placeholder['type_url'][:url_limit]

        if rule_type == 'in':
            allowed_type_names = {self._extract_type_name(url) for url in rule_value}
            candidates = [
                c for c in self._get_any_candidates(field_info, active_stack, {})
                if c.message_info.full_name not in allowed_type_names
            ]
            self._random.shuffle(candidates)
            for candidate in candidates:
                try:
                    return self._build_any_value(candidate.type_url, candidate.message_info, active_stack)
                except ValueError:
                    continue
            return placeholder

        if rule_type == 'not_in':
            if not rule_value:
                return placeholder
            for disallowed_url in rule_value:
                message_info = self._resolve_any_type_url(disallowed_url)
                if url_limit is not None and len(disallowed_url) > url_limit:
                    continue
                if message_info and message_info.full_name not in active_stack:
                    try:
                        return self._build_any_value(disallowed_url, message_info, active_stack)
                    except ValueError:
                        pass
                return {'type_url': disallowed_url, 'value': b''}
            raise self._not_violatable(field_info, rule_type, "no forbidden type_url fits Any.type_url")

        raise ValidationRuleNotViolatableError(
            f"Cannot generate an Any value violating '{rule_type}' for field "
            f"'{field_info.name}'"
        )
