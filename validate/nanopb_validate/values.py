"""Valid values: messages and oneofs, numbers, enums, strings,
bytes and formatted strings (email, hostname, IP), within validate rules and nanopb storage limits.
"""

import math
import os
import re
import struct
import sys
import time
import string
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

# Prefer pure-Python protobuf runtime to support loading generated *_pb2
# files built with older protoc versions (avoids descriptor runtime errors).
os.environ.setdefault('PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION', 'python')


sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env  # noqa: E402
env.setup()
from schema import (MessageInfo, ProtoFieldInfo, _INTEGER_TYPES)  # noqa: E402


class ValuesMixin:
    """Valid values: messages and oneofs, numbers, enums, strings,
    bytes and formatted strings (email, hostname, IP), within validate rules and nanopb storage limits.

    Part of DataGenerator (datagen.py); uses its attributes through self.
    """

    _REPEATED_ONLY_RULES = ('min_items', 'max_items', 'unique', 'required', 'oneof_required')

    def _generate_message(
        self,
        message_full_name: str,
        active_stack: Tuple[str, ...],
    ) -> Dict[str, Any]:
        """Generate a valid data dictionary for a message descriptor."""

        well_known = self._generate_well_known(message_full_name, {})
        if well_known is not None:
            return well_known

        message_info = self.registry.resolve_message(message_full_name)
        data: Dict[str, Any] = {}

        # A oneof carries exactly one member.  Generating all members would
        # make the dictionary disagree with the encoded message, where only the
        # last assigned member survives.
        oneof_groups: Dict[int, List[ProtoFieldInfo]] = {}
        for field_info in message_info.fields.values():
            if field_info.oneof_index is not None:
                oneof_groups.setdefault(field_info.oneof_index, []).append(field_info)

        for field_info in message_info.fields.values():
            if field_info.oneof_index is not None or field_info.storage == 'ignore':
                continue
            value = self._generate_valid_value(field_info, active_stack)
            if value is not None:
                data[field_info.name] = value

        for members in oneof_groups.values():
            self._generate_oneof(members, active_stack, data)

        self._apply_message_rules(message_info, data, active_stack)
        return data

    def _generate_oneof(
        self,
        members: List[ProtoFieldInfo],
        active_stack: Tuple[str, ...],
        data: Dict[str, Any],
    ) -> None:
        """Select and generate one member of a oneof."""

        order = list(members)
        self._random.shuffle(order)
        # oneof_required: the marked arm must be the selected one.
        required = [member for member in order if 'oneof_required' in member.constraint_map()]
        order = required + [member for member in order if member not in required]

        last_error: Optional[ValueError] = None
        left_unset = False
        for member in order:
            if member.storage == 'ignore':
                continue
            try:
                value = self._generate_valid_value(member, active_stack)
            except ValueError as exc:
                last_error = exc
                continue
            if value is None:
                left_unset = True      # recursive message member: nothing to generate
                continue
            data[member.name] = value
            return
        if last_error is not None and not left_unset:
            raise last_error

    def _apply_message_rules(
        self,
        message_info: MessageInfo,
        data: Dict[str, Any],
        active_stack: Tuple[str, ...],
    ) -> None:
        """Make generated data satisfy validate.message (requires/mutex/at_least)."""

        if not (message_info.requires or message_info.mutex or message_info.at_least):
            return

        protected = set(message_info.requires)
        for _, names in message_info.at_least:
            protected.update(names)
        for group in message_info.mutex:
            present = [name for name in group if name in data]
            if len(present) > 1:
                keep = [name for name in present if name in protected] or present
                survivor = self._random.choice(keep)
                for name in present:
                    if name != survivor:
                        data.pop(name, None)

        def ensure(name: str) -> bool:
            if name in data:
                return True
            field_info = message_info.fields.get(name)
            if field_info is None:
                return False
            value = self._generate_valid_value(field_info, active_stack)
            if value is None:
                return False
            self._drop_oneof_siblings(message_info, field_info, data)
            data[name] = value
            return True

        for name in message_info.requires:
            ensure(name)

        for count, names in message_info.at_least:
            present = [name for name in names if name in data]
            for name in names:
                if len(present) >= count:
                    break
                if name in present:
                    continue
                blocked = any(
                    name in group and any(other in data for other in group if other != name)
                    for group in message_info.mutex
                )
                if not blocked and ensure(name):
                    present.append(name)

    def _generate_valid_value(
        self,
        field_info: ProtoFieldInfo,
        active_stack: Tuple[str, ...],
    ) -> Any:
        """Generate a valid value for a field (a list or dict for repeated/map)."""

        if field_info.is_map():
            return self._generate_valid_map(field_info, active_stack)
        if field_info.is_repeated():
            return self._generate_valid_repeated(field_info, active_stack)
        return self._generate_valid_element(
            field_info, self._element_constraints(field_info), active_stack
        )

    def _element_constraints(self, field_info: ProtoFieldInfo) -> Dict[str, Any]:
        """Rules that apply to one value of a field (or to each repeated entry)."""

        constraints = {
            rule: value for rule, value in field_info.constraint_map().items()
            if rule not in self._REPEATED_ONLY_RULES
        }
        if field_info.is_repeated():
            constraints.update(field_info.item_constraint_map())
        return constraints

    def _generate_valid_element(
        self,
        field_info: ProtoFieldInfo,
        constraints: Dict[str, Any],
        active_stack: Tuple[str, ...],
    ) -> Any:
        """Generate one valid value of the field's scalar/enum/message type."""

        type_name = field_info.get_type_name()
        if type_name in _INTEGER_TYPES:
            return self._generate_valid_integer(field_info, constraints)
        if type_name in ('float', 'double'):
            return self._generate_valid_float(field_info, constraints)
        if type_name == 'bool':
            if 'const' in constraints:
                return bool(constraints['const'])
            return self._random.choice([True, False])
        if type_name == 'enum':
            return self._generate_valid_enum(field_info, constraints)
        if type_name == 'string':
            return self._generate_valid_string(field_info, constraints)
        if type_name == 'bytes':
            return self._generate_valid_bytes(field_info, constraints)
        if type_name == 'message':
            return self._generate_valid_message_field(field_info, constraints, active_stack)
        return None

    def _generate_valid_message_field(
        self,
        field_info: ProtoFieldInfo,
        constraints: Dict[str, Any],
        active_stack: Tuple[str, ...],
    ) -> Any:
        """Generate a valid nested message, Any or well-known type field."""

        if field_info.is_any():
            return self._generate_valid_any(field_info, constraints, active_stack)

        full_name = field_info.full_type_name()
        if not full_name:
            return None
        well_known = self._generate_well_known(full_name, constraints)
        if well_known is not None:
            return well_known
        if full_name in active_stack or len(active_stack) >= self.MAX_MESSAGE_DEPTH:
            return None
        return self._generate_message(full_name, active_stack + (full_name,))

    def _generate_well_known(self, full_name: str, constraints: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Generate Timestamp / Duration values that are semantically valid."""

        if full_name == 'google.protobuf.Timestamp':
            now = int(time.time())
            if constraints.get('gt_now'):
                seconds = now + self._random.randint(10 * 86400, 3650 * 86400)
            elif constraints.get('lt_now'):
                seconds = now - self._random.randint(86400, 3650 * 86400)
            elif 'within' in constraints:
                window = max(int(constraints['within']) // 2, 0)
                seconds = now + self._random.randint(-window, window) // 2
            else:
                seconds = self._random.randint(0, 253402300799)
            return {'seconds': seconds, 'nanos': self._random.randint(0, 999999999)}
        if full_name == 'google.protobuf.Duration':
            seconds = self._random.randint(-315576000000, 315576000000)
            nanos = self._random.randint(0, 999999999)
            return {'seconds': seconds, 'nanos': -nanos if seconds < 0 else nanos}
        return None

    # -- numbers -------------------------------------------------------

    def _int_range(self, field_info: ProtoFieldInfo, constraints: Dict[str, Any]) -> Tuple[int, int]:
        """Inclusive range allowed by the storage type and the gt/gte/lt/lte rules."""

        low, high = field_info.integer_bounds()
        if 'gte' in constraints:
            low = max(low, int(constraints['gte']))
        if 'gt' in constraints:
            low = max(low, int(constraints['gt']) + 1)
        if 'lte' in constraints:
            high = min(high, int(constraints['lte']))
        if 'lt' in constraints:
            high = min(high, int(constraints['lt']) - 1)
        return low, high

    def _sample_int(self, low: int, high: int) -> int:
        """Pick an integer, favouring boundaries and values near zero."""

        roll = self._random.random()
        if roll < 0.12:
            return low
        if roll < 0.24:
            return high
        if roll < 0.40 and high - low > 2000:
            near_low, near_high = max(low, -1000), min(high, 1000)
            if near_low <= near_high:
                return self._random.randint(near_low, near_high)
        return self._random.randint(low, high)

    def _generate_valid_integer(self, field_info: ProtoFieldInfo, constraints: Dict[str, Any]) -> int:
        low, high = self._int_range(field_info, constraints)
        forbidden = {int(value) for value in constraints.get('not_in', [])}

        def unsatisfiable() -> ValueError:
            return ValueError(
                "No valid %s value for field '%s': rules %s leave nothing in the range "
                "[%d, %d] that the nanopb storage can hold (check int_size)."
                % (field_info.get_type_name(), field_info.name, constraints, low, high)
            )

        if 'const' in constraints:
            value = int(constraints['const'])
            if not low <= value <= high or value in forbidden:
                raise unsatisfiable()
            return value
        if 'in' in constraints:
            pool = [int(v) for v in constraints['in'] if low <= int(v) <= high and int(v) not in forbidden]
            if not pool:
                raise unsatisfiable()
            return self._random.choice(pool)
        if low > high:
            raise unsatisfiable()
        if high - low < 512:
            pool = [v for v in range(low, high + 1) if v not in forbidden]
            if not pool:
                raise unsatisfiable()
            return self._random.choice(pool)
        for _ in range(100):
            value = self._sample_int(low, high)
            if value not in forbidden:
                return value
        raise unsatisfiable()

    @staticmethod
    def _to_float32(value: float) -> float:
        try:
            return struct.unpack('<f', struct.pack('<f', value))[0]
        except OverflowError:
            return math.copysign(math.inf, value)

    @staticmethod
    def _float_step(value: float, up: bool, single: bool) -> float:
        """Next representable float32/float64 above or below ``value``."""

        float_format, int_format = ('<f', '<I') if single else ('<d', '<Q')
        if math.isnan(value) or value == (math.inf if up else -math.inf):
            return value
        if value == 0:
            tiny = struct.unpack(float_format, struct.pack(int_format, 1))[0]
            return tiny if up else -tiny
        bits = struct.unpack(int_format, struct.pack(float_format, value))[0]
        bits += 1 if (value > 0) == up else -1
        return struct.unpack(float_format, struct.pack(int_format, bits))[0]

    def _generate_valid_float(self, field_info: ProtoFieldInfo, constraints: Dict[str, Any]) -> float:
        single = field_info.get_type_name() == 'float'
        cast = self._to_float32 if single else (lambda value: value)
        limit = 3.4028234663852886e38 if single else sys.float_info.max
        step = lambda value, up: self._float_step(value, up, single)

        low, high = -limit, limit
        if 'gte' in constraints:
            low = max(low, float(constraints['gte']))
        if 'gt' in constraints:
            low = max(low, step(float(constraints['gt']), True))
        if 'lte' in constraints:
            high = min(high, float(constraints['lte']))
        if 'lt' in constraints:
            high = min(high, step(float(constraints['lt']), False))
        forbidden = {cast(float(value)) for value in constraints.get('not_in', [])}

        def unsatisfiable() -> ValueError:
            return ValueError(
                "No valid %s value for field '%s': rules %s leave an empty range [%r, %r]."
                % (field_info.get_type_name(), field_info.name, constraints, low, high)
            )

        if 'const' in constraints:
            value = cast(float(constraints['const']))
            if not low <= value <= high or value in forbidden:
                raise unsatisfiable()
            return value
        if 'in' in constraints:
            pool = [cast(float(v)) for v in constraints['in']]
            pool = [v for v in pool if low <= v <= high and v not in forbidden]
            if not pool:
                raise unsatisfiable()
            return self._random.choice(pool)
        if low > high:
            raise unsatisfiable()

        # Sample a window that is wide enough to be interesting but never
        # overflows: (high - low) can exceed the largest finite double.
        explicit_low = 'gte' in constraints or 'gt' in constraints
        explicit_high = 'lte' in constraints or 'lt' in constraints
        span = 1e6
        if not explicit_low and not explicit_high:
            window_low, window_high = -span, span
        elif explicit_low and not explicit_high:
            window_low, window_high = low, min(limit, low + max(span, abs(low)))
        elif explicit_high and not explicit_low:
            window_low, window_high = max(-limit, high - max(span, abs(high))), high
        else:
            window_low, window_high = low, high
        window_low, window_high = max(window_low, low), min(window_high, high)

        for _ in range(100):
            roll = self._random.random()
            if roll < 0.08 and explicit_low:
                value = low
            elif roll < 0.16 and explicit_high:
                value = high
            else:
                fraction = self._random.random()
                value = window_low * (1.0 - fraction) + window_high * fraction
            value = cast(value)
            value = min(max(value, low), high)
            if value not in forbidden and not math.isinf(value):
                return value
        raise unsatisfiable()

    def _generate_valid_enum(self, field_info: ProtoFieldInfo, constraints: Dict[str, Any]) -> int:
        """Generate a valid enum value."""

        forbidden = {int(value) for value in constraints.get('not_in', [])}
        if 'const' in constraints:
            return int(constraints['const'])
        if 'in' in constraints:
            pool = [int(v) for v in constraints['in'] if int(v) not in forbidden]
            if not pool:
                raise ValueError(f"No usable enum values for field {field_info.name}")
            return self._random.choice(pool)

        runtime_descriptor = self.registry.pool.FindEnumTypeByName(field_info.full_type_name())
        values = [value.number for value in runtime_descriptor.values if value.number not in forbidden]
        if not values:
            raise ValueError(f"No usable enum values for field {field_info.name}")
        return self._random.choice(values)

    # -- strings and bytes ----------------------------------------------

    _TEXT_ALPHABET = string.ascii_letters + string.digits
    _TEXT_PUNCTUATION = '-_.:/@+= '

    def _length_window(
        self,
        field_info: ProtoFieldInfo,
        constraints: Dict[str, Any],
        required_bytes: int,
    ) -> Tuple[int, int, bool]:
        """Return (min, max, explicit_max) length for a string/bytes value.

        The window honours min_len/max_len and the nanopb buffer size.  A bytes
        field with (nanopb).fixed_length must be exactly max_size bytes long.
        """

        capacity = field_info.capacity()
        low = int(constraints.get('min_len', 0))
        high = constraints.get('max_len')
        high = int(high) if high is not None else None
        explicit_max = high is not None or capacity is not None
        if capacity is not None:
            high = capacity if high is None else min(high, capacity)
        if 'min_len' not in constraints and required_bytes == 0:
            # Prefer non-empty values unless the buffer cannot hold any byte.
            low = 1 if high is None else min(1, high)
        if field_info.fixed_length and capacity is not None and field_info.get_type_name() == 'bytes':
            # fixed_length bytes arrays are always exactly max_size long.
            low, high = capacity, capacity
        low = max(low, required_bytes)
        if high is None:
            high = max(low + 12, 20)
        if low > high:
            raise ValueError(
                "Field '%s' needs at least %d bytes to satisfy %s but nanopb/validate "
                "limit it to %d; the generated data could never be decoded and valid. "
                "Raise (nanopb).max_size/max_length or relax the rules."
                % (field_info.name, low, sorted(constraints), high)
            )
        return low, high, explicit_max

    def _pick_length(self, low: int, high: int, explicit_max: bool) -> int:
        roll = self._random.random()
        if roll < 0.15:
            return low
        if roll < 0.30 and explicit_max and high <= 4096:
            return high
        return self._random.randint(low, min(high, max(low + 24, 32)))

    def _compose_blob(
        self,
        field_info: ProtoFieldInfo,
        constraints: Dict[str, Any],
        is_text: bool,
        length: Optional[int] = None,
    ) -> Union[str, bytes]:
        """Build a string/bytes value from prefix/suffix/contains and filler."""

        empty: Union[str, bytes] = '' if is_text else b''
        prefix = constraints.get('prefix', empty)
        suffix = constraints.get('suffix', empty)
        contains = constraints.get('contains', empty)

        def size(value: Union[str, bytes]) -> int:
            return len(value.encode('utf-8')) if isinstance(value, str) else len(value)

        needs_contains = bool(contains) and contains not in prefix and contains not in suffix
        fixed = size(prefix) + size(suffix) + (size(contains) if needs_contains else 0)
        low, high, explicit_max = self._length_window(field_info, constraints, fixed)
        if length is None:
            length = self._pick_length(low, high, explicit_max)
        filler_len = length - fixed
        if filler_len < 0:
            raise ValueError(
                "Field '%s': %d bytes cannot hold the prefix/suffix/contains rules (%d bytes)"
                % (field_info.name, length, fixed)
            )

        if is_text:
            alphabet = self._TEXT_ALPHABET
            if not constraints.get('ascii'):
                alphabet += self._TEXT_PUNCTUATION
            filler: Union[str, bytes] = ''.join(self._random.choice(alphabet) for _ in range(filler_len))
        else:
            filler = bytes(self._random.randrange(256) for _ in range(filler_len))

        if needs_contains:
            cut = self._random.randint(0, len(filler))
            filler = filler[:cut] + contains + filler[cut:]
        return prefix + filler + suffix

    def _capacity_filter(self, field_info: ProtoFieldInfo, values: Sequence[Any]) -> List[Any]:
        capacity = field_info.capacity()
        if capacity is None:
            return list(values)
        return [v for v in values if self._blob_size(v) <= capacity]

    @staticmethod
    def _blob_size(value: Union[str, bytes]) -> int:
        return len(value.encode('utf-8')) if isinstance(value, str) else len(value)

    def _generate_valid_blob(
        self,
        field_info: ProtoFieldInfo,
        constraints: Dict[str, Any],
        is_text: bool,
    ) -> Union[str, bytes]:
        forbidden = list(constraints.get('not_in', []))

        if 'const' in constraints:
            value = constraints['const']
            if value in self._capacity_filter(field_info, [value]):
                return value
            raise ValueError(
                "Field '%s' has a 'const' rule needing %d bytes but nanopb only allocates "
                "room for %s; the generated data could never be decoded. Raise "
                "(nanopb).max_size/max_length." % (field_info.name, self._blob_size(value), field_info.capacity())
            )
        if 'in' in constraints:
            pool = [v for v in self._capacity_filter(field_info, constraints['in']) if v not in forbidden]
            if not pool:
                raise ValueError(
                    "Field '%s': no value of its 'in' rule fits the nanopb buffer (%s bytes)."
                    % (field_info.name, field_info.capacity())
                )
            return self._random.choice(pool)

        for _ in range(50):
            if is_text and any(constraints.get(kind) for kind in ('email', 'hostname', 'ip', 'ipv4', 'ipv6')):
                value = self._generate_formatted_string(field_info, constraints)
            else:
                value = self._compose_blob(field_info, constraints, is_text)
            if value in forbidden:
                continue
            problems = self._blob_violations(field_info, constraints, value, is_text)
            if problems:
                raise ValueError(
                    "Cannot satisfy %s for field '%s' together: generated %r"
                    % (sorted(problems), field_info.name, value)
                )
            self._check_storage_limits(field_info, value)
            return value
        raise ValueError(f"Could not generate a value for field '{field_info.name}' avoiding not_in")

    def _generate_valid_string(self, field_info: ProtoFieldInfo, constraints: Dict[str, Any]) -> str:
        return self._generate_valid_blob(field_info, constraints, True)

    def _generate_valid_bytes(self, field_info: ProtoFieldInfo, constraints: Dict[str, Any]) -> bytes:
        return self._generate_valid_blob(field_info, constraints, False)

    @staticmethod
    def _check_storage_limits(field_info: ProtoFieldInfo, value: Any) -> None:
        """Fail loudly when a generated value cannot fit the nanopb storage."""

        capacity = field_info.capacity()
        if capacity is None or value is None:
            return
        encoded_len = len(value.encode('utf-8')) if isinstance(value, str) else len(value)
        if encoded_len > capacity:
            raise ValueError(
                "Generated value for field '%s' needs %d bytes but nanopb only "
                "allocates room for %d; pb_decode() would fail with an overflow. "
                "Raise (nanopb).max_size/max_length or tighten the validate rules."
                % (field_info.name, encoded_len, capacity)
            )

    # -- formatted strings (email, hostname, ip) -------------------------

    def _generate_formatted_string(self, field_info: ProtoFieldInfo, constraints: Dict[str, Any]) -> str:
        """Generate an email / hostname / IP address that fits the length window."""

        kinds = [kind for kind in ('email', 'hostname', 'ipv4', 'ipv6', 'ip') if constraints.get(kind)]
        kind = kinds[0]
        # Smallest and largest possible rendering of each format.
        format_ranges = {
            'hostname': (1, 253), 'email': (3, 253),
            'ipv4': (7, 15), 'ipv6': (15, 39), 'ip': (7, 39),
        }
        format_low, format_high = format_ranges[kind]
        low, high, explicit_max = self._length_window(field_info, constraints, format_low)
        high = min(high, format_high)
        if low > high:
            raise ValueError(
                "Field '%s' requires a %s of %d..%d characters but its length rules and "
                "nanopb buffer allow only %d..%d." % (field_info.name, kind, format_low, format_high, low, high)
            )
        length = self._pick_length(low, high, explicit_max)
        if kind == 'ip':
            if length <= 14:
                kind = 'ipv4'
            elif length == 15:
                kind = self._random.choice(['ipv4', 'ipv6'])
            else:
                kind = 'ipv6'
        builders = {
            'email': self._make_email, 'hostname': self._make_hostname,
            'ipv4': self._make_ipv4, 'ipv6': self._make_ipv6,
        }
        return builders[kind](length)

    def _split_total(self, total: int, parts: int, low: int, high: int) -> List[int]:
        """Randomly split ``total`` into ``parts`` integers within [low, high]."""

        sizes = [low] * parts
        remaining = total - low * parts
        while remaining > 0:
            index = self._random.randrange(parts)
            if sizes[index] < high:
                sizes[index] += 1
                remaining -= 1
        return sizes

    def _make_hostname(self, length: int) -> str:
        # k labels need k..63k characters plus k-1 dots.
        max_labels = (length + 1) // 2
        min_labels = max(1, math.ceil((length + 1) / 64))
        labels = self._random.randint(min_labels, max(min_labels, min(max_labels, 4)))
        sizes = self._split_total(length - (labels - 1), labels, 1, 63)
        alnum = string.ascii_lowercase + string.digits
        parts = []
        for size_ in sizes:
            chars = [self._random.choice(alnum) for _ in range(size_)]
            for index in range(1, size_ - 1):
                if self._random.random() < 0.15:
                    chars[index] = '-'
            parts.append(''.join(chars))
        return '.'.join(parts)

    def _make_email(self, length: int) -> str:
        local_len = self._random.randint(1, min(32, length - 2))
        host_len = length - 1 - local_len
        alnum = string.ascii_lowercase + string.digits
        local = [self._random.choice(alnum + '_-') for _ in range(local_len)]
        if local_len >= 3 and self._random.random() < 0.5:
            local[self._random.randint(1, local_len - 2)] = '.'
        return ''.join(local) + '@' + self._make_hostname(host_len)

    def _make_ipv4(self, length: int) -> str:
        digits = self._split_total(length - 3, 4, 1, 3)
        octets = []
        for count in digits:
            low = 0 if count == 1 else 10 ** (count - 1)
            high = min(255, 10 ** count - 1)
            octets.append(str(self._random.randint(low, high)))
        return '.'.join(octets)

    def _make_ipv6(self, length: int) -> str:
        sizes = self._split_total(length - 7, 8, 1, 4)
        return ':'.join(
            ''.join(self._random.choice('0123456789abcdef') for _ in range(size_))
            for size_ in sizes
        )

    # -- rule predicates -------------------------------------------------

    _HOSTNAME_RE = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$')
    _IPV4_RE = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')

    @classmethod
    def _is_hostname(cls, value: str) -> bool:
        return 0 < len(value) <= 253 and bool(cls._HOSTNAME_RE.match(value))

    @classmethod
    def _is_email(cls, value: str) -> bool:
        if value.count('@') != 1:
            return False
        local, host = value.split('@')
        if not local or local[0] == '.' or local[-1] == '.' or '..' in local:
            return False
        if any(ord(ch) <= 32 or ord(ch) == 127 for ch in local):
            return False
        return cls._is_hostname(host)

    @classmethod
    def _is_ipv4(cls, value: str) -> bool:
        match = cls._IPV4_RE.match(value)
        return bool(match) and 7 <= len(value) <= 15 and all(int(part) <= 255 for part in match.groups())

    @staticmethod
    def _is_ipv6(value: str) -> bool:
        import ipaddress
        try:
            ipaddress.IPv6Address(value)
            return True
        except ValueError:
            return False

    def _blob_violations(
        self,
        field_info: ProtoFieldInfo,
        constraints: Dict[str, Any],
        value: Union[str, bytes],
        is_text: bool,
    ) -> List[str]:
        """Return the names of the string/bytes rules ``value`` breaks."""

        broken: List[str] = []
        size = self._blob_size(value)
        if 'const' in constraints and value != constraints['const']:
            broken.append('const')
        if 'min_len' in constraints and size < constraints['min_len']:
            broken.append('min_len')
        if 'max_len' in constraints and size > constraints['max_len']:
            broken.append('max_len')
        if 'prefix' in constraints and not value.startswith(constraints['prefix']):
            broken.append('prefix')
        if 'suffix' in constraints and not value.endswith(constraints['suffix']):
            broken.append('suffix')
        if 'contains' in constraints and constraints['contains'] not in value:
            broken.append('contains')
        if 'in' in constraints and value not in list(constraints['in']):
            broken.append('in')
        if 'not_in' in constraints and value in list(constraints['not_in']):
            broken.append('not_in')
        if is_text:
            if constraints.get('ascii') and any(ord(ch) > 127 for ch in value):
                broken.append('ascii')
            if constraints.get('email') and not self._is_email(value):
                broken.append('email')
            if constraints.get('hostname') and not self._is_hostname(value):
                broken.append('hostname')
            if constraints.get('ipv4') and not self._is_ipv4(value):
                broken.append('ipv4')
            if constraints.get('ipv6') and not self._is_ipv6(value):
                broken.append('ipv6')
            if constraints.get('ip') and not (self._is_ipv4(value) or self._is_ipv6(value)):
                broken.append('ip')
        return broken

    def _number_violations(
        self,
        field_info: ProtoFieldInfo,
        constraints: Dict[str, Any],
        value: Union[int, float],
    ) -> List[str]:
        """Return the names of the numeric/enum/bool rules ``value`` breaks."""

        broken: List[str] = []
        if 'const' in constraints and value != constraints['const']:
            broken.append('const')
        if 'gt' in constraints and not value > constraints['gt']:
            broken.append('gt')
        if 'gte' in constraints and not value >= constraints['gte']:
            broken.append('gte')
        if 'lt' in constraints and not value < constraints['lt']:
            broken.append('lt')
        if 'lte' in constraints and not value <= constraints['lte']:
            broken.append('lte')
        if 'in' in constraints and value not in list(constraints['in']):
            broken.append('in')
        if 'not_in' in constraints and value in list(constraints['not_in']):
            broken.append('not_in')
        if constraints.get('defined_only') and field_info.get_type_name() == 'enum':
            if value not in self._enum_numbers(field_info):
                broken.append('defined_only')
        return broken

    def _enum_numbers(self, field_info: ProtoFieldInfo) -> List[int]:
        descriptor = self.registry.pool.FindEnumTypeByName(field_info.full_type_name())
        return [value.number for value in descriptor.values]

    # -- repeated fields and maps -----------------------------------------
