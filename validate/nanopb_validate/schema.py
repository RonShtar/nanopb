"""Descriptors for the data generator: .options files (nanopb storage limits), field and
message info with their validate rules, and the registry of every message of a proto and its imports.
"""

import fnmatch
import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# Prefer pure-Python protobuf runtime to support loading generated *_pb2
# files built with older protoc versions (avoids descriptor runtime errors).
os.environ.setdefault('PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION', 'python')

try:
    from google.protobuf import descriptor_pb2
    from google.protobuf import descriptor_pool
    from google.protobuf import message_factory
    from google.protobuf.descriptor import Descriptor as RuntimeDescriptor
except ImportError:
    sys.stderr.write("Error: protobuf library required. Install with: pip install protobuf\n")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env  # noqa: E402
env.setup()


_MISSING = object()

# Sentinel returned by _generate_invalid_value() when the only way to violate a
# rule is to leave the field out of the encoded message (e.g. "required").
_OMIT_FIELD = object()


class ValidationRuleNotViolatableError(ValueError):
    """Raised when no invalid value can be generated for a validation rule."""


def _load_validate_pb2() -> Any:
    """validate_pb2, built by env.setup() in validate_proto/."""

    import validate_pb2
    return validate_pb2


def _load_nanopb_pb2() -> Any:
    """nanopb_pb2 from nanopb's generator/proto package."""

    from nanopb_api import nanopb_pb2
    return nanopb_pb2


class OutputFormat(Enum):
    """Output format for generated data."""

    BINARY = "binary"
    C_ARRAY = "c_array"
    PYTHON_DICT = "python_dict"
    HEX_STRING = "hex_string"


def _strip_options_comments(text: str) -> str:
    """Remove /* */, // and # comments from a nanopb .options file."""

    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    return re.sub(r'(//|#)[^\n]*', '', text)


def read_options_file(path: str) -> List[Tuple[str, Any]]:
    """Parse a nanopb .options file into (name mask, NanoPBOptions) tuples."""

    from google.protobuf import text_format

    nanopb_pb2 = _load_nanopb_pb2()
    results: List[Tuple[str, Any]] = []
    with open(path, 'r', encoding='utf-8') as handle:
        data = _strip_options_comments(handle.read())
    for line_no, line in enumerate(data.split('\n'), 1):
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            raise ValueError(
                "%s:%d: option lines need a name mask followed by options: '%s'"
                % (path, line_no, line)
            )
        options = nanopb_pb2.NanoPBOptions()
        try:
            text_format.Merge(parts[1], options)
        except Exception as exc:
            raise ValueError("%s:%d: unparsable option line '%s': %s" % (path, line_no, line, exc))
        results.append((parts[0], options))
    return results


class NanopbOptionsResolver:
    """Resolve the effective NanoPBOptions of files, messages and fields.

    Mirrors nanopb_generator.get_nanopb_suboptions(): options are inherited
    file -> message -> field, ``.options`` file entries override the inherited
    values and options written inline in the .proto (the (nanopb) extension)
    override both.  The generated C structs are sized from these options, so the
    data generator has to see exactly the same limits as the nanopb generator.
    """

    def __init__(self, entries: Optional[List[Tuple[str, Any]]] = None):
        self.entries: List[Tuple[str, Any]] = list(entries or [])

    def add_entries(self, entries: List[Tuple[str, Any]]) -> None:
        self.entries.extend(entries)

    def _merge(self, base: Any, names: Sequence[str], inline: Any) -> Any:
        nanopb_pb2 = _load_nanopb_pb2()
        merged = nanopb_pb2.NanoPBOptions()
        merged.CopyFrom(base)
        for mask, options in self.entries:
            if any(fnmatch.fnmatchcase(name, mask) for name in names):
                merged.MergeFrom(options)
        if inline is not None:
            merged.MergeFrom(inline)
        return merged

    @staticmethod
    def _inline(options: Any, extension_name: str) -> Any:
        try:
            extension = getattr(_load_nanopb_pb2(), extension_name)
            if options.HasExtension(extension):
                return options.Extensions[extension]
        except Exception:
            pass
        return None

    @staticmethod
    def _names(package: str, dotted: str) -> List[str]:
        # nanopb matches package-qualified names; accept the package-less
        # spelling as well since the documentation shows "Message.field".
        names = [dotted]
        if package and dotted.startswith(package + '.'):
            names.append(dotted[len(package) + 1:])
        return names

    def file_options(self, file_desc: descriptor_pb2.FileDescriptorProto) -> Any:
        nanopb_pb2 = _load_nanopb_pb2()
        return self._merge(
            nanopb_pb2.NanoPBOptions(), [file_desc.name],
            self._inline(file_desc.options, 'nanopb_fileopt'))

    def message_options(
        self,
        file_options: Any,
        file_desc: descriptor_pb2.FileDescriptorProto,
        full_name: str,
        message_desc: descriptor_pb2.DescriptorProto,
    ) -> Any:
        return self._merge(
            file_options, self._names(file_desc.package, full_name),
            self._inline(message_desc.options, 'nanopb_msgopt'))

    def field_options(
        self,
        message_options: Any,
        file_desc: descriptor_pb2.FileDescriptorProto,
        message_full_name: str,
        field_desc: descriptor_pb2.FieldDescriptorProto,
    ) -> Any:
        return self._merge(
            message_options,
            self._names(file_desc.package, message_full_name + '.' + field_desc.name),
            self._inline(field_desc.options, 'nanopb'))


@dataclass
class ValidationConstraint:
    """Represents a validation constraint for a field."""

    field_name: str
    field_type: str
    rule_type: str
    value: Any


_INTEGER_TYPES = (
    'int32', 'int64', 'uint32', 'uint64', 'sint32', 'sint64',
    'fixed32', 'fixed64', 'sfixed32', 'sfixed64',
)
_NUMERIC_TYPES = _INTEGER_TYPES + ('float', 'double')


@dataclass
class ProtoFieldInfo:
    """Information about a protobuf field.

    ``constraints`` holds the validate.proto rules of the field itself and
    ``item_constraints`` the rules of ``repeated.items``.  The remaining
    attributes describe the storage nanopb allocates for the field, which
    limits what data can be decoded at all.
    """

    descriptor: descriptor_pb2.FieldDescriptorProto
    nanopb_options: Any = None
    name: str = field(init=False)
    number: int = field(init=False)
    type: int = field(init=False)
    type_name: str = field(init=False)
    label: int = field(init=False)
    constraints: List[ValidationConstraint] = field(default_factory=list, init=False)
    item_constraints: List[ValidationConstraint] = field(default_factory=list, init=False)
    map_key_constraints: List[ValidationConstraint] = field(default_factory=list, init=False)
    map_value_constraints: List[ValidationConstraint] = field(default_factory=list, init=False)
    max_size: Optional[int] = field(default=None, init=False)
    max_count: Optional[int] = field(default=None, init=False)
    fixed_length: bool = field(default=False, init=False)
    fixed_count: bool = field(default=False, init=False)
    int_size: int = field(default=0, init=False)
    storage: str = field(default='static', init=False)
    oneof_index: Optional[int] = field(default=None, init=False)
    map_entry: Optional[str] = field(default=None, init=False)

    _TYPE_MAP = {
        descriptor_pb2.FieldDescriptorProto.TYPE_DOUBLE: 'double',
        descriptor_pb2.FieldDescriptorProto.TYPE_FLOAT: 'float',
        descriptor_pb2.FieldDescriptorProto.TYPE_INT64: 'int64',
        descriptor_pb2.FieldDescriptorProto.TYPE_UINT64: 'uint64',
        descriptor_pb2.FieldDescriptorProto.TYPE_INT32: 'int32',
        descriptor_pb2.FieldDescriptorProto.TYPE_FIXED64: 'fixed64',
        descriptor_pb2.FieldDescriptorProto.TYPE_FIXED32: 'fixed32',
        descriptor_pb2.FieldDescriptorProto.TYPE_BOOL: 'bool',
        descriptor_pb2.FieldDescriptorProto.TYPE_STRING: 'string',
        descriptor_pb2.FieldDescriptorProto.TYPE_GROUP: 'group',
        descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE: 'message',
        descriptor_pb2.FieldDescriptorProto.TYPE_BYTES: 'bytes',
        descriptor_pb2.FieldDescriptorProto.TYPE_UINT32: 'uint32',
        descriptor_pb2.FieldDescriptorProto.TYPE_ENUM: 'enum',
        descriptor_pb2.FieldDescriptorProto.TYPE_SFIXED32: 'sfixed32',
        descriptor_pb2.FieldDescriptorProto.TYPE_SFIXED64: 'sfixed64',
        descriptor_pb2.FieldDescriptorProto.TYPE_SINT32: 'sint32',
        descriptor_pb2.FieldDescriptorProto.TYPE_SINT64: 'sint64',
    }

    def __post_init__(self) -> None:
        self.name = self.descriptor.name
        self.number = self.descriptor.number
        self.type = self.descriptor.type
        self.type_name = self.descriptor.type_name
        self.label = self.descriptor.label
        if self.descriptor.HasField('oneof_index') and not self.descriptor.proto3_optional:
            self.oneof_index = self.descriptor.oneof_index
        if hasattr(self.descriptor, 'options'):
            self._parse_validation_rules(self.descriptor.options)
        self._parse_nanopb_options(self.nanopb_options)

    def _parse_nanopb_options(self, options: Any) -> None:
        """Read the (nanopb) storage options that size the generated C buffers.

        nanopb allocates fixed-size storage for string/bytes/repeated fields and
        narrow integer types for int_size, so data that ignores these limits
        fails to decode ("string overflow", "array overflow", "integer too
        large") even though it satisfies every validate.proto rule.
        """

        nanopb_pb2 = _load_nanopb_pb2()
        if options is None:
            options = nanopb_pb2.NanoPBOptions()
            try:
                if self.descriptor.options.HasExtension(nanopb_pb2.nanopb):
                    options.MergeFrom(self.descriptor.options.Extensions[nanopb_pb2.nanopb])
            except Exception:
                pass

        field_type = options.type
        if field_type == nanopb_pb2.FT_CALLBACK:
            self.storage = 'callback'
        elif field_type == nanopb_pb2.FT_POINTER:
            self.storage = 'pointer'
        elif field_type == nanopb_pb2.FT_IGNORE:
            self.storage = 'ignore'

        if options.HasField('max_count') and options.max_count > 0:
            self.max_count = options.max_count

        # max_length is the string length excluding the null terminator;
        # max_size is the allocated buffer, which includes it for strings.
        if options.HasField('max_length') and options.max_length > 0:
            self.max_size = options.max_length
        elif options.HasField('max_size') and options.max_size > 0:
            self.max_size = options.max_size
            if self.get_type_name() == 'string':
                self.max_size -= 1

        self.fixed_length = bool(options.fixed_length)
        self.fixed_count = bool(options.fixed_count)
        self.int_size = int(options.int_size)

    def capacity(self) -> Optional[int]:
        """Maximum string length / bytes count that fits the generated C struct."""

        if self.storage != 'static':
            return None
        return self.max_size

    def item_capacity(self) -> Optional[int]:
        """Maximum number of repeated entries that fit the generated C array."""

        if self.storage != 'static':
            return None
        return self.max_count

    def integer_bounds(self) -> Tuple[int, int]:
        """Range of values the C storage of an integer field can hold.

        This is the protobuf type range narrowed by (nanopb).int_size, which
        makes the generated struct use int8_t/int16_t/... and makes pb_decode()
        reject wire values that do not fit.
        """

        type_name = self.get_type_name()
        signed = type_name in ('int32', 'int64', 'sint32', 'sint64', 'sfixed32', 'sfixed64')
        bits = 64 if type_name.endswith('64') else 32
        if type_name in ('int32', 'int64', 'sint32', 'sint64', 'uint32', 'uint64'):
            nanopb_pb2 = _load_nanopb_pb2()
            narrowed = {
                nanopb_pb2.IS_8: 8, nanopb_pb2.IS_16: 16,
                nanopb_pb2.IS_32: 32, nanopb_pb2.IS_64: 64,
            }.get(self.int_size)
            if narrowed is not None:
                # Widening (int32 with IS_64) cannot make wire values larger
                # than the protobuf type allows.
                bits = min(bits, narrowed)
        if signed:
            return -(2 ** (bits - 1)), 2 ** (bits - 1) - 1
        return 0, 2 ** bits - 1

    def _parse_validation_rules(self, field_options: Any) -> None:
        """Parse validation rules from field options."""

        try:
            validate_pb2 = _load_validate_pb2()
            if not field_options.HasExtension(validate_pb2.rules):
                return

            rules_option = field_options.Extensions[validate_pb2.rules]
        except Exception:
            return

        self.constraints.extend(self._collect_rules(rules_option, top_level=True))
        if rules_option.HasField('repeated') and rules_option.repeated.HasField('items'):
            self.item_constraints.extend(
                self._collect_rules(rules_option.repeated.items, top_level=False)
            )
        if rules_option.HasField('map'):
            if rules_option.map.HasField('keys'):
                self.map_key_constraints.extend(
                    self._collect_rules(rules_option.map.keys, top_level=False)
                )
            if rules_option.map.HasField('values'):
                self.map_value_constraints.extend(
                    self._collect_rules(rules_option.map.values, top_level=False)
                )

    def _collect_rules(self, rules_option: Any, top_level: bool) -> List[ValidationConstraint]:
        """Flatten a validate.FieldRules message into constraints."""

        found: List[ValidationConstraint] = []

        def add_constraint(rule_type: str, value: Any) -> None:
            found.append(ValidationConstraint(self.name, self.get_type_name(), rule_type, value))

        def add_list(rules: Any, rule_type: str) -> None:
            values = list(getattr(rules, rule_type))
            if values:
                add_constraint(rule_type, values)

        def add_numeric_rules(numeric_rules: Any) -> None:
            for rule_name, proto_name in (
                ('const', 'const_value'), ('lt', 'lt'), ('lte', 'lte'),
                ('gt', 'gt'), ('gte', 'gte'),
            ):
                if numeric_rules.HasField(proto_name):
                    add_constraint(rule_name, getattr(numeric_rules, proto_name))
            add_list(numeric_rules, 'in')
            add_list(numeric_rules, 'not_in')

        for type_name in _NUMERIC_TYPES:
            if rules_option.HasField(type_name):
                add_numeric_rules(getattr(rules_option, type_name))

        for kind in ('string', 'bytes'):
            if not rules_option.HasField(kind):
                continue
            kind_rules = getattr(rules_option, kind)
            for rule_name, proto_name in (
                ('const', 'const_value'), ('min_len', 'min_len'), ('max_len', 'max_len'),
                ('prefix', 'prefix'), ('suffix', 'suffix'), ('contains', 'contains'),
            ):
                if kind_rules.HasField(proto_name):
                    add_constraint(rule_name, getattr(kind_rules, proto_name))
            if kind == 'string':
                for flag in ('ascii', 'email', 'hostname', 'ip', 'ipv4', 'ipv6'):
                    if getattr(kind_rules, flag, False):
                        add_constraint(flag, True)
            add_list(kind_rules, 'in')
            add_list(kind_rules, 'not_in')

        if rules_option.HasField('bool') and rules_option.bool.HasField('const_value'):
            add_constraint('const', rules_option.bool.const_value)

        if rules_option.HasField('enum'):
            enum_rules = rules_option.enum
            if enum_rules.HasField('const_value'):
                add_constraint('const', enum_rules.const_value)
            if enum_rules.HasField('defined_only') and enum_rules.defined_only:
                add_constraint('defined_only', True)
            add_list(enum_rules, 'in')
            add_list(enum_rules, 'not_in')

        if top_level and rules_option.HasField('repeated'):
            repeated_rules = rules_option.repeated
            if repeated_rules.HasField('min_items'):
                add_constraint('min_items', repeated_rules.min_items)
            if repeated_rules.HasField('max_items'):
                add_constraint('max_items', repeated_rules.max_items)
            if repeated_rules.HasField('unique') and repeated_rules.unique:
                add_constraint('unique', True)

        if top_level and rules_option.HasField('map'):
            map_rules = rules_option.map
            if map_rules.HasField('min_pairs'):
                add_constraint('min_items', map_rules.min_pairs)
            if map_rules.HasField('max_pairs'):
                add_constraint('max_items', map_rules.max_pairs)

        if rules_option.HasField('any'):
            add_list(rules_option.any, 'in')
            add_list(rules_option.any, 'not_in')

        if top_level and rules_option.HasField('timestamp'):
            timestamp_rules = rules_option.timestamp
            if timestamp_rules.HasField('gt_now') and timestamp_rules.gt_now:
                add_constraint('gt_now', True)
            if timestamp_rules.HasField('lt_now') and timestamp_rules.lt_now:
                add_constraint('lt_now', True)
            if timestamp_rules.HasField('within'):
                add_constraint('within', timestamp_rules.within.seconds)

        if top_level and rules_option.HasField('required') and rules_option.required:
            add_constraint('required', True)
        if top_level and rules_option.HasField('oneof_required') and rules_option.oneof_required:
            add_constraint('oneof_required', True)

        return found

    def get_type_name(self) -> str:
        """Get human-readable type name."""

        return self._TYPE_MAP.get(self.type, 'unknown')

    def full_type_name(self) -> str:
        """Get the fully qualified message or enum type name."""

        return self.type_name.lstrip('.') if self.type_name else ''

    def is_repeated(self) -> bool:
        """Check if field is repeated (maps are repeated entries too)."""

        return self.label == descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED

    def is_map(self) -> bool:
        """Check if field is a map<key, value> field."""

        return self.map_entry is not None

    def is_message(self) -> bool:
        """Check if field is a message field."""

        return self.type == descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE

    def is_any(self) -> bool:
        """Check if field is google.protobuf.Any."""

        return self.full_type_name() == 'google.protobuf.Any'

    def constraint_map(self) -> Dict[str, Any]:
        """Get constraints as a rule->value mapping."""

        return {constraint.rule_type: constraint.value for constraint in self.constraints}

    def item_constraint_map(self) -> Dict[str, Any]:
        """Get repeated.items constraints as a rule->value mapping."""

        return {constraint.rule_type: constraint.value for constraint in self.item_constraints}


@dataclass
class MessageInfo:
    """Descriptor metadata for a message type."""

    full_name: str
    short_name: str
    descriptor_proto: descriptor_pb2.DescriptorProto
    file_descriptor: descriptor_pb2.FileDescriptorProto
    fields: Dict[str, ProtoFieldInfo]
    requires: List[str] = field(default_factory=list)
    mutex: List[List[str]] = field(default_factory=list)
    at_least: List[Tuple[int, List[str]]] = field(default_factory=list)
    oneof_names: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class AnyCandidate:
    """Concrete message candidate for an Any field."""

    message_info: MessageInfo
    type_url: str


class DescriptorRegistry:
    """Registry for proto descriptors and dynamic message resolution."""

    def __init__(
        self,
        file_set: descriptor_pb2.FileDescriptorSet,
        target_file: descriptor_pb2.FileDescriptorProto,
        options_resolver: Optional[NanopbOptionsResolver] = None,
    ):
        self.file_set = file_set
        self.target_file = target_file
        self.options_resolver = options_resolver or NanopbOptionsResolver()
        self.pool = descriptor_pool.DescriptorPool()
        self._factory = None
        self.messages_by_full_name: Dict[str, MessageInfo] = {}
        self.target_top_level_names: List[str] = []
        self._top_level_aliases: Dict[str, str] = {}
        self._build()

    def _build(self) -> None:
        self._add_files_to_pool()
        for file_desc in self.file_set.file:
            self._register_file_messages(file_desc)

    def _add_files_to_pool(self) -> None:
        pending = {file_desc.name: file_desc for file_desc in self.file_set.file}
        added = set()

        while pending:
            progressed = False
            for name, file_desc in list(pending.items()):
                if any(dep not in added and dep in pending for dep in file_desc.dependency):
                    continue
                self.pool.AddSerializedFile(file_desc.SerializeToString())
                added.add(name)
                del pending[name]
                progressed = True

            if progressed:
                continue

            name, file_desc = next(iter(pending.items()))
            self.pool.AddSerializedFile(file_desc.SerializeToString())
            added.add(name)
            del pending[name]

    def _register_file_messages(self, file_desc: descriptor_pb2.FileDescriptorProto) -> None:
        package_prefix = file_desc.package
        file_options = self.options_resolver.file_options(file_desc)
        for message_desc in file_desc.message_type:
            self._register_message(
                file_desc, message_desc, package_prefix, file_options, top_level=True
            )

    def _register_message(
        self,
        file_desc: descriptor_pb2.FileDescriptorProto,
        message_desc: descriptor_pb2.DescriptorProto,
        prefix: str,
        file_options: Any,
        top_level: bool = False,
    ) -> None:
        full_name = '.'.join(part for part in [prefix, message_desc.name] if part)
        message_options = self.options_resolver.message_options(
            file_options, file_desc, full_name, message_desc
        )
        fields = {}
        for field_desc in message_desc.field:
            field_options = self.options_resolver.field_options(
                message_options, file_desc, full_name, field_desc
            )
            fields[field_desc.name] = ProtoFieldInfo(field_desc, field_options)

        # map<K, V> fields are repeated fields of a synthetic *Entry message.
        nested_by_name = {nested.name: nested for nested in message_desc.nested_type}
        for field_info in fields.values():
            if not field_info.is_repeated() or not field_info.is_message():
                continue
            entry_name = field_info.full_type_name()
            if not entry_name.startswith(full_name + '.'):
                continue
            nested = nested_by_name.get(entry_name[len(full_name) + 1:])
            if nested is not None and nested.options.map_entry:
                field_info.map_entry = entry_name

        info = MessageInfo(
            full_name=full_name,
            short_name=message_desc.name,
            descriptor_proto=message_desc,
            file_descriptor=file_desc,
            fields=fields,
            oneof_names=[oneof.name for oneof in message_desc.oneof_decl],
        )
        self._parse_message_rules(info, message_desc)
        self.messages_by_full_name[full_name] = info

        if top_level and file_desc.name == self.target_file.name:
            self.target_top_level_names.append(message_desc.name)
            self._top_level_aliases[message_desc.name] = full_name

        for nested_desc in message_desc.nested_type:
            self._register_message(file_desc, nested_desc, full_name, file_options)

    @staticmethod
    def _parse_message_rules(info: MessageInfo, message_desc: descriptor_pb2.DescriptorProto) -> None:
        """Read the validate.message options (requires / mutex / at_least)."""

        try:
            validate_pb2 = _load_validate_pb2()
            if not message_desc.options.HasExtension(validate_pb2.message):
                return
            rules = message_desc.options.Extensions[validate_pb2.message]
        except Exception:
            return
        info.requires = list(rules.requires)
        info.mutex = [list(group.fields) for group in rules.mutex]
        info.at_least = [(int(rule.n), list(rule.fields)) for rule in rules.at_least]

    def resolve_message(self, message_name: str) -> MessageInfo:
        """Resolve a message by full name or target-file top-level alias."""

        normalized = message_name.lstrip('.')
        if normalized in self.messages_by_full_name:
            return self.messages_by_full_name[normalized]
        if normalized in self._top_level_aliases:
            return self.messages_by_full_name[self._top_level_aliases[normalized]]
        raise ValueError(f"Message {message_name} not found")

    def get_runtime_descriptor(self, message_name: str) -> RuntimeDescriptor:
        """Get runtime descriptor for a message."""

        full_name = self.resolve_message(message_name).full_name
        return self.pool.FindMessageTypeByName(full_name)

    def get_message_class(self, message_name: str):
        """Get a dynamic protobuf message class."""

        descriptor = self.get_runtime_descriptor(message_name)
        return self.get_message_class_for_descriptor(descriptor)

    def get_message_class_for_descriptor(self, descriptor: RuntimeDescriptor):
        """Get a dynamic protobuf message class from a runtime descriptor."""

        try:
            return message_factory.GetMessageClass(descriptor)
        except AttributeError:
            if self._factory is None:
                self._factory = message_factory.MessageFactory(self.pool)
            return self._factory.GetPrototype(descriptor)

    def iter_messages(self) -> Iterable[MessageInfo]:
        """Iterate over all indexed messages."""

        return self.messages_by_full_name.values()
