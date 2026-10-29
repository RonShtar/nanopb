#!/usr/bin/env python3
# kate: replace-tabs on; indent-width 4;

"""
nanopb test data generator.

This module generates valid and invalid protobuf test data based on
validation constraints defined in .proto files using validate.proto.
"""

import copy
import fnmatch
import math
import os
import re
import struct
import sys
import time
import random
import string
import importlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

# Prefer pure-Python protobuf runtime to support loading generated *_pb2
# files built with older protoc versions (avoids descriptor runtime errors).
os.environ.setdefault('PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION', 'python')

try:
    from google.protobuf import any_pb2
    from google.protobuf import descriptor_pb2
    from google.protobuf import descriptor_pool
    from google.protobuf import message_factory
    from google.protobuf.descriptor import Descriptor as RuntimeDescriptor
    from google.protobuf.descriptor import FieldDescriptor as RuntimeFieldDescriptor
    from google.protobuf.message import Message
except ImportError:
    sys.stderr.write("Error: protobuf library required. Install with: pip install protobuf\n")
    sys.exit(1)

try:
    from .proto._utils import invoke_protoc
    from .proto import TemporaryDirectory
except ImportError:
    from proto._utils import invoke_protoc
    from proto import TemporaryDirectory

_MISSING = object()

# Sentinel returned by _generate_invalid_value() when the only way to violate a
# rule is to leave the field out of the encoded message (e.g. "required").
_OMIT_FIELD = object()


class ValidationRuleNotViolatableError(ValueError):
    """Raised when no invalid value can be generated for a validation rule."""


def _load_validate_pb2() -> Any:
    """Load validate_pb2 from the repository-local generator/proto directory."""

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    from generator.proto import validate_pb2
    return validate_pb2


def _load_nanopb_pb2() -> Any:
    """Load nanopb_pb2 from the repository-local generator/proto directory."""

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    from generator.proto import nanopb_pb2
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


class DataGenerator:
    """Generates test data for protobuf messages with validation rules."""

    MAX_MESSAGE_DEPTH = 8
    _SYSTEM_ANY_EXCLUDED_FILES = {
        'validate.proto',
        'nanopb.proto',
        'google/protobuf/any.proto',
        'google/protobuf/descriptor.proto',
    }

    def __init__(
        self,
        proto_file: str,
        include_paths: Optional[List[str]] = None,
        options_files: Optional[List[str]] = None,
    ):
        """Load ``proto_file`` and the nanopb options that apply to it.

        ``<name>.options`` next to each .proto (or below an include path) is
        picked up automatically, like nanopb_generator does; ``options_files``
        names additional .options files to apply.
        """

        self.proto_file = proto_file
        self.include_paths = include_paths or []
        self.options_files = options_files or []
        self.file_descriptor: Optional[descriptor_pb2.FileDescriptorProto] = None
        self.registry: Optional[DescriptorRegistry] = None
        self._random = random.Random()
        self._load_proto()

    def _load_proto(self) -> None:
        """Load and compile the proto file."""

        self._ensure_validate_pb2()
        _load_validate_pb2()
        # Register the (nanopb) extensions too, otherwise storage options such
        # as max_size land in unknown_fields and are invisible to the generator.
        try:
            _load_nanopb_pb2()
        except Exception:
            pass

        proto_abs_path = os.path.abspath(self.proto_file)
        proto_dir = os.path.dirname(proto_abs_path)
        proto_basename = os.path.basename(proto_abs_path)

        search_paths = [
            proto_dir,
            os.path.join(os.path.dirname(__file__), 'proto'),
        ] + [os.path.abspath(path) for path in self.include_paths]

        with TemporaryDirectory() as tmpdir:
            desc_file = os.path.join(tmpdir, 'descriptor.pb')
            protoc_args = [
                'protoc',
                '--descriptor_set_out=' + desc_file,
                '--include_imports',
                '--experimental_allow_proto3_optional',
            ]

            for path in search_paths:
                if os.path.exists(path):
                    protoc_args.append('-I' + path)

            protoc_args.append(proto_basename)

            old_cwd = os.getcwd()
            try:
                os.chdir(proto_dir)
                status = invoke_protoc(protoc_args)
            finally:
                os.chdir(old_cwd)

            if status != 0:
                raise RuntimeError(f"protoc failed with status {status}")

            with open(desc_file, 'rb') as handle:
                descriptor_data = handle.read()

        file_set = descriptor_pb2.FileDescriptorSet()
        file_set.ParseFromString(descriptor_data)

        for file_desc in file_set.file:
            if file_desc.name == proto_basename or file_desc.name.endswith('/' + proto_basename):
                self.file_descriptor = file_desc
                break

        if not self.file_descriptor:
            raise ValueError(f"Could not find descriptor for {proto_basename}")

        resolver = NanopbOptionsResolver()
        for file_desc in file_set.file:
            options_path = self._find_options_file(file_desc.name, search_paths)
            if options_path:
                resolver.add_entries(read_options_file(options_path))
        for options_path in self.options_files:
            resolver.add_entries(read_options_file(options_path))

        self.registry = DescriptorRegistry(file_set, self.file_descriptor, resolver)

    @staticmethod
    def _find_options_file(proto_name: str, search_paths: Sequence[str]) -> Optional[str]:
        """Locate the .options file that belongs to a .proto file."""

        options_name = os.path.splitext(proto_name)[0] + '.options'
        for directory in search_paths:
            candidate = os.path.join(directory, options_name)
            if os.path.isfile(candidate):
                return candidate
        return None

    def _ensure_validate_pb2(self) -> None:
        """Ensure generator/proto/validate_pb2.py exists by building it if missing."""

        try:
            gen_dir = os.path.dirname(os.path.abspath(__file__))
            proto_dir = os.path.join(gen_dir, 'proto')
            target_py = os.path.join(proto_dir, 'validate_pb2.py')
            if os.path.isfile(target_py):
                return

            validate_proto = os.path.join(proto_dir, 'validate.proto')
            if not os.path.isfile(validate_proto):
                return

            protoc_args = [
                'protoc',
                f'--python_out={proto_dir}',
                f'-I{proto_dir}',
                os.path.basename(validate_proto),
            ]

            old_cwd = os.getcwd()
            try:
                os.chdir(proto_dir)
                invoke_protoc(protoc_args)
            finally:
                os.chdir(old_cwd)
        except Exception:
            pass

    def get_messages(self) -> List[str]:
        """Get list of top-level messages in the target proto file."""

        return list(self.registry.target_top_level_names if self.registry else [])

    def get_field_info(self, message_name: str, field_name: str) -> Optional[ProtoFieldInfo]:
        """Get field information for a specific message field."""

        try:
            message_info = self.registry.resolve_message(message_name)
        except ValueError:
            return None
        return message_info.fields.get(field_name)

    def get_all_fields(self, message_name: str) -> Dict[str, ProtoFieldInfo]:
        """Get all fields for a message."""

        try:
            return dict(self.registry.resolve_message(message_name).fields)
        except ValueError:
            return {}

    # ------------------------------------------------------------------
    # Public generation API
    # ------------------------------------------------------------------

    def generate_valid(self, message_name: str, seed: Optional[int] = None) -> Dict[str, Any]:
        """Generate valid test data for a message.

        The data satisfies every validate.proto rule and fits the storage that
        nanopb allocates for the message (max_size, max_count, int_size, ...),
        so it can be decoded by pb_decode() and passes the generated validator.
        """

        self._random = random.Random(seed)
        message_info = self.registry.resolve_message(message_name)
        return self._generate_message(message_info.full_name, (message_info.full_name,))

    def generate_invalid(
        self,
        message_name: str,
        violate_field: Optional[Union[str, List[str]]] = None,
        violate_rule: Optional[Union[str, List[str]]] = None,
        seed: Optional[int] = None
    ) -> Dict[str, Any]:
        """Generate invalid test data for a message.

        Exactly the requested field/rule is violated; the generated value is
        still decodable by pb_decode(), so it reaches the validator.  Rules of
        ``repeated.items`` are addressed as ``items.<rule>`` (e.g. ``items.gt``).
        Raises ValidationRuleNotViolatableError when no decodable value can
        violate the rule, e.g. ``max_len`` larger than the allocated buffer.
        """

        self._random = random.Random(seed)
        message_info = self.registry.resolve_message(message_name)
        stack = (message_info.full_name,)
        data = self._generate_message(message_info.full_name, stack)
        fields = message_info.fields

        constrained_fields = {
            name: info for name, info in fields.items()
            if info.constraints or info.item_constraints
        }
        if not constrained_fields:
            raise ValueError(f"No validation constraints found for {message_name}")

        explicit_fields = violate_field is not None
        selected_fields = self._split_names(violate_field)
        if not selected_fields:
            selected_fields = list(constrained_fields.keys())
            self._random.shuffle(selected_fields)
        else:
            for field_name in selected_fields:
                if field_name not in constrained_fields:
                    if field_name not in fields:
                        raise ValueError(f"Field {field_name} does not exist in message {message_name}")
                    raise ValueError(f"Field {field_name} has no constraints to violate")

        candidate_rules = self._split_names(violate_rule)
        failures: List[str] = []
        violated = 0

        for field_name in selected_fields:
            field_info = constrained_fields[field_name]
            pool = self._violatable_constraints(field_info)
            if candidate_rules:
                matching = [c for c in pool if c.rule_type in set(candidate_rules)]
                if not matching:
                    if explicit_fields:
                        raise ValueError(
                            f"Field {field_name} has no rule named {candidate_rules} "
                            f"(available: {sorted({c.rule_type for c in pool})})"
                        )
                    continue
                pool = matching
            self._random.shuffle(pool)

            done = False
            for chosen in pool:
                try:
                    value = self._generate_invalid_value(field_info, chosen, stack)
                except ValidationRuleNotViolatableError as exc:
                    failures.append(str(exc))
                    continue
                self._drop_oneof_siblings(message_info, field_info, data)
                if value is _OMIT_FIELD:
                    # The violation is the absence of the field itself.
                    data.pop(field_name, None)
                else:
                    data[field_name] = value
                done = True
                break

            if done:
                violated += 1
                if not explicit_fields:
                    return data
            elif explicit_fields:
                raise ValidationRuleNotViolatableError(failures[-1])

        if violated:
            return data
        raise ValidationRuleNotViolatableError(
            "No rule of message %s can be violated with decodable data: %s"
            % (message_name, '; '.join(failures) or 'no matching rule')
        )

    def violatable_rules(self, message_name: str) -> List[Tuple[str, str]]:
        """(field, rule) pairs that generate_invalid() can be asked to violate.

        Rules of repeated.items come out as ``items.<rule>``.
        """

        message_info = self.registry.resolve_message(message_name)
        pairs: List[Tuple[str, str]] = []
        for name, info in message_info.fields.items():
            for constraint in self._violatable_constraints(info):
                if (name, constraint.rule_type) not in pairs:
                    pairs.append((name, constraint.rule_type))
        return pairs

    @staticmethod
    def _split_names(names: Optional[Union[str, List[str]]]) -> List[str]:
        """Normalize comma separated names / lists of names."""

        if not names:
            return []
        if isinstance(names, str):
            names = [names]
        result: List[str] = []
        for name in names:
            if isinstance(name, str):
                result.extend(part.strip() for part in name.split(',') if part.strip())
        return result

    @staticmethod
    def _violatable_constraints(field_info: ProtoFieldInfo) -> List[ValidationConstraint]:
        """Constraints of a field, with repeated.items rules as ``items.<rule>``."""

        pool = list(field_info.constraints)
        for constraint in field_info.item_constraints:
            pool.append(ValidationConstraint(
                constraint.field_name, constraint.field_type,
                'items.' + constraint.rule_type, constraint.value,
            ))
        return pool

    def _drop_oneof_siblings(
        self,
        message_info: MessageInfo,
        field_info: ProtoFieldInfo,
        data: Dict[str, Any],
    ) -> None:
        """Remove the other members of a oneof before one of them is replaced."""

        if field_info.oneof_index is None:
            return
        for other in message_info.fields.values():
            if other.oneof_index == field_info.oneof_index and other.name != field_info.name:
                data.pop(other.name, None)

    # ------------------------------------------------------------------
    # Valid data
    # ------------------------------------------------------------------

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

        pairs: Dict[Any, Any] = {}
        attempts = 0
        while len(pairs) < count and attempts < count * 30 + 30:
            attempts += 1
            key = self._generate_valid_element(key_info, key_info.constraint_map(), active_stack)
            value = self._generate_valid_element(value_info, value_info.constraint_map(), active_stack)
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

    def encode_to_binary(self, message_name: str, data: Dict[str, Any]) -> bytes:
        """Encode a data dictionary to protobuf binary format."""

        message = self._build_message_from_data(message_name, data)
        return message.SerializeToString()

    def _build_message_from_data(self, message_name: str, data: Dict[str, Any]) -> Message:
        """Build a dynamic protobuf message from generated data."""

        message_class = self.registry.get_message_class(message_name)
        message = message_class()
        self._populate_message(message, data)
        return message

    def _populate_message(self, message: Message, data: Dict[str, Any]) -> None:
        """Populate a protobuf message instance from a dictionary."""

        for field_name, value in data.items():
            runtime_field = message.DESCRIPTOR.fields_by_name.get(field_name)
            if runtime_field is None or value is None:
                continue

            is_repeated = getattr(runtime_field, 'is_repeated', _MISSING)
            if is_repeated is _MISSING:
                if hasattr(runtime_field, 'label'):
                    is_repeated = (
                        runtime_field.label
                        == RuntimeFieldDescriptor.LABEL_REPEATED
                    )
                else:
                    raise AttributeError(
                        f"Field descriptor {runtime_field!r} does not expose repeated field metadata"
                    )

            if is_repeated and isinstance(value, dict):
                self._populate_map(message, runtime_field, value)
                continue

            if is_repeated:
                if runtime_field.cpp_type == RuntimeFieldDescriptor.CPPTYPE_MESSAGE:
                    container = getattr(message, field_name)
                    for item in value:
                        if item is None:
                            continue
                        if runtime_field.message_type.full_name == 'google.protobuf.Any':
                            container.add().CopyFrom(
                                self._build_runtime_any_message(runtime_field.message_type, item)
                            )
                        else:
                            container.add().CopyFrom(
                                self._build_runtime_message(runtime_field.message_type, item)
                            )
                else:
                    getattr(message, field_name).extend(value)
                continue

            if runtime_field.cpp_type == RuntimeFieldDescriptor.CPPTYPE_MESSAGE:
                if runtime_field.message_type.full_name == 'google.protobuf.Any':
                    getattr(message, field_name).CopyFrom(
                        self._build_runtime_any_message(runtime_field.message_type, value)
                    )
                else:
                    getattr(message, field_name).CopyFrom(
                        self._build_runtime_message(runtime_field.message_type, value)
                    )
            else:
                setattr(message, field_name, value)

    def _populate_map(self, message: Message, runtime_field: Any, pairs: Dict[Any, Any]) -> None:
        """Fill a map<key, value> field from a dict."""

        container = getattr(message, runtime_field.name)
        value_field = runtime_field.message_type.fields_by_name['value']
        for key, value in pairs.items():
            if value_field.cpp_type == RuntimeFieldDescriptor.CPPTYPE_MESSAGE:
                if value_field.message_type.full_name == 'google.protobuf.Any':
                    container[key].CopyFrom(self._build_runtime_any_message(value_field.message_type, value))
                else:
                    container[key].CopyFrom(self._build_runtime_message(value_field.message_type, value))
            else:
                container[key] = value

    def _build_runtime_message(
        self,
        descriptor: RuntimeDescriptor,
        value: Union[Dict[str, Any], Message],
    ) -> Message:
        """Build a runtime submessage from a dict or pass through a message."""

        if isinstance(value, Message):
            return value

        message_class = self.registry.get_message_class_for_descriptor(descriptor)
        message = message_class()
        self._populate_message(message, value)
        return message

    def _normalize_any_value(self, value: Union[Dict[str, Any], any_pb2.Any]) -> Dict[str, Any]:
        """Normalize Any input into a type_url/value dictionary."""

        if isinstance(value, any_pb2.Any):
            return {'type_url': value.type_url, 'value': value.value}

        if not isinstance(value, dict):
            raise TypeError("Any field value must be a dict or Any instance")

        if '@type' in value:
            type_url = str(value['@type'])
            payload = value.get('value', {})
            if isinstance(payload, dict):
                message_info = self._resolve_any_type_url(type_url)
                if not message_info:
                    raise ValueError(f"Unknown Any type_url: {type_url}")
                payload_message = self._build_message_from_data(message_info.full_name, payload)
                payload_bytes = payload_message.SerializeToString()
            else:
                payload_bytes = payload
            return {'type_url': type_url, 'value': payload_bytes}

        type_url = value.get('type_url')
        payload_value = value.get('value', b'')
        if type_url is None:
            raise ValueError("Any field value must contain type_url")

        if isinstance(payload_value, dict):
            message_info = self._resolve_any_type_url(str(type_url))
            if not message_info:
                raise ValueError(f"Unknown Any type_url: {type_url}")
            payload_message = self._build_message_from_data(message_info.full_name, payload_value)
            payload_bytes = payload_message.SerializeToString()
        else:
            payload_bytes = payload_value

        return {'type_url': str(type_url), 'value': payload_bytes}

    def _build_runtime_any_message(
        self,
        descriptor: RuntimeDescriptor,
        value: Union[Dict[str, Any], any_pb2.Any],
    ) -> Message:
        """Build an Any message instance tied to a descriptor pool."""

        normalized = self._normalize_any_value(value)
        return self._build_runtime_message(descriptor, normalized)

    def format_output(
        self,
        data: Any,
        format_type: OutputFormat = OutputFormat.C_ARRAY,
        name: str = "test_data"
    ) -> Union[str, bytes]:
        """Format generated output."""

        if format_type == OutputFormat.BINARY:
            return data

        if format_type == OutputFormat.HEX_STRING:
            return data.hex()

        if format_type == OutputFormat.C_ARRAY:
            hex_values = ', '.join(f'0x{byte:02x}' for byte in data)
            return (
                f'const uint8_t {name}[] = {{{hex_values}}};\n'
                f'const size_t {name}_size = {len(data)};'
            )

        if format_type == OutputFormat.PYTHON_DICT:
            return str(data)

        return str(data)


def main() -> int:
    """Command line entry point."""

    import argparse

    parser = argparse.ArgumentParser(
        description='Generate test data for protobuf messages with validation'
    )
    parser.add_argument('proto_file', help='Path to .proto file')
    parser.add_argument('message', help='Message name to generate data for')
    parser.add_argument('--invalid', action='store_true',
                        help='Generate invalid data instead of valid')
    parser.add_argument(
        '--field', dest='fields', action='append', default=None,
        help='Field(s) to violate (can be given multiple times or comma-separated)'
    )
    parser.add_argument(
        '--rule', dest='rules', action='append', default=None,
        help='Rule(s) to violate (can be given multiple times or comma-separated)'
    )
    parser.add_argument('--format', choices=['binary', 'c_array', 'hex', 'dict'],
                        default='c_array', help='Output format')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--seed', type=int, help='Random seed for reproducibility')
    parser.add_argument('-I', '--include', action='append', default=[],
                        help='Include path for proto files')
    parser.add_argument('-f', '--options-file', dest='options_files', action='append', default=[],
                        metavar='FILE',
                        help='Additional nanopb .options file (can be given multiple times). '
                             '<proto>.options next to each .proto is always read')

    args = parser.parse_args()

    try:
        generator = DataGenerator(args.proto_file, args.include, options_files=args.options_files)
    except Exception as exc:
        print(f"Error loading proto file: {exc}", file=sys.stderr)
        return 1

    try:
        if args.invalid:
            data_dict = generator.generate_invalid(
                args.message,
                violate_field=args.fields,
                violate_rule=args.rules,
                seed=args.seed
            )
        else:
            data_dict = generator.generate_valid(args.message, seed=args.seed)

        format_map = {
            'binary': OutputFormat.BINARY,
            'c_array': OutputFormat.C_ARRAY,
            'hex': OutputFormat.HEX_STRING,
            'dict': OutputFormat.PYTHON_DICT,
        }

        if args.format == 'dict':
            output = generator.format_output(
                data_dict,
                format_map[args.format],
                f"{args.message.lower()}_data"
            )
        else:
            binary_data = generator.encode_to_binary(args.message, data_dict)
            output = generator.format_output(
                binary_data,
                format_map[args.format],
                f"{args.message.lower()}_data"
            )

        if args.output:
            if args.format == 'binary':
                with open(args.output, 'wb') as handle:
                    handle.write(output)
            else:
                with open(args.output, 'w') as handle:
                    handle.write(output)
                    handle.write('\n')
        else:
            if args.format == 'binary':
                sys.stdout.buffer.write(output)
            else:
                print(output)

        print(f"\n// Generated data: {data_dict}", file=sys.stderr)
    except Exception as exc:
        print(f"Error generating data: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
