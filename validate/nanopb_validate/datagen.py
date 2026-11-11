"""
nanopb test data generator.

This module generates valid and invalid protobuf test data based on
validation constraints defined in .proto files using validate.proto.
"""

import os
import sys
import random
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

# Prefer pure-Python protobuf runtime to support loading generated *_pb2
# files built with older protoc versions (avoids descriptor runtime errors).
os.environ.setdefault('PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION', 'python')

try:
    from google.protobuf import descriptor_pb2
except ImportError:
    sys.stderr.write("Error: protobuf library required. Install with: pip install protobuf\n")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env  # noqa: E402
env.setup()
from proto._utils import invoke_protoc  # noqa: E402  (nanopb's generator/proto)
from proto import TemporaryDirectory  # noqa: E402
from schema import (DescriptorRegistry, MessageInfo, NanopbOptionsResolver, OutputFormat, ProtoFieldInfo,  # noqa: E402
                    ValidationConstraint, ValidationRuleNotViolatableError, _OMIT_FIELD, _load_nanopb_pb2,
                    _load_validate_pb2, read_options_file)
from values import ValuesMixin  # noqa: E402
from containers import ContainersMixin  # noqa: E402
from violations import ViolationsMixin  # noqa: E402
from encoding import EncodingMixin  # noqa: E402


class DataGenerator(ValuesMixin, ContainersMixin, ViolationsMixin, EncodingMixin):
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
            env.NANOPB_PROTO_DIR,
            env.VALIDATE_PROTO_DIR,
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
        """validate_pb2 is built by env.setup(); kept for callers of the old API."""

        env.build_validate_pb2()

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
