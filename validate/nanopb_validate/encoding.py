"""Encoding: generated dicts to protobuf messages and bytes,
Any packing, and output formats (binary, C array, hex, dict).
"""

import os
import sys
from typing import Any, Dict, Union

# Prefer pure-Python protobuf runtime to support loading generated *_pb2
# files built with older protoc versions (avoids descriptor runtime errors).
os.environ.setdefault('PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION', 'python')

try:
    from google.protobuf import any_pb2
    from google.protobuf.descriptor import Descriptor as RuntimeDescriptor
    from google.protobuf.descriptor import FieldDescriptor as RuntimeFieldDescriptor
    from google.protobuf.message import Message
except ImportError:
    sys.stderr.write("Error: protobuf library required. Install with: pip install protobuf\n")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import env  # noqa: E402
env.setup()
from schema import (OutputFormat, _MISSING)  # noqa: E402


class EncodingMixin:
    """Encoding: generated dicts to protobuf messages and bytes,
    Any packing, and output formats (binary, C array, hex, dict).

    Part of DataGenerator (datagen.py); uses its attributes through self.
    """

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
