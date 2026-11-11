"""
Nanopb Validation Support Module
=================================

This module extends the nanopb generator to support declarative validation
constraints via custom options defined in validate.proto. It generates
validation code (C header and source files) for protobuf messages.

Architecture Overview
---------------------
The module consists of several key components:

1. **ValidationRule**: A dataclass representing a single validation constraint
   (e.g., "field must be >= 10", "string must match email format").

2. **FieldValidator**: Parses and stores validation rules for a single field.
   It extracts rules from the FieldRules protobuf option and converts them
   into ValidationRule objects.

3. **MessageValidator**: Aggregates field validators for all fields in a message,
   including handling of oneof groups. Also manages message-level validation rules.

4. **ValidatorGenerator**: The main code generator that produces C header and
   source files containing validation functions. It uses the validators to
   emit appropriate C code for each constraint.

Main Flow
---------
1. Input: ProtoFile with messages containing validate.proto options
2. Parse validation rules from each field and message
3. Generate validation header (.h) with function declarations and documentation
4. Generate validation source (.c) with implementation of validation functions
5. Output: Validation code that can be compiled alongside generated pb.c/pb.h files

Rule Types
----------
- Numeric constraints: GT, GTE, LT, LTE, EQ, IN, NOT_IN
- String constraints: MIN_LEN, MAX_LEN, PREFIX, SUFFIX, CONTAINS, ASCII
- Format validators: EMAIL, HOSTNAME, IP, IPV4, IPV6
- Repeated field constraints: MIN_ITEMS, MAX_ITEMS, UNIQUE, ITEMS
- Enum constraints: DEFINED_ONLY, IN, NOT_IN
- Message-level: REQUIRED, ONEOF_REQUIRED, and custom message rules
- Special: ANY_IN, ANY_NOT_IN for google.protobuf.Any fields

Code Generation Strategy
------------------------
The generator produces C code that uses macros from pb_validate.h to:
- Navigate field paths for clear error messages
- Accumulate violations, exiting early on the first one
- Recursively validate nested message fields
- Handle optional fields and pointers appropriately
"""

import re
from collections import OrderedDict
from typing import Any, List, Optional
from c_layout import (RUNTIME_CHECK, c_block, lib_include)  # noqa: E402
from rule_model import (FieldContext, FieldValidator, IRBuilder, MessageValidator, RULE_ASCII, RULE_CONTAINS,  # noqa: E402
                        RULE_EMAIL, RULE_ENUM_DEFINED, RULE_EQ, RULE_GT, RULE_GTE, RULE_HOSTNAME, RULE_IN,
                        RULE_IP, RULE_IPV4, RULE_IPV6, RULE_ITEMS, RULE_LT, RULE_LTE, RULE_MAP_ENTRIES,
                        RULE_MAX_ITEMS, RULE_MAX_LEN, RULE_MIN_ITEMS, RULE_MIN_LEN, RULE_NOT_IN,
                        RULE_NO_SPARSE, RULE_ONEOF_REQUIRED, RULE_PREFIX, RULE_REQUIRED, RULE_SUFFIX,
                        RULE_UNIQUE, ValidationRule, ValidationRuleNotImplementedError, _escape_for_comment)
from emitters import (_emitter_registry)  # noqa: E402

class ValidatorGenerator:
    """
    Generates C validation code for protobuf messages.
    
    This is the main code generator class. It takes parsed validation rules
    and produces C header and source files containing validation functions.
    
    The generator supports two modes:
    - Normal mode: Validation stops at the first violation
    - Bypass mode: All violations are collected before returning
    
    Attributes:
        proto_file: The ProtoFile object being processed
        validators: OrderedDict mapping message names to MessageValidator objects
        validate_enabled: Whether validation is enabled for this proto file
    """
    
    # =========================================================================
    # Class Constants: Rule Type to C Enum Mappings
    # =========================================================================
    # These mappings centralize the conversion from Python rule types to C macro names.
    # By defining them as class constants, we ensure consistency across all code paths.
    
    NUMERIC_RULE_TO_C_ENUM = {
        RULE_GT: 'PB_VALIDATE_RULE_GT',
        RULE_GTE: 'PB_VALIDATE_RULE_GTE',
        RULE_LT: 'PB_VALIDATE_RULE_LT',
        RULE_LTE: 'PB_VALIDATE_RULE_LTE',
        RULE_EQ: 'PB_VALIDATE_RULE_EQ',
    }
    
    STRING_FORMAT_RULE_TO_C_ENUM = {
        RULE_EMAIL: 'PB_VALIDATE_RULE_EMAIL',
        RULE_HOSTNAME: 'PB_VALIDATE_RULE_HOSTNAME',
        RULE_IP: 'PB_VALIDATE_RULE_IP',
        RULE_IPV4: 'PB_VALIDATE_RULE_IPV4',
        RULE_IPV6: 'PB_VALIDATE_RULE_IPV6',
        RULE_ASCII: 'PB_VALIDATE_RULE_ASCII',
        RULE_PREFIX: 'PB_VALIDATE_RULE_PREFIX',
        RULE_SUFFIX: 'PB_VALIDATE_RULE_SUFFIX',
        RULE_CONTAINS: 'PB_VALIDATE_RULE_CONTAINS',
    }
    
    # Macros for callback string validation
    # Macros for normal string validation
    NORMAL_STRING_FORMAT_MACROS = {
        RULE_EMAIL: 'PB_VALIDATE_STR_EMAIL',
        RULE_HOSTNAME: 'PB_VALIDATE_STR_HOSTNAME',
        RULE_IP: 'PB_VALIDATE_STR_IP',
        RULE_IPV4: 'PB_VALIDATE_STR_IPV4',
        RULE_IPV6: 'PB_VALIDATE_STR_IPV6',
    }
    
    def __init__(self, proto_file: Any):
        """
        Initialize the ValidatorGenerator.
        
        Args:
            proto_file: The ProtoFile object containing messages to validate
        """
        self.proto_file = proto_file
        self.validators = OrderedDict()
        # Optional callable(ctype) -> bool answering whether a message from
        # another file gets a validator; set by the plugin.  Without it,
        # messages of other files are assumed to have one.
        self.external_has_validator = None

        # Pipeline components
        self.ir_builder = IRBuilder(proto_file)
        self.emitter_registry = _emitter_registry
        
        # Check if validation is enabled in file options
        self.validate_enabled = False
        if hasattr(proto_file, 'file_options') and hasattr(proto_file.file_options, 'validate'):
            self.validate_enabled = proto_file.file_options.validate
    
    def add_message_validator(self, message: Any, message_rules: Optional[Any] = None) -> None:
        """
        Add a validator for a message (only if it has validation rules).
        
        Args:
            message: The protobuf message descriptor
            message_rules: The MessageRules option from validate.proto (or None)
        """
        validator = MessageValidator(message, message_rules, self.proto_file)
        if validator.field_validators or validator.message_rules or validator.oneof_validators:
            self.validators[str(message.name)] = validator
    
    def force_add_message_validator(self, message: Any, message_rules: Optional[Any] = None) -> None:
        """
        Force add a validator for a message, even if no rules are present.
        
        This is used when a message has no rules of its own but still needs a
        validator function generated for it.
        We still generate a validation function that always returns true.
        
        Args:
            message: The protobuf message descriptor
            message_rules: The MessageRules option from validate.proto (or None)
        """
        validator = MessageValidator(message, message_rules, self.proto_file)
        self.validators[str(message.name)] = validator
    
    # =========================================================================
    # Documentation and Display Helpers
    # =========================================================================

    def _rule_to_text(self, rule: ValidationRule) -> str:
        """Convert a single ValidationRule into a human-friendly sentence fragment."""
        rt = rule.rule_type
        p = rule.params or {}
        val = p.get('value')
        values = p.get('values')
        def list_render(vals):
            try:
                return '{' + ', '.join(str(v) for v in vals) + '}'
            except Exception:
                return '{...}'
        if rt == RULE_REQUIRED:
            return 'required'
        if rt == RULE_ONEOF_REQUIRED:
            return 'one-of group requires a value'
        if rt == RULE_EQ:
            return f'== {val}'
        if rt == RULE_GT:
            return f'> {val}'
        if rt == RULE_GTE:
            return f'>= {val}'
        if rt == RULE_LT:
            return f'< {val}'
        if rt == RULE_LTE:
            return f'<= {val}'
        if rt == RULE_IN:
            return f'in {list_render(values)}'
        if rt == RULE_NOT_IN:
            return f'not in {list_render(values)}'
        if rt == RULE_MIN_LEN:
            return f'min length {val}'
        if rt == RULE_MAX_LEN:
            return f'max length {val}'
        if rt == RULE_PREFIX:
            return f'prefix "{_escape_for_comment(val)}"'
        if rt == RULE_SUFFIX:
            return f'suffix "{_escape_for_comment(val)}"'
        if rt == RULE_CONTAINS:
            return f'contains "{_escape_for_comment(val)}"'
        if rt == RULE_ASCII:
            return 'ASCII only'
        if rt == RULE_EMAIL:
            return 'valid email address'
        if rt == RULE_HOSTNAME:
            return 'valid hostname'
        if rt == RULE_IP:
            return 'valid IP address'
        if rt == RULE_IPV4:
            return 'valid IPv4 address'
        if rt == RULE_IPV6:
            return 'valid IPv6 address'
        if rt == RULE_ENUM_DEFINED:
            return 'must be a defined enum value'
        if rt == RULE_MIN_ITEMS:
            return f'at least {val} items'
        if rt == RULE_MAX_ITEMS:
            return f'at most {val} items'
        if rt == RULE_UNIQUE:
            return 'items must be unique'
        if rt == RULE_ITEMS:
            return 'per-item validation rules'
        if rt == RULE_NO_SPARSE:
            return 'no sparse map entries'
        if rt == RULE_MAP_ENTRIES:
            return 'per-entry key/value rules'
        # Fallback
        return rt.replace('_', ' ').lower()

    def _format_field_constraints(self, field_name: str, fv: 'FieldValidator') -> str:
        """Produce a concise, pretty description line for a field and its constraints."""
        try:
            # Group multiple fragments with semicolons
            parts = [self._rule_to_text(r) for r in fv.rules]
            # Deduplicate while preserving order
            seen = set()
            uniq = []
            for t in parts:
                if t not in seen:
                    seen.add(t)
                    uniq.append(t)
            if not uniq:
                return f"- {field_name}: no constraints"
            return f"- {field_name}: " + '; '.join(uniq)
        except Exception:
            return f"- {field_name}: (constraints unavailable)"
    # ----------------------------------------------------------------------

    def _collect_validation_dependencies(self):
        """
        Collect validation header dependencies from imported proto files.
        
        Returns a set of validation header paths that need to be included.
        These are proto files that define messages used as field types in this file.
        """
        dep_headers = set()
        
        # Iterate through all validators and their messages
        for validator in self.validators.values():
            message = validator.message
            # Check all fields in the message, including the members of oneofs:
            # a oneof arm of a type from another file is validated by calling
            # that file's validator too.
            fields = []
            for field in getattr(message, 'fields', []):
                if getattr(field, 'pbtype', None) == 'oneof':
                    fields.extend(getattr(field, 'fields', []) or [])
                else:
                    fields.append(field)
            for field in fields:
                try:
                    # Only consider message-type fields
                    if getattr(field, 'pbtype', None) not in ('MESSAGE', 'MSG_W_CB'):
                        continue
                    
                    # Get the message type
                    submsg_ctype = getattr(field, 'ctype', None)
                    if not submsg_ctype:
                        continue
                    
                    # Skip google.protobuf.Any - it doesn't have validation
                    submsg_ctype_str = str(submsg_ctype).lower()
                    if 'google' in submsg_ctype_str and 'protobuf' in submsg_ctype_str:
                        continue
                    
                    # Look up the message in dependencies
                    dep_msg = self.proto_file.dependencies.get(str(submsg_ctype))
                    if dep_msg and hasattr(dep_msg, 'protofile'):
                        dep_protofile = dep_msg.protofile
                        # Only add if it's from a different proto file
                        if dep_protofile != self.proto_file:
                            dep_name = dep_protofile.fdesc.name
                            if dep_name.endswith('.proto'):
                                dep_name = dep_name[:-6]
                            dep_headers.add(dep_name)
                except Exception:
                    # Skip fields with unexpected structure
                    pass
        
        return sorted(dep_headers)

    def _nested_validation_lines(self, field: Any, field_name: str,
                                 oneof_name: Optional[str] = None,
                                 is_anonymous: bool = False) -> List[str]:
        """C statements that validate the sub-message(s) stored in ``field``.

        Covers singular, optional, pointer, repeated, fixed_count, map and
        oneof-arm sub-messages.  google.protobuf.Any/Timestamp have their own
        rules and are skipped.
        """
        pbtype = getattr(field, 'pbtype', None)
        ctype = getattr(field, 'ctype', None)
        if pbtype not in ('MESSAGE', 'MSG_W_CB') or not ctype:
            return []
        lowered = str(ctype).lower()
        if 'google' in lowered and 'protobuf' in lowered and ('any' in lowered or 'timestamp' in lowered):
            return []

        sub_func = 'pb_validate_' + str(ctype).replace('.', '_')
        allocation = getattr(field, 'allocation', None)
        rules = getattr(field, 'rules', None)

        if oneof_name is not None:
            if not self._has_validator(ctype):
                return []
            if is_anonymous:
                return ['    PB_VALIDATE_NESTED_MSG(ctx, %s, msg, %s, violations);\n' % (sub_func, field_name)]
            return ['    PB_VALIDATE_NESTED_MSG_ONEOF(ctx, %s, msg, %s, %s, violations);\n'
                    % (sub_func, oneof_name, field_name)]

        if rules in ('REPEATED', 'FIXARRAY'):
            if allocation != 'STATIC':
                return []
            is_map = False
            entry = self._message_by_name(ctype)
            if entry is not None and getattr(getattr(entry, 'desc', None), 'options', None) is not None \
                    and entry.desc.options.map_entry:
                # map<K, V>: validate the values that are messages.
                value_field = next((f for f in entry.fields if getattr(f, 'name', '') == 'value'), None)
                if value_field is None:
                    return []
                inner = self._nested_validation_lines(value_field, 'value')
                if not inner or getattr(value_field, 'pbtype', None) not in ('MESSAGE', 'MSG_W_CB'):
                    return []
                sub_func = 'pb_validate_' + str(getattr(value_field, 'ctype')).replace('.', '_')
                is_map = True
            elif not self._has_validator(ctype):
                return []
            # One macro per shape, so no call has an empty argument.
            if is_map and rules == 'REPEATED':
                macro = 'PB_VALIDATE_NESTED_MAP_VALUES'
            elif is_map:
                return ['    PB_VALIDATE_NESTED_MSG_ITEMS(ctx, %s, msg->%s[pbv_i].value, '
                        'sizeof(msg->%s) / sizeof(msg->%s[0]), violations);\n'
                        % (sub_func, field_name, field_name, field_name)]
            elif rules == 'FIXARRAY':
                macro = 'PB_VALIDATE_NESTED_MSG_FIXARRAY'
            else:
                macro = 'PB_VALIDATE_NESTED_MSG_REPEATED'
            return ['    %s(ctx, %s, msg, %s, violations);\n' % (macro, sub_func, field_name)]

        if not self._has_validator(ctype):
            return []
        if allocation == 'POINTER':
            return ['    PB_VALIDATE_NESTED_MSG_POINTER(ctx, %s, msg, %s, violations);\n' % (sub_func, field_name)]
        if rules == 'OPTIONAL':
            return ['    PB_VALIDATE_NESTED_MSG_OPTIONAL(ctx, %s, msg, %s, violations);\n' % (sub_func, field_name)]
        return ['    PB_VALIDATE_NESTED_MSG(ctx, %s, msg, %s, violations);\n' % (sub_func, field_name)]

    def _message_by_name(self, ctype: Any) -> Optional[Any]:
        for message in getattr(self.proto_file, 'messages', []) or []:
            if str(message.name) == str(ctype):
                return message
        return None

    def _has_validator(self, ctype: Any) -> bool:
        """Will a pb_validate_<ctype>() exist?

        Messages of this file have one if they are in self.validators; for
        messages of other files ask external_has_validator, or assume so.
        """
        if str(ctype) in self.validators:
            return True
        if self._message_by_name(ctype) is not None:
            return False
        if self.external_has_validator is not None:
            return self.external_has_validator(ctype)
        return True

    def generate_header(self):
        """Generate validation header file content."""
        if not self.validators:
            return
        
        # Extract base name without .proto extension
        base_name = self.proto_file.fdesc.name
        if base_name.endswith('.proto'):
            base_name = base_name[:-6]
        
        guard = 'PB_VALIDATE_%s_INCLUDED' % base_name.upper().replace('.', '_').replace('/', '_').replace('-', '_')
        
        yield '/* Validation header for %s */\n' % self.proto_file.fdesc.name
        yield '#ifndef %s\n' % guard
        yield '#define %s\n' % guard
        yield '\n'
        yield lib_include('pb_validate.h')
        yield RUNTIME_CHECK
        yield '#include "%s.pb.h"\n' % base_name
        
        # Include validation headers for imported proto files
        dep_headers = self._collect_validation_dependencies()
        for dep_header in dep_headers:
            yield '#include "%s_validate.h"\n' % dep_header
        
        yield '\n'
        yield '#ifdef __cplusplus\n'
        yield 'extern "C" {\n'
        yield '#endif\n'
        yield '\n'
        
        # Generate validation function declarations with rich Doxygen
        for msg_name, validator in self.validators.items():
            # Use the C struct name from the message
            struct_name = str(validator.message.name)
            func_name = 'pb_validate_' + struct_name.replace('.', '_')
            # Build field description list
            try:
                all_field_names = []
                for f in getattr(validator.message, 'fields', []) or []:
                    fname = getattr(f, 'name', None)
                    if fname:
                        all_field_names.append(fname)
                validated_field_names = list(validator.field_validators.keys())
                fields_without = [fn for fn in all_field_names if fn not in validated_field_names]
            except Exception:
                all_field_names, fields_without = [], []

            # Doxygen header
            yield '/**\n'
            yield ' * @brief Validate %s message.\n' % struct_name
            yield ' *\n'
            yield ' * Fields and constraints:\n'
            # With constraints
            for fname, fv in validator.field_validators.items():
                desc = _escape_for_comment(self._format_field_constraints(fname, fv))
                yield ' * %s\n' % desc
            # Oneof validators
            for oneof_name, oneof_data in validator.oneof_validators.items():
                yield ' * - oneof %s:\n' % _escape_for_comment(oneof_name)
                for member_field, member_fv in oneof_data['members']:
                    desc = _escape_for_comment(self._format_field_constraints(member_field.name, member_fv))
                    yield ' *   %s\n' % desc
            # Without constraints
            for fname in fields_without:
                # Skip oneof names as they are already documented above
                if fname in validator.oneof_validators:
                    continue
                field_obj = next((f for f in getattr(validator.message, 'fields', []) or []
                                  if getattr(f, 'name', None) == fname), None)
                try:
                    nested = field_obj is not None and bool(self._nested_validation_lines(field_obj, fname))
                except Exception:
                    nested = False
                if nested:
                    yield ' * - %s: no rules of its own; each %s is validated\n' % (
                        _escape_for_comment(fname), _escape_for_comment(str(field_obj.ctype)))
                else:
                    yield ' * - %s: no constraints\n' % _escape_for_comment(fname)
            # Message-level rules summary
            if validator.message_rules:
                yield ' *\n'
                yield ' * Message-level rules:\n'
                for mr in validator.message_rules:
                    try:
                        if mr.rule_type == 'REQUIRES':
                            yield ' * - requires field "%s"\n' % _escape_for_comment(mr.params.get('field', ''))
                        elif mr.rule_type == 'MUTEX':
                            fields = mr.params.get('fields', [])
                            yield ' * - mutual exclusion among %s\n' % _escape_for_comment('{'+', '.join(fields)+'}')
                        elif mr.rule_type == 'AT_LEAST':
                            n = mr.params.get('n', 1)
                            fields = mr.params.get('fields', [])
                            yield ' * - at least %s of %s must be set\n' % (str(n), _escape_for_comment('{'+', '.join(fields)+'}'))
                        else:
                            yield ' * - %s\n' % _escape_for_comment(mr.rule_type.lower())
                    except Exception:
                        yield ' * - (message rule)\n'
            yield ' *\n'
            yield ' * @param msg [in] Pointer to %s instance to validate.\n' % struct_name
            yield ' * @param violations [out] Violations accumulator for collecting errors.\n'
            
            yield ' * @return true if valid, false otherwise.\n'
            yield ' */\n'
            
            yield 'bool %s(const %s *msg, pb_violations_t *violations);\n' % (func_name, struct_name)
            
            yield '\n'
        
        yield '#ifdef __cplusplus\n'
        yield '} /* extern "C" */\n'
        yield '#endif\n'
        yield '\n'
        yield '#endif /* %s */\n' % guard
    
    # =========================================================================
    # IR-Based Source Generation (AUTHORITATIVE PIPELINE)
    # =========================================================================
    # All code generation routes through the IR pipeline:
    #   ValidationRule → IRBuilder → RuleIR → RuleEmitter → C code
    
    def _emit_rule(self, rule: ValidationRule, field: Any,
                   is_oneof: bool = False, oneof_name: str = '',
                   is_anonymous: bool = False, message_name: Optional[str] = None) -> str:
        """
        Emit C code for a single validation rule using the IR pipeline.

        This is the SINGLE authoritative code generation path. All rule emission
        must go through this method.

        Args:
            rule: The ValidationRule to emit
            field: The field descriptor
            is_oneof: Whether this field is in a oneof group
            oneof_name: Name of the oneof group (if applicable)
            is_anonymous: Whether the oneof is anonymous
            message_name: Name of the owning message, used only to make a
                ValidationRuleNotImplementedError (if raised) easier to locate

        Returns:
            C code string for this rule
        """
        # Build field context
        if is_oneof:
            context = FieldContext.for_oneof_member(field, oneof_name, is_anonymous)
        else:
            context = FieldContext.for_regular_field(field)

        # Build RuleIR
        rule_ir = self.ir_builder.build_rule_ir(rule, context)

        # Emit via emitter registry
        return self.emitter_registry.emit(rule_ir, self.proto_file, message_name)

    def _emit_map_entries(self, rule: ValidationRule, field: Any, message_name: str) -> str:
        """C code applying map.keys / map.values to every entry of a map field.

        The entry's key and value are ordinary fields of the synthetic
        <Field>Entry message, so their rules go through the normal emitters;
        the generated code then reads them from the current entry
        (``pbv_entry``) instead of from ``msg``.
        """
        field_name = getattr(field, 'name', '')
        ctype = getattr(field, 'ctype', None)
        entry = self._message_by_name(ctype)
        desc = getattr(entry, 'desc', None)
        if entry is None or desc is None or not desc.options.map_entry \
                or getattr(field, 'allocation', None) != 'STATIC' \
                or getattr(field, 'rules', None) != 'REPEATED':
            raise ValidationRuleNotImplementedError(
                'validate.proto option "map.keys"/"map.values" on message "%s" field "%s" '
                'needs a statically allocated map (give it a max_count).'
                % (message_name, field_name))

        body = ''
        for part in ('key', 'value'):
            part_rules = rule.params.get(part + '_rules')
            if part_rules is None:
                continue
            sub_field = next((f for f in entry.fields if getattr(f, 'name', '') == part), None)
            sub_rules = FieldValidator(sub_field, part_rules, self.proto_file).rules
            if not sub_rules:
                continue
            code = ''.join(self._emit_rule(r, sub_field, message_name=message_name)
                           for r in sub_rules)
            if not code.strip():
                raise ValidationRuleNotImplementedError(
                    'validate.proto option "map.%ss" on message "%s" field "%s" produced '
                    'no check. Remove it from the .proto, or wait for support.'
                    % (part, message_name, field_name))
            code = re.sub(r'\bmsg\b(?=\s*(->|,))', 'pbv_entry', code)
            body += '            PB_VALIDATE_FIELD_BEGIN(ctx, "%s");\n' % part
            body += c_block(code, 12)
            body += '            PB_VALIDATE_FIELD_END(ctx);\n'
        if not body:
            return ''

        out = '        for (pb_size_t pbv_mi = 0; pbv_mi < msg->%s_count; ++pbv_mi) {\n' % field_name
        out += '            const %s *pbv_entry = &msg->%s[pbv_mi];\n' % (ctype, field_name)
        out += '            PB_VALIDATE_PUSH_INDEX(ctx, pbv_mi);\n'
        out += body
        out += '            PB_VALIDATE_POP_INDEX(ctx);\n'
        out += '        }\n'
        return out

    def generate_source(self):
        """Generate validation source file content."""
        if not self.validators:
            return
        # Extract base name without .proto extension
        base_name = self.proto_file.fdesc.name
        if base_name.endswith('.proto'):
            base_name = base_name[:-6]

        yield '/* Validation implementation for %s */\n' % self.proto_file.fdesc.name
        yield '#include "%s_validate.h"\n' % base_name
        yield '#include <string.h>\n'
        yield '\n'
        
        # Generate static rule data
        for msg_name, validator in self.validators.items():
            # Use the C struct name from the message
            struct_name = str(validator.message.name)
            func_name = 'pb_validate_' + struct_name.replace('.', '_')
            
            # Generate validation function
            yield 'bool %s(const %s *msg, pb_violations_t *violations)\n' % (func_name, struct_name)
            
            # Comments in the body would only repeat the code (each field is
            # named by PB_VALIDATE_FIELD_BEGIN); the rules are documented once,
            # in the Doxygen block of the header.
            yield '{\n'
            yield '    PB_VALIDATE_BEGIN(ctx, %s, msg, violations);\n' % struct_name
            yield '\n'
            
            # Generate field validations
            for field_name, field_validator in validator.field_validators.items():
                field = field_validator.field
                
                yield '    PB_VALIDATE_FIELD_BEGIN(ctx, "%s");\n' % field_name

                for rule in field_validator.rules:
                    if rule.rule_type == RULE_MAP_ENTRIES:
                        yield c_block(self._emit_map_entries(rule, field, struct_name), 4)
                    else:
                        yield c_block(self._emit_rule(rule, field, message_name=struct_name), 4)

                # Automatic recursion for nested message fields
                try:
                    yield c_block(''.join(self._nested_validation_lines(field, field_name)), 4)
                except Exception:
                    # If field shape is unexpected, skip recursion silently to avoid crashes
                    pass

                yield '    PB_VALIDATE_FIELD_END(ctx);\n'
                yield '\n'
            
            # Also recurse into message-typed fields that have no field-level rules
            try:
                field_names_with_rules = set(validator.field_validators.keys())
            except Exception:
                field_names_with_rules = set()
            for f in getattr(validator.message, 'fields', []):
                try:
                    if getattr(f, 'name', None) in field_names_with_rules:
                        continue
                    if getattr(f, 'pbtype', None) not in ('MESSAGE', 'MSG_W_CB'):
                        continue
                    fname = getattr(f, 'name')
                    submsg_ctype = getattr(f, 'ctype', None)
                    if not submsg_ctype:
                        continue
                    # Skip google.protobuf.Any and google.protobuf.Timestamp - they have special validation
                    submsg_ctype_str = str(submsg_ctype).lower()
                    if 'google' in submsg_ctype_str and 'protobuf' in submsg_ctype_str and ('any' in submsg_ctype_str or 'timestamp' in submsg_ctype_str):
                        continue
                    
                    lines = self._nested_validation_lines(f, fname)
                    if not lines:
                        continue
                    yield '    PB_VALIDATE_FIELD_BEGIN(ctx, "%s");\n' % fname
                    yield c_block(''.join(lines), 4)
                    yield '    PB_VALIDATE_FIELD_END(ctx);\n'
                    yield '\n'
                except Exception:
                    # Skip if field metadata is unexpected
                    pass

            # Generate oneof member validations (switch-based)
            for oneof_name, oneof_data in validator.oneof_validators.items():
                oneof_obj = oneof_data['oneof']
                members = oneof_data['members']  # List of (field, FieldValidator) tuples
                
                yield '    PB_VALIDATE_ONEOF_BEGIN(ctx, msg, %s)\n' % oneof_name
                
                for member_field, member_fv in members:
                    field_name = member_field.name
                    # Generate case for this oneof member
                    # Tag constant format: <MESSAGE_NAME>_<field_name>_tag
                    tag_name = '%s_%s_tag' % (struct_name, field_name)
                    yield '    PB_VALIDATE_ONEOF_CASE(%s)\n' % tag_name
                    yield '        PB_VALIDATE_FIELD_BEGIN(ctx, "%s");\n' % field_name
                    
                    # Get anonymous flag for the oneof
                    is_anonymous = getattr(oneof_obj, 'anonymous', False)
                    
                    for rule in member_fv.rules:
                        yield c_block(self._emit_rule(rule, member_field, is_oneof=True,
                                                      oneof_name=oneof_name, is_anonymous=is_anonymous,
                                                      message_name=struct_name), 8)

                    yield '        PB_VALIDATE_FIELD_END(ctx);\n'
                    yield '    PB_VALIDATE_ONEOF_CASE_END()\n'
                
                yield '    PB_VALIDATE_ONEOF_DEFAULT()\n'
                yield '    PB_VALIDATE_ONEOF_END()\n'
                yield '\n'

            # Sub-messages held in oneof arms are validated while their arm is
            # selected, whether or not the arm has rules of its own.
            for oneof in getattr(validator.message, 'fields', []):
                if getattr(oneof, 'pbtype', None) != 'oneof':
                    continue
                is_anonymous = getattr(oneof, 'anonymous', False)
                arms = []
                for member in getattr(oneof, 'fields', []) or []:
                    try:
                        lines = self._nested_validation_lines(
                            member, member.name, oneof_name=oneof.name, is_anonymous=is_anonymous)
                    except Exception:
                        lines = []
                    if lines:
                        arms.append((member, lines))
                if not arms:
                    continue
                yield '    PB_VALIDATE_ONEOF_BEGIN(ctx, msg, %s)\n' % oneof.name
                for member, lines in arms:
                    yield '    PB_VALIDATE_ONEOF_CASE(%s_%s_tag)\n' % (struct_name, member.name)
                    yield '        PB_VALIDATE_FIELD_BEGIN(ctx, "%s");\n' % member.name
                    yield c_block(''.join(lines), 8)
                    yield '        PB_VALIDATE_FIELD_END(ctx);\n'
                    yield '    PB_VALIDATE_ONEOF_CASE_END()\n'
                yield '    PB_VALIDATE_ONEOF_DEFAULT()\n'
                yield '    PB_VALIDATE_ONEOF_END()\n'
                yield '\n'

            # Generate message-level validations
            for rule in validator.message_rules:
                yield c_block(self._generate_message_rule_check(validator.message, rule), 4)
                yield '\n'
            
            yield '    PB_VALIDATE_END(ctx, violations);\n'
            yield '}\n'
            yield '\n'

    
    def _escape_c_string(self, s: str) -> str:
        """
        Escape a string for use in C code.
        
        Handles all standard C escape sequences to ensure safe embedding
        of arbitrary string values in generated C code.
        """
        result = s.replace('\\', '\\\\')  # Must be first to avoid double-escaping
        result = result.replace('"', '\\"')
        result = result.replace('\n', '\\n')
        result = result.replace('\r', '\\r')
        result = result.replace('\t', '\\t')
        result = result.replace('\0', '\\0')
        result = result.replace('\v', '\\v')
        result = result.replace('\f', '\\f')
        result = result.replace('\b', '\\b')
        result = result.replace('\a', '\\a')
        return result
    # =========================================================================
    # Message-Level Rule Code Generators
    # =========================================================================
    # These methods generate C code for message-level validation rules
    # (requires, mutex, at_least constraints).

    def _generate_message_rule_check(self, message: Any, rule: ValidationRule) -> str:
        """
        Generate code for a message-level validation rule using the IR pipeline.

        Args:
            message: The message descriptor
            rule: The ValidationRule to generate code for

        Returns:
            C code string implementing the rule check

        Raises:
            ValidationRuleNotImplementedError: if no emitter is registered for
                this rule type (see RuleEmitterRegistry.emit) -- generation
                fails loudly rather than silently producing no enforcement.
        """
        context = FieldContext.for_message_rule()
        rule_ir = self.ir_builder.build_rule_ir(rule, context)
        return self.emitter_registry.emit(rule_ir, self.proto_file, str(message.name))
