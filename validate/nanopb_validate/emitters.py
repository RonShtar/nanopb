"""C emission per rule type: one RuleEmitter per family (numeric, string, bytes, repeated, any,
timestamp, enum, ...) and the registry that picks the emitter for a rule.
"""

from typing import Any, Dict, List, Optional
from abc import ABC, abstractmethod
from rule_model import (RULE_ANY_IN, RULE_ANY_NOT_IN, RULE_ASCII, RULE_CONTAINS, RULE_EMAIL,  # noqa: E402
                        RULE_ENUM_DEFINED, RULE_EQ, RULE_GT, RULE_GTE, RULE_HOSTNAME, RULE_IN, RULE_IP,
                        RULE_IPV4, RULE_IPV6, RULE_ITEMS, RULE_LT, RULE_LTE, RULE_MAX_ITEMS, RULE_MAX_LEN,
                        RULE_MIN_ITEMS, RULE_MIN_LEN, RULE_NOT_IN, RULE_ONEOF_REQUIRED, RULE_PREFIX,
                        RULE_REQUIRED, RULE_SUFFIX, RULE_TIMESTAMP_GT_NOW, RULE_TIMESTAMP_LT_NOW,
                        RULE_TIMESTAMP_WITHIN, RULE_UNIQUE, RuleIR, ValidationRuleNotImplementedError,
                        _c_numeric_literal, _escape_c_string, _get_numeric_validator_info)

class RuleEmitter(ABC):
    """
    Abstract base class for rule emitters.
    
    RuleEmitters convert RuleIR objects into C code strings. Each concrete
    emitter handles a category of validation rules (e.g., numeric, string, repeated).
    
    The table-driven dispatch in RuleEmitterRegistry routes each rule to its
    appropriate emitter based on rule type.
    """
    
    @abstractmethod
    def emit(self, rule_ir: RuleIR, proto_file: Any) -> str:
        """
        Emit C code for a validation rule.
        
        Args:
            rule_ir: The RuleIR containing all emission context
            proto_file: The ProtoFile (for enum lookups, etc.)
            
        Returns:
            A string of C code implementing the validation
        """
        pass


class NumericRuleEmitter(RuleEmitter):
    """Emits C code for numeric comparison rules (GT, GTE, LT, LTE, EQ)."""
    
    RULE_TO_C_ENUM = {
        RULE_GT: 'PB_VALIDATE_RULE_GT',
        RULE_GTE: 'PB_VALIDATE_RULE_GTE',
        RULE_LT: 'PB_VALIDATE_RULE_LT',
        RULE_LTE: 'PB_VALIDATE_RULE_LTE',
        RULE_EQ: 'PB_VALIDATE_RULE_EQ',
    }
    
    def emit(self, rule_ir: RuleIR, proto_file: Any) -> str:
        if not rule_ir.c_type_info:
            return ''
        
        rule_enum = self.RULE_TO_C_ENUM.get(rule_ir.rule_type, '')
        if not rule_enum:
            return ''
        
        value = _c_numeric_literal(rule_ir.rule.params.get('value', 0),
                                   rule_ir.constraint_id.split('.', 1)[0])
        ctype = rule_ir.c_type_info.c_type
        validator_func = rule_ir.c_type_info.validator_func
        
        if rule_ir.context.is_oneof and not rule_ir.context.is_anonymous:
            return (
                '    PB_VALIDATE_ONEOF_NUMERIC(ctx, msg, %s, %s, %s, %s, %s, %s, "%s");\n'
            ) % (rule_ir.context.oneof_name, rule_ir.field_name, ctype, 
                 validator_func, rule_enum, value, rule_ir.constraint_id)
        else:
            return (
                '        PB_VALIDATE_NUMERIC_GENERIC(ctx, msg, %s, %s, %s, %s, %s, "%s");\n'
            ) % (rule_ir.field_name, ctype, validator_func, rule_enum, value, rule_ir.constraint_id)


class ConstValueRuleEmitter(RuleEmitter):
    """Emits C code for string/bytes const_value rules (RULE_EQ).

    Numeric, bool and enum const_value rules are handled by
    NumericRuleEmitter, which relies on a numeric C type being known for the
    field. String and bytes fields have no such numeric type, so they need
    their own emitter; without it the rule would be silently dropped.
    """

    def emit(self, rule_ir: RuleIR, proto_file: Any) -> str:
        ctx = rule_ir.context
        field_name = rule_ir.field_name
        pbtype = getattr(ctx.field, 'pbtype', None)
        value = rule_ir.rule.params.get('value', '')

        if pbtype == 'STRING':
            if isinstance(value, bytes):
                value = value.decode('utf-8', 'replace')
            escaped = _escape_c_string(value)
            if ctx.is_oneof and not ctx.is_anonymous:
                return '    PB_VALIDATE_ONEOF_STR_CONST(ctx, msg, %s, %s, "%s", "%s");\n' % (
                    ctx.oneof_name, field_name, escaped, rule_ir.constraint_id)
            return '        PB_VALIDATE_STR_CONST(ctx, msg, %s, "%s", "%s");\n' % (
                field_name, escaped, rule_ir.constraint_id)

        if pbtype == 'BYTES':
            if isinstance(value, str):
                value = value.encode('latin-1', 'replace')
            data = bytes(value)
            array_name = 'pbv_%s_const' % field_name
            byte_list = ', '.join('0x%02x' % byte for byte in data) if data else '0x00'
            code = '        static const uint8_t %s[] = { %s };\n' % (array_name, byte_list)
            if ctx.is_oneof and not ctx.is_anonymous:
                code += '    PB_VALIDATE_ONEOF_BYTES_CONST(ctx, msg, %s, %s, %s, %d, "%s");\n' % (
                    ctx.oneof_name, field_name, array_name, len(data), rule_ir.constraint_id)
            else:
                code += '        PB_VALIDATE_BYTES_CONST(ctx, msg, %s, %s, %d, "%s");\n' % (
                    field_name, array_name, len(data), rule_ir.constraint_id)
            return code

        return ''


class StringLengthRuleEmitter(RuleEmitter):
    """Emits C code for string length rules (MIN_LEN, MAX_LEN)."""
    
    def emit(self, rule_ir: RuleIR, proto_file: Any) -> str:
        is_min = rule_ir.rule_type == RULE_MIN_LEN
        length = rule_ir.rule.params.get('value', 0)
        field_name = rule_ir.field_name
        ctx = rule_ir.context
        
        is_string = 'string' in rule_ir.constraint_id
        
        if ctx.is_oneof and not ctx.is_anonymous:
            if is_string:
                macro = 'PB_VALIDATE_ONEOF_STR_MIN_LEN' if is_min else 'PB_VALIDATE_ONEOF_STR_MAX_LEN'
                return '    %s(ctx, msg, %s, %s, %d, "%s");\n' % (
                    macro, ctx.oneof_name, field_name, length, rule_ir.constraint_id)
            else:  # bytes
                macro = 'PB_VALIDATE_ONEOF_BYTES_MIN_LEN' if is_min else 'PB_VALIDATE_ONEOF_BYTES_MAX_LEN'
                return '    %s(ctx, msg, %s, %s, %d, "%s");\n' % (
                    macro, ctx.oneof_name, field_name, length, rule_ir.constraint_id)
        else:
            if is_string:
                macro = 'PB_VALIDATE_STR_MIN_LEN' if is_min else 'PB_VALIDATE_STR_MAX_LEN'
            else:
                macro = 'PB_VALIDATE_BYTES_MIN_LEN' if is_min else 'PB_VALIDATE_BYTES_MAX_LEN'
            return '        %s(ctx, msg, %s, %d, "%s");\n' % (
                macro, field_name, length, rule_ir.constraint_id)


class StringFormatRuleEmitter(RuleEmitter):
    """Emits C code for string format rules (EMAIL, HOSTNAME, IP, etc.)."""
    
    NORMAL_MACROS = {
        RULE_EMAIL: 'PB_VALIDATE_STR_EMAIL',
        RULE_HOSTNAME: 'PB_VALIDATE_STR_HOSTNAME',
        RULE_IP: 'PB_VALIDATE_STR_IP',
        RULE_IPV4: 'PB_VALIDATE_STR_IPV4',
        RULE_IPV6: 'PB_VALIDATE_STR_IPV6',
        RULE_ASCII: 'PB_VALIDATE_STR_ASCII',
    }
    
    RULE_TO_C_ENUM = {
        RULE_EMAIL: 'PB_VALIDATE_RULE_EMAIL',
        RULE_HOSTNAME: 'PB_VALIDATE_RULE_HOSTNAME',
        RULE_IP: 'PB_VALIDATE_RULE_IP',
        RULE_IPV4: 'PB_VALIDATE_RULE_IPV4',
        RULE_IPV6: 'PB_VALIDATE_RULE_IPV6',
        RULE_ASCII: 'PB_VALIDATE_RULE_ASCII',
    }
    
    def emit(self, rule_ir: RuleIR, proto_file: Any) -> str:
        ctx = rule_ir.context
        field_name = rule_ir.field_name
        
        if ctx.is_oneof and not ctx.is_anonymous:
            rule_enum = self.RULE_TO_C_ENUM.get(rule_ir.rule_type, '')
            if not rule_enum:
                return ''
            return '    PB_VALIDATE_ONEOF_STR_FORMAT(ctx, msg, %s, %s, %s, "%s", "String format validation failed");\n' % (
                ctx.oneof_name, field_name, rule_enum, rule_ir.constraint_id)
        else:
            macro = self.NORMAL_MACROS.get(rule_ir.rule_type, '')
            if not macro:
                return ''
            return '        %s(ctx, msg, %s, "%s");\n' % (macro, field_name, rule_ir.constraint_id)


class StringPatternRuleEmitter(RuleEmitter):
    """Emits C code for string pattern rules (PREFIX, SUFFIX, CONTAINS)."""
    
    NORMAL_MACROS = {
        RULE_PREFIX: 'PB_VALIDATE_STR_PREFIX',
        RULE_SUFFIX: 'PB_VALIDATE_STR_SUFFIX',
        RULE_CONTAINS: 'PB_VALIDATE_STR_CONTAINS',
    }
    
    def emit(self, rule_ir: RuleIR, proto_file: Any) -> str:
        ctx = rule_ir.context
        field_name = rule_ir.field_name
        pattern = _escape_c_string(rule_ir.rule.params.get('value', ''))
        
        if ctx.is_oneof and not ctx.is_anonymous:
            oneof_macro = {
                RULE_PREFIX: 'PB_VALIDATE_ONEOF_STR_PREFIX',
                RULE_SUFFIX: 'PB_VALIDATE_ONEOF_STR_SUFFIX',
                RULE_CONTAINS: 'PB_VALIDATE_ONEOF_STR_CONTAINS',
            }.get(rule_ir.rule_type, '')
            if oneof_macro:
                return '    %s(ctx, msg, %s, %s, "%s", "%s");\n' % (
                    oneof_macro, ctx.oneof_name, field_name, pattern, rule_ir.constraint_id)
        else:
            macro = self.NORMAL_MACROS.get(rule_ir.rule_type, '')
            if macro:
                return '        %s(ctx, msg, %s, "%s", "%s");\n' % (
                    macro, field_name, pattern, rule_ir.constraint_id)
        return ''


class RepeatedRuleEmitter(RuleEmitter):
    """Emits C code for repeated field rules (MIN_ITEMS, MAX_ITEMS, UNIQUE)."""
    
    def emit(self, rule_ir: RuleIR, proto_file: Any) -> str:
        field_name = rule_ir.field_name
        
        if rule_ir.rule_type == RULE_MIN_ITEMS:
            value = rule_ir.rule.params.get('value', 0)
            return '        PB_VALIDATE_MIN_ITEMS(ctx, msg, %s, %d, "%s");\n' % (
                field_name, value, rule_ir.constraint_id)
        
        elif rule_ir.rule_type == RULE_MAX_ITEMS:
            value = rule_ir.rule.params.get('value', 0)
            return '        PB_VALIDATE_MAX_ITEMS(ctx, msg, %s, %d, "%s");\n' % (
                field_name, value, rule_ir.constraint_id)
        
        elif rule_ir.rule_type == RULE_UNIQUE:
            pbtype = getattr(rule_ir.context.field, 'pbtype', None)
            if pbtype in ('MESSAGE', 'MSG_W_CB'):
                raise ValidationRuleNotImplementedError(
                    'validate.proto option "repeated.unique" on field "%s" has no C-runtime '
                    'enforcement for message items. Remove it from the .proto, or wait '
                    'for support.' % field_name)
            elif pbtype == 'STRING':
                return '        PB_VALIDATE_REPEATED_UNIQUE_STRING(ctx, msg, %s, "%s");\n' % (
                    field_name, rule_ir.constraint_id)
            elif pbtype == 'BYTES':
                return '        PB_VALIDATE_REPEATED_UNIQUE_BYTES(ctx, msg, %s, "%s");\n' % (
                    field_name, rule_ir.constraint_id)
            else:
                return '        PB_VALIDATE_REPEATED_UNIQUE_SCALAR(ctx, msg, %s, "%s");\n' % (
                    field_name, rule_ir.constraint_id)
        
        return ''


class ItemsRuleEmitter(RuleEmitter):
    """
    Emits C code for per-item validation on repeated fields (RULE_ITEMS).
    
    This emitter generates code that iterates over each element in a repeated
    field and applies the specified constraints (min_len, max_len, gt, lt, etc.).
    """
    
    # Mapping from rule types to C enum constants for numeric comparisons
    NUMERIC_RULE_TO_C_ENUM = {
        RULE_GT: 'PB_VALIDATE_RULE_GT',
        RULE_GTE: 'PB_VALIDATE_RULE_GTE',
        RULE_LT: 'PB_VALIDATE_RULE_LT',
        RULE_LTE: 'PB_VALIDATE_RULE_LTE',
        RULE_EQ: 'PB_VALIDATE_RULE_EQ',
    }
    
    # Mapping from string format rule types to C enum constants
    STRING_FORMAT_RULE_TO_C_ENUM = {
        RULE_EMAIL: 'PB_VALIDATE_RULE_EMAIL',
        RULE_HOSTNAME: 'PB_VALIDATE_RULE_HOSTNAME',
        RULE_IP: 'PB_VALIDATE_RULE_IP',
        RULE_IPV4: 'PB_VALIDATE_RULE_IPV4',
        RULE_IPV6: 'PB_VALIDATE_RULE_IPV6',
        RULE_ASCII: 'PB_VALIDATE_RULE_ASCII',
    }
    
    def emit(self, rule_ir: RuleIR, proto_file: Any) -> str:
        """
        Emit C code for per-item validation on a repeated field.
        
        Args:
            rule_ir: The RuleIR containing item_rules in params
            proto_file: The ProtoFile for context
            
        Returns:
            C code string implementing per-item validation
        """
        field_name = rule_ir.field_name
        item_rules = rule_ir.rule.params.get('item_rules', [])
        if not item_rules:
            return ''
        
        field = rule_ir.context.field
        pbtype = getattr(field, 'pbtype', None)
        code = ''
        
        for item_rule in item_rules:
            rule_type = item_rule.get('rule')
            constraint_id = item_rule.get('constraint_id', '')
            emitted = len(code)

            if rule_type == RULE_EQ and pbtype == 'STRING':
                expected = item_rule.get('value', '')
                if isinstance(expected, bytes):
                    expected = expected.decode('utf-8', 'replace')
                code += '        /* repeated.items string.const validation */\n'
                code += '        for (pb_size_t pbv_i = 0; pbv_i < msg->%s_count; ++pbv_i) {\n' % field_name
                code += '            PB_VALIDATE_PUSH_INDEX(ctx, pbv_i);\n'
                code += '            if (strcmp(msg->%s[pbv_i], "%s") != 0) {\n' % (field_name, _escape_c_string(expected))
                code += '                PB_VALIDATE_RECORD(ctx, "%s", "Value must equal specified constant");\n' % constraint_id
                code += '                if (PB_VALIDATE_SHOULD_EXIT(ctx)) { PB_VALIDATE_POP_INDEX(ctx); return false; }\n'
                code += '            }\n'
                code += '            PB_VALIDATE_POP_INDEX(ctx);\n'
                code += '        }\n'

            elif rule_type == RULE_MIN_LEN and pbtype == 'STRING':
                value = item_rule.get('value', 0)
                code += '        PB_VALIDATE_REPEATED_ITEMS_STR_MIN_LEN(ctx, msg, %s, %d, "%s");\n' % (
                    field_name, value, constraint_id)
            
            elif rule_type == RULE_MAX_LEN and pbtype == 'STRING':
                value = item_rule.get('value', 0)
                code += '        PB_VALIDATE_REPEATED_ITEMS_STR_MAX_LEN(ctx, msg, %s, %d, "%s");\n' % (
                    field_name, value, constraint_id)
            
            elif rule_type in (RULE_GT, RULE_GTE, RULE_LT, RULE_LTE, RULE_EQ):
                # Extract just the type name from the constraint_id (e.g., 'int32' from 'int32.gt')
                type_name = constraint_id.split('.', 1)[0]
                value = _c_numeric_literal(item_rule.get('value', 0), type_name)
                ctype, func = _get_numeric_validator_info(type_name)
                if ctype and func:
                    rule_enum = self.NUMERIC_RULE_TO_C_ENUM.get(rule_type)
                    if rule_enum:
                        code += '        PB_VALIDATE_REPEATED_ITEMS_NUMERIC(ctx, msg, %s, %s, %s, %s, %s, "%s");\n' % (
                            field_name, ctype, func, rule_enum, value, constraint_id)
            
            elif rule_type == RULE_PREFIX and pbtype == 'STRING':
                prefix = item_rule.get('value', '')
                code += '        /* repeated.items string.prefix validation */\n'
                code += '        for (pb_size_t pbv_i = 0; pbv_i < msg->%s_count; ++pbv_i) {\n' % field_name
                code += '            const char *pbv_prefix = "%s";\n' % prefix
                code += '            PB_VALIDATE_PUSH_INDEX(ctx, pbv_i);\n'
                code += '            if (!pb_validate_string_inline(msg->%s[pbv_i], (pb_size_t)strlen(msg->%s[pbv_i]), pbv_prefix, PB_VALIDATE_RULE_PREFIX)) {\n' % (field_name, field_name)
                code += '                PB_VALIDATE_RECORD(ctx, "%s", "String must start with specified prefix");\n' % constraint_id
                code += '                if (PB_VALIDATE_SHOULD_EXIT(ctx)) { PB_VALIDATE_POP_INDEX(ctx); return false; }\n'
                code += '            }\n'
                code += '            PB_VALIDATE_POP_INDEX(ctx);\n'
                code += '        }\n'
            
            elif rule_type == RULE_SUFFIX and pbtype == 'STRING':
                suffix = item_rule.get('value', '')
                code += '        /* repeated.items string.suffix validation */\n'
                code += '        for (pb_size_t pbv_i = 0; pbv_i < msg->%s_count; ++pbv_i) {\n' % field_name
                code += '            const char *pbv_suffix = "%s";\n' % suffix
                code += '            PB_VALIDATE_PUSH_INDEX(ctx, pbv_i);\n'
                code += '            if (!pb_validate_string(msg->%s[pbv_i], (pb_size_t)strlen(msg->%s[pbv_i]), pbv_suffix, PB_VALIDATE_RULE_SUFFIX)) {\n' % (field_name, field_name)
                code += '                PB_VALIDATE_RECORD(ctx, "%s", "String must end with specified suffix");\n' % constraint_id
                code += '                if (PB_VALIDATE_SHOULD_EXIT(ctx)) { PB_VALIDATE_POP_INDEX(ctx); return false; }\n'
                code += '            }\n'
                code += '            PB_VALIDATE_POP_INDEX(ctx);\n'
                code += '        }\n'
            
            elif rule_type == RULE_CONTAINS and pbtype == 'STRING':
                needle = item_rule.get('value', '')
                code += '        /* repeated.items string.contains validation */\n'
                code += '        for (pb_size_t pbv_i = 0; pbv_i < msg->%s_count; ++pbv_i) {\n' % field_name
                code += '            const char *pbv_needle = "%s";\n' % needle
                code += '            PB_VALIDATE_PUSH_INDEX(ctx, pbv_i);\n'
                code += '            if (!pb_validate_string(msg->%s[pbv_i], (pb_size_t)strlen(msg->%s[pbv_i]), pbv_needle, PB_VALIDATE_RULE_CONTAINS)) {\n' % (field_name, field_name)
                code += '                PB_VALIDATE_RECORD(ctx, "%s", "String must contain specified substring");\n' % constraint_id
                code += '                if (PB_VALIDATE_SHOULD_EXIT(ctx)) { PB_VALIDATE_POP_INDEX(ctx); return false; }\n'
                code += '            }\n'
                code += '            PB_VALIDATE_POP_INDEX(ctx);\n'
                code += '        }\n'
            
            elif rule_type == RULE_ASCII and pbtype == 'STRING':
                code += '        /* repeated.items string.ascii validation */\n'
                code += '        for (pb_size_t pbv_i = 0; pbv_i < msg->%s_count; ++pbv_i) {\n' % field_name
                code += '            PB_VALIDATE_PUSH_INDEX(ctx, pbv_i);\n'
                code += '            if (!pb_validate_string(msg->%s[pbv_i], (pb_size_t)strlen(msg->%s[pbv_i]), NULL, PB_VALIDATE_RULE_ASCII)) {\n' % (field_name, field_name)
                code += '                PB_VALIDATE_RECORD(ctx, "%s", "String must contain only ASCII characters");\n' % constraint_id
                code += '                if (PB_VALIDATE_SHOULD_EXIT(ctx)) { PB_VALIDATE_POP_INDEX(ctx); return false; }\n'
                code += '            }\n'
                code += '            PB_VALIDATE_POP_INDEX(ctx);\n'
                code += '        }\n'
            
            elif rule_type in (RULE_EMAIL, RULE_HOSTNAME, RULE_IP, RULE_IPV4, RULE_IPV6) and pbtype == 'STRING':
                rule_enum = self.STRING_FORMAT_RULE_TO_C_ENUM.get(rule_type)
                if rule_enum:
                    code += '        /* repeated.items %s validation */\n' % constraint_id
                    code += '        for (pb_size_t pbv_i = 0; pbv_i < msg->%s_count; ++pbv_i) {\n' % field_name
                    code += '            PB_VALIDATE_PUSH_INDEX(ctx, pbv_i);\n'
                    code += '            if (!pb_validate_string(msg->%s[pbv_i], (pb_size_t)strlen(msg->%s[pbv_i]), NULL, %s)) {\n' % (field_name, field_name, rule_enum)
                    code += '                PB_VALIDATE_RECORD(ctx, "%s", "String format validation failed");\n' % constraint_id
                    code += '                if (PB_VALIDATE_SHOULD_EXIT(ctx)) { PB_VALIDATE_POP_INDEX(ctx); return false; }\n'
                    code += '            }\n'
                    code += '            PB_VALIDATE_POP_INDEX(ctx);\n'
                    code += '        }\n'
            
            elif rule_type == RULE_ENUM_DEFINED:
                # Previously dropped without a trace, so repeated enum fields
                # accepted undefined values even with items.enum.defined_only.
                enum_vals = _enum_values(proto_file, getattr(field, 'ctype', None), constraint_id)
                if enum_vals:
                    arr_values = ', '.join(str(v) for v in enum_vals)
                    code += '        /* repeated.items enum.defined_only validation */\n'
                    code += '        {\n'
                    code += '            static const int pbv_%s_item_vals[] = { %s };\n' % (field_name, arr_values)
                    code += '            for (pb_size_t pbv_i = 0; pbv_i < msg->%s_count; ++pbv_i) {\n' % field_name
                    code += '                PB_VALIDATE_PUSH_INDEX(ctx, pbv_i);\n'
                    code += '                if (!pb_validate_enum_defined_only((int)msg->%s[pbv_i], pbv_%s_item_vals, (pb_size_t)(sizeof(pbv_%s_item_vals)/sizeof(pbv_%s_item_vals[0])))) {\n' % (field_name, field_name, field_name, field_name)
                    code += '                    PB_VALIDATE_RECORD(ctx, "%s", "Value must be a defined enum value");\n' % constraint_id
                    code += '                    if (PB_VALIDATE_SHOULD_EXIT(ctx)) { PB_VALIDATE_POP_INDEX(ctx); return false; }\n'
                    code += '                }\n'
                    code += '                PB_VALIDATE_POP_INDEX(ctx);\n'
                    code += '            }\n'
                    code += '        }\n'

            elif rule_type == RULE_IN:
                values = item_rule.get('values', [])
                if pbtype == 'STRING':
                    values_array = ', '.join('"%s"' % v for v in values)
                    code += '        /* repeated.items string.in validation */\n'
                    code += '        for (pb_size_t pbv_i = 0; pbv_i < msg->%s_count; ++pbv_i) {\n' % field_name
                    code += '            const char *pbv_allowed[] = { %s };\n' % values_array
                    code += '            bool pbv_match = false;\n'
                    code += '            PB_VALIDATE_PUSH_INDEX(ctx, pbv_i);\n'
                    code += '            for (size_t pbv_k = 0; pbv_k < sizeof(pbv_allowed)/sizeof(pbv_allowed[0]); pbv_k++) {\n'
                    code += '                if (strcmp(msg->%s[pbv_i], pbv_allowed[pbv_k]) == 0) { pbv_match = true; break; }\n' % field_name
                    code += '            }\n'
                    code += '            if (!pbv_match) {\n'
                    code += '                PB_VALIDATE_RECORD(ctx, "%s", "Value must be one of allowed set");\n' % constraint_id
                    code += '                if (PB_VALIDATE_SHOULD_EXIT(ctx)) { PB_VALIDATE_POP_INDEX(ctx); return false; }\n'
                    code += '            }\n'
                    code += '            PB_VALIDATE_POP_INDEX(ctx);\n'
                    code += '        }\n'
                else:
                    type_name = constraint_id.split('.', 1)[0]
                    conditions = ['msg->%s[pbv_i] == %s' % (field_name, _c_numeric_literal(v, type_name))
                                  for v in values]
                    condition_str = ' || '.join(conditions) if conditions else 'false'
                    code += '        /* repeated.items %s.in validation */\n' % constraint_id.split('.')[0]
                    code += '        for (pb_size_t pbv_i = 0; pbv_i < msg->%s_count; ++pbv_i) {\n' % field_name
                    code += '            PB_VALIDATE_PUSH_INDEX(ctx, pbv_i);\n'
                    code += '            if (!(%s)) {\n' % condition_str
                    code += '                PB_VALIDATE_RECORD(ctx, "%s", "Value must be one of allowed set");\n' % constraint_id
                    code += '                if (PB_VALIDATE_SHOULD_EXIT(ctx)) { PB_VALIDATE_POP_INDEX(ctx); return false; }\n'
                    code += '            }\n'
                    code += '            PB_VALIDATE_POP_INDEX(ctx);\n'
                    code += '        }\n'
            
            elif rule_type == RULE_NOT_IN:
                values = item_rule.get('values', [])
                if pbtype == 'STRING':
                    values_array = ', '.join('"%s"' % v for v in values)
                    code += '        /* repeated.items string.not_in validation */\n'
                    code += '        for (pb_size_t pbv_i = 0; pbv_i < msg->%s_count; ++pbv_i) {\n' % field_name
                    code += '            const char *pbv_blocked[] = { %s };\n' % values_array
                    code += '            bool pbv_forbidden = false;\n'
                    code += '            PB_VALIDATE_PUSH_INDEX(ctx, pbv_i);\n'
                    code += '            for (size_t pbv_k = 0; pbv_k < sizeof(pbv_blocked)/sizeof(pbv_blocked[0]); pbv_k++) {\n'
                    code += '                if (strcmp(msg->%s[pbv_i], pbv_blocked[pbv_k]) == 0) { pbv_forbidden = true; break; }\n' % field_name
                    code += '            }\n'
                    code += '            if (pbv_forbidden) {\n'
                    code += '                PB_VALIDATE_RECORD(ctx, "%s", "Value is in forbidden set");\n' % constraint_id
                    code += '                if (PB_VALIDATE_SHOULD_EXIT(ctx)) { PB_VALIDATE_POP_INDEX(ctx); return false; }\n'
                    code += '            }\n'
                    code += '            PB_VALIDATE_POP_INDEX(ctx);\n'
                    code += '        }\n'
                else:
                    type_name = constraint_id.split('.', 1)[0]
                    conditions = ['msg->%s[pbv_i] != %s' % (field_name, _c_numeric_literal(v, type_name))
                                  for v in values]
                    condition_str = ' && '.join(conditions) if conditions else 'true'
                    code += '        /* repeated.items %s.not_in validation */\n' % constraint_id.split('.')[0]
                    code += '        for (pb_size_t pbv_i = 0; pbv_i < msg->%s_count; ++pbv_i) {\n' % field_name
                    code += '            PB_VALIDATE_PUSH_INDEX(ctx, pbv_i);\n'
                    code += '            if (!(%s)) {\n' % condition_str
                    code += '                PB_VALIDATE_RECORD(ctx, "%s", "Value is in forbidden set");\n' % constraint_id
                    code += '                if (PB_VALIDATE_SHOULD_EXIT(ctx)) { PB_VALIDATE_POP_INDEX(ctx); return false; }\n'
                    code += '            }\n'
                    code += '            PB_VALIDATE_POP_INDEX(ctx);\n'
                    code += '        }\n'

            if len(code) == emitted:
                # A declared per-item rule must never turn into no check.
                raise ValidationRuleNotImplementedError(
                    'validate.proto option "repeated.items.%s" on field "%s" has no C-runtime '
                    'enforcement for this field type yet. Remove it from the .proto, or wait '
                    'for support.' % (constraint_id, field_name))

        return code


class TimestampRuleEmitter(RuleEmitter):
    """Emits C code for timestamp rules (GT_NOW, LT_NOW, WITHIN)."""
    
    def emit(self, rule_ir: RuleIR, proto_file: Any) -> str:
        field_name = rule_ir.field_name
        
        if rule_ir.rule_type == RULE_TIMESTAMP_GT_NOW:
            return '    PB_VALIDATE_TIMESTAMP_GT_NOW(ctx, msg, %s, "%s");\n' % (
                field_name, rule_ir.constraint_id)
        
        elif rule_ir.rule_type == RULE_TIMESTAMP_LT_NOW:
            return '    PB_VALIDATE_TIMESTAMP_LT_NOW(ctx, msg, %s, "%s");\n' % (
                field_name, rule_ir.constraint_id)
        
        elif rule_ir.rule_type == RULE_TIMESTAMP_WITHIN:
            seconds = rule_ir.rule.params.get('seconds', 0)
            return '    PB_VALIDATE_TIMESTAMP_WITHIN(ctx, msg, %s, %d, "%s");\n' % (
                field_name, seconds, rule_ir.constraint_id)
        
        return ''


class AnyRuleEmitter(RuleEmitter):
    """Emits C code for Any field rules (ANY_IN, ANY_NOT_IN).

    Handles singular Any fields (guarded by has_<field>), Any held in a oneof
    arm (selected arm implies presence) and repeated Any fields (every entry).
    """

    def emit(self, rule_ir: RuleIR, proto_file: Any) -> str:
        field_name = rule_ir.field_name
        values = rule_ir.rule.params.get('values', [])
        ctx = rule_ir.context

        if not values:
            return ''

        values_array = ', '.join('"%s"' % _escape_c_string(url) for url in values)
        is_in = rule_ir.rule_type == RULE_ANY_IN
        suffix = 'in' if is_in else 'notin'
        macro = 'ANY_IN' if is_in else 'ANY_NOT_IN'
        message = 'type_url not in allowed list' if is_in else 'type_url in disallowed list'
        array = 'pbv_%s_urls_%s' % (field_name, suffix)
        decl = '        static const char *%s[] = { %s };\n' % (array, values_array)

        if ctx.is_oneof and not ctx.is_anonymous:
            return '        {\n' + decl.replace('        static', '            static') + (
                '            PB_VALIDATE_ONEOF_%s(ctx, msg, %s, %s, %s, %d, "%s");\n'
                '        }\n') % (macro, ctx.oneof_name, field_name, array, len(values),
                                  rule_ir.constraint_id)

        rules = getattr(ctx.field, 'rules', None)
        if rules in ('REPEATED', 'FIXARRAY') and not ctx.is_oneof:
            count = ('msg->%s_count' % field_name) if rules == 'REPEATED' else \
                '(sizeof(msg->%s) / sizeof(msg->%s[0]))' % (field_name, field_name)
            check = ('(pbv_url && strcmp(pbv_url, %s[pbv_k]) == 0)' % array)
            if is_in:
                body = ('                bool pbv_ok = false;\n'
                        '                for (size_t pbv_k = 0; pbv_k < %d; ++pbv_k)\n'
                        '                    if %s { pbv_ok = true; break; }\n'
                        '                if (!pbv_ok) {\n') % (len(values), check)
            else:
                body = ('                bool pbv_ok = true;\n'
                        '                for (size_t pbv_k = 0; pbv_k < %d; ++pbv_k)\n'
                        '                    if %s { pbv_ok = false; break; }\n'
                        '                if (!pbv_ok) {\n') % (len(values), check)
            return ('        {\n' + decl.replace('        static', '            static') +
                    '            for (pb_size_t pbv_i = 0; pbv_i < %s; ++pbv_i) {\n'
                    '                const char *pbv_url = (const char *)msg->%s[pbv_i].type_url;\n'
                    '%s'
                    '                    PB_VALIDATE_PUSH_INDEX(ctx, pbv_i);\n'
                    '                    PB_VALIDATE_RECORD(ctx, "%s", "%s");\n'
                    '                    PB_VALIDATE_POP_INDEX(ctx);\n'
                    '                    if (PB_VALIDATE_SHOULD_EXIT(ctx)) return false;\n'
                    '                }\n'
                    '            }\n'
                    '        }\n') % (count, field_name, body, rule_ir.constraint_id, message)

        return decl + '        PB_VALIDATE_%s(ctx, msg, %s, %s, %d, "%s");\n' % (
            macro, field_name, array, len(values), rule_ir.constraint_id)


class BytesSetRuleEmitter(RuleEmitter):
    """Emits C code for bytes prefix / suffix / contains / in / not_in.

    These used to fall through to the string macros, which call strlen() on a
    pb_bytes_array_t and do not even compile.
    """

    C_RULE = {
        RULE_PREFIX: 'PB_VALIDATE_RULE_PREFIX',
        RULE_SUFFIX: 'PB_VALIDATE_RULE_SUFFIX',
        RULE_CONTAINS: 'PB_VALIDATE_RULE_CONTAINS',
    }
    MESSAGES = {
        RULE_PREFIX: 'Bytes must start with specified prefix',
        RULE_SUFFIX: 'Bytes must end with specified suffix',
        RULE_CONTAINS: 'Bytes must contain specified sub-sequence',
        RULE_IN: 'Value must be one of allowed set',
        RULE_NOT_IN: 'Value is in forbidden set',
    }

    @staticmethod
    def _as_bytes(value: Any) -> bytes:
        if isinstance(value, str):
            return value.encode('latin-1', 'replace')
        return bytes(value)

    @staticmethod
    def _array(name: str, data: bytes) -> str:
        return 'static const pb_byte_t %s[] = { %s };' % (
            name, ', '.join('0x%02x' % b for b in data) if data else '0x00')

    def emit(self, rule_ir: RuleIR, proto_file: Any) -> str:
        ctx = rule_ir.context
        field_name = rule_ir.field_name
        access = ('msg->%s.%s' % (ctx.oneof_name, field_name)
                  if ctx.is_oneof and not ctx.is_anonymous else 'msg->%s' % field_name)
        message = self.MESSAGES[rule_ir.rule_type]
        fail = ('                PB_VALIDATE_RECORD(ctx, "%s", "%s");\n'
                '                if (PB_VALIDATE_SHOULD_EXIT(ctx)) return false;\n'
                % (rule_ir.constraint_id, message))

        if rule_ir.rule_type in self.C_RULE:
            data = self._as_bytes(rule_ir.rule.params.get('value', b''))
            return ('        {\n'
                    '            %s\n'
                    '            if (!pb_validate_bytes_pattern(%s.bytes, %s.size, pbv_pattern, %d, %s)) {\n'
                    '%s'
                    '            }\n'
                    '        }\n') % (self._array('pbv_pattern', data), access, access, len(data),
                                       self.C_RULE[rule_ir.rule_type], fail)

        values = [self._as_bytes(v) for v in rule_ir.rule.params.get('values', [])]
        if not values:
            return ''
        arrays = '\n            '.join(self._array('pbv_v%d' % i, v) for i, v in enumerate(values))
        items = ', '.join('{ pbv_v%d, %d }' % (i, len(v)) for i, v in enumerate(values))
        negate = '' if rule_ir.rule_type == RULE_IN else '!'
        return ('        {\n'
                '            %s\n'
                '            static const pb_validate_bytes_item_t pbv_set[] = { %s };\n'
                '            if (!(%spb_validate_bytes_in(%s.bytes, %s.size, pbv_set, %d))) {\n'
                '%s'
                '            }\n'
                '        }\n') % (arrays, items, negate, access, access, len(values), fail)


class RequiredRuleEmitter(RuleEmitter):
    """Emits C code for required field rule."""
    
    def emit(self, rule_ir: RuleIR, proto_file: Any) -> str:
        field = rule_ir.context.field
        if getattr(field, 'rules', None) == 'OPTIONAL':
            return ('        if (!msg->has_%s) {\n'
                    '            PB_VALIDATE_RECORD(ctx, "%s", "Field is required");\n'
                    '            if (PB_VALIDATE_SHOULD_EXIT(ctx)) return false;\n'
                    '        }\n') % (rule_ir.field_name, rule_ir.constraint_id)
        return ''


class InNotInRuleEmitter(RuleEmitter):
    """Emits C code for IN and NOT_IN rules."""
    
    def emit(self, rule_ir: RuleIR, proto_file: Any) -> str:
        values = rule_ir.rule.params.get('values', [])
        field_name = rule_ir.field_name
        ctx = rule_ir.context
        is_in = rule_ir.rule_type == RULE_IN
        
        is_string = 'string' in rule_ir.constraint_id
        
        if is_string:
            values_array = ', '.join('"%s"' % _escape_c_string(v) for v in values)
            
            if ctx.is_oneof and not ctx.is_anonymous:
                field_access = '%s.%s' % (ctx.oneof_name, field_name)
                if is_in:
                    conditions = ['strcmp(msg->%s, "%s") == 0' % (field_access, _escape_c_string(v)) for v in values]
                    condition_str = ' || '.join(conditions)
                    return ('    if (!(%s)) { PB_VALIDATE_RECORD(ctx, "%s", "Value must be one of allowed set"); if (PB_VALIDATE_SHOULD_EXIT(ctx)) return false; }\n'
                           ) % (condition_str, rule_ir.constraint_id)
                else:
                    conditions = ['strcmp(msg->%s, "%s") != 0' % (field_access, _escape_c_string(v)) for v in values]
                    condition_str = ' && '.join(conditions)
                    return ('    if (!(%s)) { PB_VALIDATE_RECORD(ctx, "%s", "Value in forbidden set"); if (PB_VALIDATE_SHOULD_EXIT(ctx)) return false; }\n'
                           ) % (condition_str, rule_ir.constraint_id)
            else:
                if is_in:
                    return ('    static const char *pbv_%s_in[] = { %s };\n'
                            '    PB_VALIDATE_STR_IN(ctx, msg, %s, pbv_%s_in, %d, "%s");\n') % (
                        field_name, values_array, field_name, field_name, len(values), rule_ir.constraint_id)
                else:
                    return ('    static const char *pbv_%s_notin[] = { %s };\n'
                            '    PB_VALIDATE_STR_NOT_IN(ctx, msg, %s, pbv_%s_notin, %d, "%s");\n') % (
                        field_name, values_array, field_name, field_name, len(values), rule_ir.constraint_id)
        else:
            # Numeric IN/NOT_IN
            field_access = field_name if not (ctx.is_oneof and not ctx.is_anonymous) else '%s.%s' % (ctx.oneof_name, field_name)
            
            if is_in:
                type_name = rule_ir.constraint_id.split('.', 1)[0]
                conditions = ['msg->%s == %s' % (field_access, _c_numeric_literal(v, type_name))
                              for v in values]
                condition_str = ' || '.join(conditions)
                values_str = ', '.join(str(v) for v in values)
                return ('        if (!(%s)) {\n'
                        '            PB_VALIDATE_RECORD(ctx, "%s", "Value must be one of: %s");\n'
                        '            if (PB_VALIDATE_SHOULD_EXIT(ctx)) return false;\n'
                        '        }\n') % (condition_str, rule_ir.constraint_id, values_str)
            else:
                type_name = rule_ir.constraint_id.split('.', 1)[0]
                conditions = ['msg->%s != %s' % (field_access, _c_numeric_literal(v, type_name))
                              for v in values]
                condition_str = ' && '.join(conditions)
                values_str = ', '.join(str(v) for v in values)
                return ('        if (!(%s)) {\n'
                        '            PB_VALIDATE_RECORD(ctx, "%s", "Value must not be one of: %s");\n'
                        '            if (PB_VALIDATE_SHOULD_EXIT(ctx)) return false;\n'
                        '        }\n') % (condition_str, rule_ir.constraint_id, values_str)


def _enum_values(proto_file: Any, ctype: Any, constraint_id: str) -> List[int]:
    """Values of the enum ``ctype``, defined in ``proto_file`` or one of its dependencies.

    Raises ValidationRuleNotImplementedError when the enum cannot be found, so a
    declared defined_only rule never silently turns into no check at all.
    """
    for e in getattr(proto_file, 'enums', []) or []:
        if str(e.names) == str(ctype):
            return [int(v) for (_, v) in getattr(e, 'values', [])]
    dep = (getattr(proto_file, 'dependencies', None) or {}).get(str(ctype))
    if dep is not None and hasattr(dep, 'values') and hasattr(dep, 'names'):
        return [int(v) for (_, v) in dep.values]
    raise ValidationRuleNotImplementedError(
        'validate.proto option "%s" names enum "%s", whose values are not known '
        'while generating %s. Generate the .proto that defines it in the same '
        'invocation, or remove the rule.'
        % (constraint_id, ctype, getattr(getattr(proto_file, 'fdesc', None), 'name', '?')))


class EnumDefinedRuleEmitter(RuleEmitter):
    """Emits C code for enum defined_only rule."""
    
    def emit(self, rule_ir: RuleIR, proto_file: Any) -> str:
        if not rule_ir.rule.params.get('value', True):
            return ''
        
        field = rule_ir.context.field
        enum_vals = _enum_values(proto_file, getattr(field, 'ctype', None), rule_ir.constraint_id)
        arr_values = ', '.join(str(v) for v in enum_vals)
        field_name = rule_ir.field_name
        ctx = rule_ir.context

        if ctx.is_oneof and not ctx.is_anonymous:
            field_access = '%s.%s' % (ctx.oneof_name, field_name)
            return ('    static const int pbv_%s_vals[] = { %s };\n'
                    '    if (!pb_validate_enum_defined_only((int)msg->%s, pbv_%s_vals, (pb_size_t)(sizeof(pbv_%s_vals)/sizeof(pbv_%s_vals[0])))) {\n'
                    '        PB_VALIDATE_RECORD(ctx, "%s", "Value must be a defined enum value");\n'
                    '        if (PB_VALIDATE_SHOULD_EXIT(ctx)) return false;\n'
                    '    }\n') % (field_name, arr_values, field_access, field_name, field_name, field_name, rule_ir.constraint_id)
        return ('    static const int pbv_%s_vals[] = { %s };\n'
                '    PB_VALIDATE_ENUM_DEFINED_ONLY(ctx, msg, %s, pbv_%s_vals, "%s");\n'
               ) % (field_name, arr_values, field_name, field_name, rule_ir.constraint_id)


class RuleEmitterRegistry:
    """
    Registry for rule emitters with table-driven dispatch.
    
    This class provides a central dispatch mechanism for routing rules to their
    appropriate emitters. Adding a new rule type requires:
    1. Creating a RuleEmitter subclass
    2. Registering it in this registry
    
    This is the single place where rule → emitter mapping is defined.
    """
    
    def __init__(self):
        """Initialize the registry with all known emitters."""
        self._emitters: Dict[str, RuleEmitter] = {}
        self._register_defaults()
    
    def _register_defaults(self):
        """Register all default rule emitters."""
        numeric_emitter = NumericRuleEmitter()
        for rule_type in [RULE_GT, RULE_GTE, RULE_LT, RULE_LTE, RULE_EQ]:
            self._emitters[rule_type] = numeric_emitter

        # const_value on string/bytes fields cannot use the numeric path
        self._const_emitter = ConstValueRuleEmitter()
        self._bytes_set_emitter = BytesSetRuleEmitter()
        
        length_emitter = StringLengthRuleEmitter()
        for rule_type in [RULE_MIN_LEN, RULE_MAX_LEN]:
            self._emitters[rule_type] = length_emitter
        
        format_emitter = StringFormatRuleEmitter()
        for rule_type in [RULE_EMAIL, RULE_HOSTNAME, RULE_IP, RULE_IPV4, RULE_IPV6, RULE_ASCII]:
            self._emitters[rule_type] = format_emitter
        
        pattern_emitter = StringPatternRuleEmitter()
        for rule_type in [RULE_PREFIX, RULE_SUFFIX, RULE_CONTAINS]:
            self._emitters[rule_type] = pattern_emitter
        
        repeated_emitter = RepeatedRuleEmitter()
        for rule_type in [RULE_MIN_ITEMS, RULE_MAX_ITEMS, RULE_UNIQUE]:
            self._emitters[rule_type] = repeated_emitter
        
        # Items emitter for per-item validation on repeated fields
        self._emitters[RULE_ITEMS] = ItemsRuleEmitter()
        
        timestamp_emitter = TimestampRuleEmitter()
        for rule_type in [RULE_TIMESTAMP_GT_NOW, RULE_TIMESTAMP_LT_NOW, RULE_TIMESTAMP_WITHIN]:
            self._emitters[rule_type] = timestamp_emitter
        
        any_emitter = AnyRuleEmitter()
        for rule_type in [RULE_ANY_IN, RULE_ANY_NOT_IN]:
            self._emitters[rule_type] = any_emitter
        
        # Additional emitters
        self._emitters[RULE_REQUIRED] = RequiredRuleEmitter()
        
        in_not_in_emitter = InNotInRuleEmitter()
        for rule_type in [RULE_IN, RULE_NOT_IN]:
            self._emitters[rule_type] = in_not_in_emitter
        
        self._emitters[RULE_ENUM_DEFINED] = EnumDefinedRuleEmitter()
    
    def register(self, rule_type: str, emitter: RuleEmitter):
        """Register an emitter for a rule type."""
        self._emitters[rule_type] = emitter
    
    def _wrap_optional(self, rule_ir: RuleIR, code: str) -> str:
        """
        Wrap code in optional field check if the field is optional.
        
        For optional fields, we only run validation if the has_<field> flag is set.
        """
        if not rule_ir.context.is_optional:
            return code
        
        field_name = rule_ir.field_name
        indented = ''.join(('    ' + line) if line.strip() else line 
                          for line in code.splitlines(True))
        return '        if (msg->has_%s) {\n%s        }\n' % (field_name, indented)
    
    def emit(self, rule_ir: RuleIR, proto_file: Any, message_name: Optional[str] = None) -> str:
        """
        Emit C code for a rule using the appropriate emitter.

        Args:
            rule_ir: The RuleIR to emit
            proto_file: The ProtoFile for context
            message_name: Name of the owning message, used only to make the
                error below easier to locate

        Returns:
            C code string.

        Raises:
            ValidationRuleNotImplementedError: if no emitter is registered
                for this rule type. A declared validate.proto option with no
                C-runtime enforcement is a generation-time error, not a
                silently-ignored no-op -- see the "fail loudly" categories
                documented in docs/validation.md.
        """
        emitter = self._emitters.get(rule_ir.rule_type)
        if rule_ir.rule_type == RULE_EQ and \
                getattr(rule_ir.context.field, 'pbtype', None) in ('STRING', 'BYTES'):
            emitter = self._const_emitter
        if rule_ir.rule_type in (RULE_PREFIX, RULE_SUFFIX, RULE_CONTAINS, RULE_IN, RULE_NOT_IN) and \
                getattr(rule_ir.context.field, 'pbtype', None) == 'BYTES':
            emitter = self._bytes_set_emitter
        if emitter:
            code = emitter.emit(rule_ir, proto_file)
            # Presence rules must run when the field is absent, so they are
            # never wrapped in the has_<field> guard.
            if rule_ir.rule_type in (RULE_REQUIRED, RULE_ONEOF_REQUIRED):
                return code
            # Wrap in optional check if field is optional
            return self._wrap_optional(rule_ir, code)

        location = 'message "%s"' % message_name if message_name else 'an unknown message'
        if rule_ir.field_name:
            location += ' field "%s"' % rule_ir.field_name
        raise ValidationRuleNotImplementedError(
            'validate.proto option "%s" (rule type %s) on %s has no C-runtime '
            'enforcement yet. Remove it from the .proto, or wait for support.'
            % (rule_ir.constraint_id, rule_ir.rule_type, location))


# Global emitter registry instance
_emitter_registry = RuleEmitterRegistry()
