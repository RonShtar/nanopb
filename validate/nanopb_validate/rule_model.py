"""The validate.proto rule model: rule identifiers, ValidationRule, the per-field and per-message
validators (FieldValidator, MessageValidator) and the IR the emitters consume. Uses nanopb's naming
style (Globals) when nanopb_generator is importable, stubs otherwise.
"""

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# =============================================================================
# EXTERNAL DEPENDENCIES (from nanopb_generator.py)
# =============================================================================
# This module depends on exactly two items from nanopb_generator:
#
# 1. Globals.naming_style - Used for C identifier formatting:
#    - type_name(name) - Format a message name as C type (e.g., "Foo_Bar")
#    - var_name(name) - Format a field name as C variable (e.g., "field_name")
#
# 2. OneOf - The OneOf class type, used only for isinstance() checks
#
# These dependencies are isolated here and have fallback stubs for standalone use.
# If additional dependencies are needed, they MUST be added to this block.

try:
    import nanopb_generator  # on sys.path via env.setup()
    Globals = nanopb_generator.Globals
    OneOf = nanopb_generator.OneOf
except (ImportError, AttributeError):
    # Fallback stubs for when used as standalone module
    class Globals:
        """Stub for Globals when nanopb_generator is not available."""
        class naming_style:
            @staticmethod
            def type_name(name):
                return str(name).replace('.', '_')
            @staticmethod
            def var_name(name):
                return str(name)
    class OneOf:
        """Stub for OneOf class when nanopb_generator is not available."""
        pass


class ValidationRuleNotImplementedError(Exception):
    """Raised when a declared (validate.*) option has no C-runtime enforcement
    yet. Generation fails with this rather than silently emitting no check --
    see the "fail loudly" categories in docs/validation.md. The protoc plugin
    (nanopb_validate_generator.py) catches this and turns it into a
    GeneratorError, which protoc reports as a plain generation failure."""


# =============================================================================
# MODULE CONSTANTS
# =============================================================================
# Rule identifiers used throughout code generation.
# These constants provide type safety and make the code self-documenting.

RULE_REQUIRED = 'REQUIRED'
RULE_ONEOF_REQUIRED = 'ONEOF_REQUIRED'
RULE_EQ = 'EQ'
RULE_GT = 'GT'
RULE_GTE = 'GTE'
RULE_LT = 'LT'
RULE_LTE = 'LTE'
RULE_IN = 'IN'
RULE_NOT_IN = 'NOT_IN'
RULE_MIN_LEN = 'MIN_LEN'
RULE_MAX_LEN = 'MAX_LEN'
RULE_PREFIX = 'PREFIX'
RULE_SUFFIX = 'SUFFIX'
RULE_CONTAINS = 'CONTAINS'
RULE_ASCII = 'ASCII'
RULE_EMAIL = 'EMAIL'
RULE_HOSTNAME = 'HOSTNAME'
RULE_IP = 'IP'
RULE_IPV4 = 'IPV4'
RULE_IPV6 = 'IPV6'
RULE_ENUM_DEFINED = 'ENUM_DEFINED'
RULE_MIN_ITEMS = 'MIN_ITEMS'
RULE_MAX_ITEMS = 'MAX_ITEMS'
RULE_UNIQUE = 'UNIQUE'
RULE_ITEMS = 'ITEMS'
RULE_NO_SPARSE = 'NO_SPARSE'
RULE_MAP_ENTRIES = 'MAP_ENTRIES'
RULE_ANY_IN = 'ANY_IN'
RULE_ANY_NOT_IN = 'ANY_NOT_IN'
RULE_TIMESTAMP_GT_NOW = 'TIMESTAMP_GT_NOW'
RULE_TIMESTAMP_LT_NOW = 'TIMESTAMP_LT_NOW'
RULE_TIMESTAMP_WITHIN = 'TIMESTAMP_WITHIN'


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _c_numeric_literal(value: Any, type_name: str) -> str:
    """C spelling of a rule constant for a field of protobuf type ``type_name``.

    64-bit constants need INT64_C/UINT64_C: a bare literal above INT64_MAX has
    no signed type (a warning, an error with -Werror), and -9223372036854775808
    is the negation of an unsigned literal.
    """
    if isinstance(value, bool):
        # str(True) would put the Python spelling "True" into the C source.
        return 'true' if value else 'false'
    if isinstance(value, int):
        if type_name in ('uint64', 'fixed64'):
            return 'UINT64_C(%d)' % value
        if type_name in ('int64', 'sint64', 'sfixed64'):
            if value == -(1 << 63):
                return '(-INT64_C(9223372036854775807) - 1)'
            return 'INT64_C(%d)' % value
    return str(value)


def _get_numeric_validator_info(type_name: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Map a protobuf numeric type name to its C type and validator function.
    
    This centralizes the type mapping logic used throughout code generation.
    
    Args:
        type_name: The protobuf type name (e.g., 'int32', 'float', 'uint64')
        
    Returns:
        A tuple of (c_type, validator_function_name), or (None, None) if not found.
        
    Examples:
        >>> _get_numeric_validator_info('int32')
        ('int32_t', 'pb_validate_int32')
        >>> _get_numeric_validator_info('float')
        ('float', 'pb_validate_float')
    """
    TYPE_MAP = {
        'int32': ('int32_t', 'pb_validate_int32'),
        'sint32': ('int32_t', 'pb_validate_int32'),
        'sfixed32': ('int32_t', 'pb_validate_int32'),
        'int64': ('int64_t', 'pb_validate_int64'),
        'sint64': ('int64_t', 'pb_validate_int64'),
        'sfixed64': ('int64_t', 'pb_validate_int64'),
        'uint32': ('uint32_t', 'pb_validate_uint32'),
        'fixed32': ('uint32_t', 'pb_validate_uint32'),
        'uint64': ('uint64_t', 'pb_validate_uint64'),
        'fixed64': ('uint64_t', 'pb_validate_uint64'),
        'float': ('float', 'pb_validate_float'),
        'double': ('double', 'pb_validate_double'),
        'bool': ('bool', 'pb_validate_bool'),
        'enum': ('int', 'pb_validate_enum'),
    }
    return TYPE_MAP.get(type_name, (None, None))


def _escape_for_comment(s: Any) -> str:
    """
    Escape a string to be safe for use inside C comments and Doxygen blocks.
    
    Args:
        s: The string to escape (can be any type, will be converted to str)
        
    Returns:
        An escaped string safe for use in C comments.
        
    Note:
        - Prevents accidental comment closing by escaping */
        - Normalizes line endings
        - Handles None gracefully
    """
    try:
        if s is None:
            return ''
        # Avoid closing comment accidentally and normalize newlines
        return str(s).replace('*/', '* /').replace('\r\n', '\n').replace('\r', '\n')
    except Exception:
        return str(s) if s is not None else ''


def _escape_c_string(s: Any) -> str:
    """
    Escape a string to be safe for use in C string literals.
    
    Args:
        s: The string to escape (can be any type, will be converted to str)
        
    Returns:
        An escaped string safe for use in C string literals.
        
    Note:
        Backslashes are escaped first to avoid double-escaping.
    """
    try:
        if s is None:
            return ''
        # Escape backslashes first, then special characters
        s = str(s)
        s = s.replace('\\', '\\\\')
        s = s.replace('"', '\\"')
        s = s.replace('\n', '\\n')
        s = s.replace('\r', '\\r')
        s = s.replace('\t', '\\t')
        return s
    except Exception:
        return str(s) if s is not None else ''


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass(frozen=True)
class CTypeInfo:
    """
    Encapsulates C type metadata for numeric field validation.
    
    This dataclass centralizes the C type information needed for code generation,
    making the relationship between protobuf types and C types explicit.
    
    Attributes:
        c_type: The C type name (e.g., 'int32_t', 'float')
        validator_func: The C validator function name (e.g., 'pb_validate_int32')
        proto_type: The original protobuf type name (e.g., 'int32', 'sint32')
    """
    c_type: str
    validator_func: str
    proto_type: str
    
    @classmethod
    def from_proto_type(cls, proto_type: str) -> Optional['CTypeInfo']:
        """Create CTypeInfo from a protobuf type name, or None if not a known type."""
        c_type, validator_func = _get_numeric_validator_info(proto_type)
        if c_type and validator_func:
            return cls(c_type=c_type, validator_func=validator_func, proto_type=proto_type)
        return None


@dataclass(frozen=True)
class ValidationRule:
    """
    Represents a single validation constraint on a field.
    
    A ValidationRule encapsulates one specific constraint to be enforced,
    such as "value must be greater than 10" or "string must be a valid email".
    
    Attributes:
        rule_type: The type of rule (e.g., RULE_GT, RULE_EMAIL, RULE_MIN_LEN).
                   Should be one of the RULE_* constants defined in this module.
        constraint_id: A unique identifier for this constraint, typically
                       in the format "type.rule" (e.g., "int32.gt", "string.email").
                       Used in error messages and documentation.
        params: Optional dictionary of parameters for the rule.
                For example, a GT rule might have {'value': 10},
                an IN rule might have {'values': [1, 2, 3]}.
                
    Examples:
        >>> ValidationRule(RULE_GT, 'int32.gt', {'value': 10})
        ValidationRule(rule_type='GT', constraint_id='int32.gt', params={'value': 10})
        
        >>> ValidationRule(RULE_EMAIL, 'string.email')
        ValidationRule(rule_type='EMAIL', constraint_id='string.email', params={})
    """
    rule_type: str
    constraint_id: str
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FieldContext:
    """
    Context for code generation that unifies regular fields and oneof members.
    
    This dataclass encapsulates all information needed to generate validation
    code for a field, whether it's a regular message field or a member of a
    oneof group. The unified context enables a single code generation path
    through the IR pipeline for all field types.
    
    Attributes:
        field: The protobuf field descriptor
        field_name: The field's name (used in generated code)
        is_oneof: True if this field is inside a oneof group
        oneof_name: Name of the containing oneof (None for regular fields)
        is_anonymous: True for C11 anonymous unions (field accessed directly)
        
    Properties:
        field_access: Returns the C expression to access this field from msg
                      E.g., "field_name" for regular/anonymous oneof,
                      "oneof_name.field_name" for non-anonymous oneof
        is_optional: Returns True if this is an optional field
    """
    field: Any
    field_name: str
    is_oneof: bool = False
    oneof_name: Optional[str] = None
    is_anonymous: bool = False
    
    @property
    def field_access(self) -> str:
        """Return C expression for accessing this field from msg pointer."""
        if self.is_oneof and not self.is_anonymous:
            return f"{self.oneof_name}.{self.field_name}"
        return self.field_name
    
    @property
    def is_optional(self) -> bool:
        """
        Return True if this field is optional (proto3 optional or proto2 optional).
        
        In nanopb, optional fields are identified by having `rules == 'OPTIONAL'` 
        in the field descriptor. These fields generate a `has_<field>` flag in the
        C struct that must be checked before validating the field value.
        """
        if self.field is None:
            return False
        try:
            return getattr(self.field, 'rules', None) == 'OPTIONAL'
        except Exception:
            return False
    
    @classmethod
    def for_regular_field(cls, field: Any) -> 'FieldContext':
        """Create context for a regular (non-oneof) field."""
        return cls(
            field=field,
            field_name=field.name,
            is_oneof=False,
            oneof_name=None,
            is_anonymous=False
        )
    
    @classmethod
    def for_oneof_member(cls, field: Any, oneof_name: str, anonymous: bool) -> 'FieldContext':
        """Create context for a field within a oneof group."""
        return cls(
            field=field,
            field_name=field.name,
            is_oneof=True,
            oneof_name=oneof_name,
            is_anonymous=anonymous
        )
    
    @classmethod
    def for_message_rule(cls) -> 'FieldContext':
        """
        Create a context for message-level rules.
        
        Message-level rules (REQUIRES, MUTEX, AT_LEAST) don't apply to a specific
        field, so this returns a context with no field information. This makes
        the intent explicit rather than using a raw FieldContext with None values.
        """
        return cls(
            field=None,
            field_name='',
            is_oneof=False,
            oneof_name=None,
            is_anonymous=False
        )


@dataclass
class RuleIR:
    """
    Complete intermediate representation for a single validation rule.
    
    RuleIR contains all information needed to emit C code for a validation rule,
    without needing to look up any additional context. This is the "ready to emit"
    representation that decouples parsing from code generation.
    
    The separation between ValidationRule (parsed data) and RuleIR (emission-ready)
    allows us to:
    - Validate rule consistency before emission
    - Add C-specific metadata (types, macros) in one place
    - Test parsing and emission independently
    
    Attributes:
        rule: The original ValidationRule with constraint info
        context: FieldContext with field access information
        c_type_info: C type metadata for numeric rules (None for non-numeric)
        c_macro: The C macro name to use for this rule
        params_formatted: Pre-formatted parameters for C code (e.g., quoted strings)
    """
    rule: ValidationRule
    context: FieldContext
    c_type_info: Optional[CTypeInfo] = None
    c_macro: str = ''
    params_formatted: Dict[str, str] = field(default_factory=dict)
    
    @property
    def rule_type(self) -> str:
        """Shortcut to get the rule type."""
        return self.rule.rule_type
    
    @property
    def constraint_id(self) -> str:
        """Shortcut to get the constraint ID."""
        return self.rule.constraint_id
    
    @property
    def field_name(self) -> str:
        """Shortcut to get the field name."""
        return self.context.field_name
    
    @property
    def field_access(self) -> str:
        """Shortcut to get the field access expression."""
        return self.context.field_access


# =============================================================================
# IR BUILDER
# =============================================================================
# The IRBuilder transforms parsed validation rules into the IR representation.
# This separation allows us to validate and preprocess rules before emission.

class IRBuilder:
    """
    Builds RuleIR objects from parsed ValidationRules.
    
    IRBuilder is responsible for transforming the parsed validation rules into
    the emission-ready IR. It:
    - Determines the appropriate C macro for each rule type
    - Resolves C type information for numeric rules
    - Pre-formats parameters for C code generation

    Dependencies:
        - Uses Globals.naming_style for C name formatting
        - Uses CTypeInfo for numeric type resolution
    """
    
    # Mapping from rule type to C macro name for regular fields
    RULE_TO_MACRO = {
        RULE_REQUIRED: 'PB_VALIDATE_REQUIRED',
        RULE_MIN_LEN: 'PB_VALIDATE_STR_MIN_LEN',
        RULE_MAX_LEN: 'PB_VALIDATE_STR_MAX_LEN',
        RULE_PREFIX: 'PB_VALIDATE_STR_PREFIX',
        RULE_SUFFIX: 'PB_VALIDATE_STR_SUFFIX',
        RULE_CONTAINS: 'PB_VALIDATE_STR_CONTAINS',
        RULE_ASCII: 'PB_VALIDATE_STR_ASCII',
        RULE_EMAIL: 'PB_VALIDATE_STR_EMAIL',
        RULE_HOSTNAME: 'PB_VALIDATE_STR_HOSTNAME',
        RULE_IP: 'PB_VALIDATE_STR_IP',
        RULE_IPV4: 'PB_VALIDATE_STR_IPV4',
        RULE_IPV6: 'PB_VALIDATE_STR_IPV6',
        RULE_MIN_ITEMS: 'PB_VALIDATE_MIN_ITEMS',
        RULE_MAX_ITEMS: 'PB_VALIDATE_MAX_ITEMS',
        RULE_UNIQUE: 'PB_VALIDATE_REPEATED_UNIQUE_SCALAR',
        RULE_ENUM_DEFINED: 'PB_VALIDATE_ENUM_DEFINED_ONLY',
        RULE_ANY_IN: 'PB_VALIDATE_ANY_IN',
        RULE_ANY_NOT_IN: 'PB_VALIDATE_ANY_NOT_IN',
        RULE_TIMESTAMP_GT_NOW: 'PB_VALIDATE_TIMESTAMP_GT_NOW',
        RULE_TIMESTAMP_LT_NOW: 'PB_VALIDATE_TIMESTAMP_LT_NOW',
        RULE_TIMESTAMP_WITHIN: 'PB_VALIDATE_TIMESTAMP_WITHIN',
    }
    
    # Numeric rule types that use PB_VALIDATE_NUMERIC_GENERIC
    NUMERIC_COMPARISON_RULES = {RULE_GT, RULE_GTE, RULE_LT, RULE_LTE, RULE_EQ}
    
    # Rule type to C enum constant for numeric comparisons
    NUMERIC_RULE_TO_C_ENUM = {
        RULE_GT: 'PB_VALIDATE_RULE_GT',
        RULE_GTE: 'PB_VALIDATE_RULE_GTE',
        RULE_LT: 'PB_VALIDATE_RULE_LT',
        RULE_LTE: 'PB_VALIDATE_RULE_LTE',
        RULE_EQ: 'PB_VALIDATE_RULE_EQ',
    }
    
    def __init__(self, proto_file: Any):
        """
        Initialize the IR builder.
        
        Args:
            proto_file: The ProtoFile object (used for type lookups)
        """
        self.proto_file = proto_file
    
    def build_rule_ir(self, rule: ValidationRule, context: FieldContext) -> RuleIR:
        """
        Build a RuleIR from a ValidationRule and FieldContext.
        
        Args:
            rule: The parsed ValidationRule
            context: The FieldContext for the field
            
        Returns:
            A complete RuleIR ready for code emission
        """
        # Determine C type info for numeric rules
        c_type_info = None
        if rule.rule_type in self.NUMERIC_COMPARISON_RULES:
            proto_type = rule.constraint_id.split('.', 1)[0]
            c_type_info = CTypeInfo.from_proto_type(proto_type)
        
        # Determine the C macro to use
        c_macro = self._resolve_macro(rule, context)
        
        # Format parameters for C code
        params_formatted = self._format_params(rule)
        
        return RuleIR(
            rule=rule,
            context=context,
            c_type_info=c_type_info,
            c_macro=c_macro,
            params_formatted=params_formatted
        )
    
    def _resolve_macro(self, rule: ValidationRule, context: FieldContext) -> str:
        """Resolve the C macro name for a rule."""
        # Numeric comparisons use NUMERIC_GENERIC
        if rule.rule_type in self.NUMERIC_COMPARISON_RULES:
            if context.is_oneof and not context.is_anonymous:
                return 'PB_VALIDATE_ONEOF_NUMERIC'
            return 'PB_VALIDATE_NUMERIC_GENERIC'
        
        # Lookup in the standard table
        macro = self.RULE_TO_MACRO.get(rule.rule_type, '')
        
        # Adjust for oneof if needed
        if context.is_oneof and not context.is_anonymous and macro:
            # Many macros have ONEOF variants
            oneof_macro = macro.replace('PB_VALIDATE_STR_', 'PB_VALIDATE_ONEOF_STR_')
            if oneof_macro != macro:
                return oneof_macro
        
        return macro
    
    def _format_params(self, rule: ValidationRule) -> Dict[str, str]:
        """Format rule parameters for C code generation."""
        formatted = {}
        params = rule.params
        
        if 'value' in params:
            val = params['value']
            if isinstance(val, str):
                formatted['value'] = '"%s"' % _escape_c_string(val)
            else:
                formatted['value'] = str(val)
        
        if 'values' in params:
            values = params['values']
            if all(isinstance(v, str) for v in values):
                formatted['values_array'] = ', '.join('"%s"' % _escape_c_string(v) for v in values)
            else:
                formatted['values_array'] = ', '.join(str(v) for v in values)
            formatted['values_count'] = str(len(values))
        
        if 'seconds' in params:
            formatted['seconds'] = str(params['seconds'])
        
        if 'field' in params:
            formatted['field'] = str(params['field'])
        
        if 'fields' in params:
            formatted['fields'] = ', '.join(str(f) for f in params['fields'])
        
        if 'n' in params:
            formatted['n'] = str(params['n'])
        
        return formatted


class FieldValidator:
    """
    Handles validation rule parsing and storage for a single protobuf field.
    
    This class is responsible for:
    - Extracting validation rules from the field's validate.proto options
    - Converting those options into ValidationRule objects
    - Storing the rules for later code generation
    
    The parsing is type-aware: it knows how to extract rules for strings,
    numeric types, bytes, enums, repeated fields, maps, and special types
    like google.protobuf.Any.
    
    Attributes:
        field: The protobuf field descriptor
        rules: List of ValidationRule objects extracted from the field's options
        proto_file: The ProtoFile object (used for enum lookups, etc.)
    """
    
    def __init__(self, field: Any, rules_option: Any, proto_file: Optional[Any] = None,
                 _message_desc: Optional[Any] = None):
        """
        Initialize a FieldValidator for a given field.
        
        Args:
            field: The protobuf field descriptor
            rules_option: The FieldRules option from validate.proto (or None)
            proto_file: The ProtoFile object containing this field
            _message_desc: Deprecated parameter, retained for API compatibility; no longer used
        """
        self.field = field
        self.rules: List[ValidationRule] = []
        self.proto_file = proto_file
        self.parse_rules(rules_option)
    
    def parse_rules(self, rules_option: Any) -> None:
        """
        Parse validation rules from the FieldRules option.
        
        This is the main entry point for rule extraction. It dispatches to
        type-specific parsers based on which field is set in the FieldRules option.
        
        The method relies only on the provided rules_option (field.validate_rules).
        There is no descriptor scanning or binary parsing fallback.
        
        Args:
            rules_option: The FieldRules message from validate.proto, or None
        """
        if not rules_option:
            return
        
        # Parse type-specific rules
        if rules_option.HasField('string'):
            self._parse_string_rules(rules_option.string)
        if rules_option.HasField('bytes'):
            self._parse_bytes_rules(rules_option.bytes)
        if rules_option.HasField('bool'):
            self._parse_bool_rules(rules_option.bool)
        if rules_option.HasField('enum'):
            self._parse_enum_rules(rules_option.enum)
        if rules_option.HasField('repeated'):
            self._parse_repeated_rules(rules_option.repeated)
        if rules_option.HasField('map'):
            self._parse_map_rules(rules_option.map)
        if rules_option.HasField('any'):
            self._parse_any_rules(rules_option.any)
        if rules_option.HasField('timestamp'):
            self._parse_timestamp_rules(rules_option.timestamp)
        
        # Parse numeric rules for all numeric types (consolidated for clarity)
        numeric_types = [
            'int32', 'int64', 'uint32', 'uint64',
            'sint32', 'sint64', 'fixed32', 'fixed64',
            'sfixed32', 'sfixed64', 'double', 'float'
        ]
        for type_name in numeric_types:
            if rules_option.HasField(type_name):
                self._parse_numeric_rules(getattr(rules_option, type_name), type_name)
        
        # Parse field-level flags
        if rules_option.HasField('required') and rules_option.required:
            self.rules.append(ValidationRule(RULE_REQUIRED, 'required'))
        if rules_option.HasField('oneof_required') and rules_option.oneof_required:
            self.rules.append(ValidationRule(RULE_ONEOF_REQUIRED, 'oneof_required'))
    
    
    def _parse_numeric_rules(self, rules: Any, type_name: str) -> None:
        """
        Parse validation rules for numeric fields (int32, float, etc.).
        
        Numeric rules include comparisons (lt, lte, gt, gte, const) and
        set membership (in, not_in).
        
        Args:
            rules: The numeric rules message (e.g., Int32Rules, FloatRules)
            type_name: The name of the numeric type (e.g., 'int32', 'float')
        """
        if rules.HasField('const_value'):
            self.rules.append(ValidationRule(RULE_EQ, f'{type_name}.const', {'value': rules.const_value}))
        if rules.HasField('lt'):
            self.rules.append(ValidationRule(RULE_LT, f'{type_name}.lt', {'value': rules.lt}))
        if rules.HasField('lte'):
            self.rules.append(ValidationRule(RULE_LTE, f'{type_name}.lte', {'value': rules.lte}))
        if rules.HasField('gt'):
            self.rules.append(ValidationRule(RULE_GT, f'{type_name}.gt', {'value': rules.gt}))
        if rules.HasField('gte'):
            self.rules.append(ValidationRule(RULE_GTE, f'{type_name}.gte', {'value': rules.gte}))
        if hasattr(rules, 'in') and getattr(rules, 'in'):
            self.rules.append(ValidationRule(RULE_IN, f'{type_name}.in', {'values': list(getattr(rules, 'in'))}))
        if rules.not_in:
            self.rules.append(ValidationRule(RULE_NOT_IN, f'{type_name}.not_in', {'values': list(rules.not_in)}))
    
    def _parse_bool_rules(self, rules: Any) -> None:
        """
        Parse validation rules for boolean fields.
        
        Args:
            rules: The BoolRules message from validate.proto
        """
        if rules.HasField('const_value'):
            self.rules.append(ValidationRule(RULE_EQ, 'bool.const', {'value': rules.const_value}))
    
    def _parse_string_rules(self, rules: Any) -> None:
        """
        Parse validation rules for string fields.
        
        String rules include length constraints, pattern matching (prefix, suffix,
        contains), format validation (email, IP address, etc.), and set membership.
        
        Args:
            rules: The StringRules message from validate.proto

        Raises:
            ValidationRuleNotImplementedError: for options declared in
                validate.proto that have no C-runtime enforcement at all
                (pattern has no regex engine; min_bytes/max_bytes have no
                distinct byte-vs-character-length check for a NUL-terminated
                C string).
        """
        if rules.HasField('pattern'):
            raise ValidationRuleNotImplementedError(
                'validate.proto option "string.pattern" on field "%s" has no C-runtime '
                'enforcement yet (no regex engine). Remove it from the .proto, or wait '
                'for support.' % self.field.name)
        if rules.HasField('min_bytes'):
            raise ValidationRuleNotImplementedError(
                'validate.proto option "string.min_bytes" on field "%s" has no C-runtime '
                'enforcement yet. Remove it from the .proto, or wait for support.'
                % self.field.name)
        if rules.HasField('max_bytes'):
            raise ValidationRuleNotImplementedError(
                'validate.proto option "string.max_bytes" on field "%s" has no C-runtime '
                'enforcement yet. Remove it from the .proto, or wait for support.'
                % self.field.name)
        if rules.HasField('const_value'):
            self.rules.append(ValidationRule(RULE_EQ, 'string.const', {'value': rules.const_value}))
        if rules.HasField('min_len'):
            self.rules.append(ValidationRule(RULE_MIN_LEN, 'string.min_len', {'value': rules.min_len}))
        if rules.HasField('max_len'):
            self.rules.append(ValidationRule(RULE_MAX_LEN, 'string.max_len', {'value': rules.max_len}))
        if rules.HasField('prefix'):
            self.rules.append(ValidationRule(RULE_PREFIX, 'string.prefix', {'value': rules.prefix}))
        if rules.HasField('suffix'):
            self.rules.append(ValidationRule(RULE_SUFFIX, 'string.suffix', {'value': rules.suffix}))
        if rules.HasField('contains'):
            self.rules.append(ValidationRule(RULE_CONTAINS, 'string.contains', {'value': rules.contains}))
        if rules.HasField('ascii') and rules.ascii:
            self.rules.append(ValidationRule(RULE_ASCII, 'string.ascii'))
        if getattr(rules, 'email', False):
            self.rules.append(ValidationRule(RULE_EMAIL, 'string.email'))
        if getattr(rules, 'hostname', False):
            self.rules.append(ValidationRule(RULE_HOSTNAME, 'string.hostname'))
        if getattr(rules, 'ip', False):
            self.rules.append(ValidationRule(RULE_IP, 'string.ip'))
        if getattr(rules, 'ipv4', False):
            self.rules.append(ValidationRule(RULE_IPV4, 'string.ipv4'))
        if getattr(rules, 'ipv6', False):
            self.rules.append(ValidationRule(RULE_IPV6, 'string.ipv6'))
        if hasattr(rules, 'in') and getattr(rules, 'in'):
            self.rules.append(ValidationRule(RULE_IN, 'string.in', {'values': list(getattr(rules, 'in'))}))
        if rules.not_in:
            self.rules.append(ValidationRule(RULE_NOT_IN, 'string.not_in', {'values': list(rules.not_in)}))
    
    def _parse_bytes_rules(self, rules: Any) -> None:
        """
        Parse validation rules for bytes fields.
        
        Bytes rules are similar to string rules but operate on byte sequences.
        
        Args:
            rules: The BytesRules message from validate.proto

        Raises:
            ValidationRuleNotImplementedError: "pattern" is declared in
                validate.proto but has no C-runtime enforcement (no regex
                engine for byte sequences).
        """
        if rules.HasField('pattern'):
            raise ValidationRuleNotImplementedError(
                'validate.proto option "bytes.pattern" on field "%s" has no C-runtime '
                'enforcement yet (no regex engine). Remove it from the .proto, or wait '
                'for support.' % self.field.name)
        if rules.HasField('const_value'):
            self.rules.append(ValidationRule(RULE_EQ, 'bytes.const', {'value': rules.const_value}))
        if rules.HasField('min_len'):
            self.rules.append(ValidationRule(RULE_MIN_LEN, 'bytes.min_len', {'value': rules.min_len}))
        if rules.HasField('max_len'):
            self.rules.append(ValidationRule(RULE_MAX_LEN, 'bytes.max_len', {'value': rules.max_len}))
        if rules.HasField('prefix'):
            self.rules.append(ValidationRule(RULE_PREFIX, 'bytes.prefix', {'value': rules.prefix}))
        if rules.HasField('suffix'):
            self.rules.append(ValidationRule(RULE_SUFFIX, 'bytes.suffix', {'value': rules.suffix}))
        if rules.HasField('contains'):
            self.rules.append(ValidationRule(RULE_CONTAINS, 'bytes.contains', {'value': rules.contains}))
        if hasattr(rules, 'in') and getattr(rules, 'in'):
            self.rules.append(ValidationRule(RULE_IN, 'bytes.in', {'values': list(getattr(rules, 'in'))}))
        if rules.not_in:
            self.rules.append(ValidationRule(RULE_NOT_IN, 'bytes.not_in', {'values': list(rules.not_in)}))
    
    def _parse_enum_rules(self, rules: Any) -> None:
        """
        Parse validation rules for enum fields.
        
        Enum rules include const value, defined_only (must be a known enum value),
        and set membership.
        
        Args:
            rules: The EnumRules message from validate.proto
        """
        if rules.HasField('const_value'):
            self.rules.append(ValidationRule(RULE_EQ, 'enum.const', {'value': rules.const_value}))
        if rules.HasField('defined_only'):
            self.rules.append(ValidationRule(RULE_ENUM_DEFINED, 'enum.defined_only', {'value': rules.defined_only}))
        if hasattr(rules, 'in') and getattr(rules, 'in'):
            self.rules.append(ValidationRule(RULE_IN, 'enum.in', {'values': list(getattr(rules, 'in'))}))
        if rules.not_in:
            self.rules.append(ValidationRule(RULE_NOT_IN, 'enum.not_in', {'values': list(rules.not_in)}))
    
    def _parse_repeated_rules(self, rules: Any) -> None:
        """
        Parse validation rules for repeated fields.
        
        Repeated field rules include item count constraints (min_items, max_items),
        uniqueness constraints, and per-item validation rules.
        
        Args:
            rules: The RepeatedRules message from validate.proto
        """
        if rules.HasField('min_items'):
            self.rules.append(ValidationRule(RULE_MIN_ITEMS, 'repeated.min_items', {'value': rules.min_items}))
        if rules.HasField('max_items'):
            self.rules.append(ValidationRule(RULE_MAX_ITEMS, 'repeated.max_items', {'value': rules.max_items}))
        if rules.HasField('unique') and rules.unique:
            self.rules.append(ValidationRule(RULE_UNIQUE, 'repeated.unique'))
        # Parse per-item validation rules
        if rules.HasField('items'):
            item_rules_list = self._extract_item_rules(rules.items)
            if item_rules_list:
                self.rules.append(ValidationRule(
                    RULE_ITEMS, 'repeated.items', {'item_rules': item_rules_list}
                ))
    
    def _extract_item_rules(self, items_rules: Any) -> List[Dict[str, Any]]:
        """
        Extract per-item validation rules for repeated fields.
        
        This method examines the items rules and extracts type-specific constraints
        that should be applied to each element of the repeated field.
        
        Args:
            items_rules: The repeated.items submessage from validate.proto
            
        Returns:
            A list of dictionaries, each representing one per-item constraint
        """
        result = []
        
        # Extract rules for each type that might be in the items
        if items_rules.HasField('string'):
            result.extend(self._extract_string_item_rules(items_rules.string))
        if items_rules.HasField('bool'):
            result.extend(self._extract_bool_item_rules(items_rules.bool))
        if items_rules.HasField('enum'):
            result.extend(self._extract_enum_item_rules(items_rules.enum))
        
        # Extract numeric item rules for all numeric types (consolidated)
        numeric_types = [
            'int32', 'int64', 'uint32', 'uint64',
            'sint32', 'sint64', 'fixed32', 'fixed64',
            'sfixed32', 'sfixed64', 'float', 'double'
        ]
        for type_name in numeric_types:
            if items_rules.HasField(type_name):
                result.extend(self._extract_numeric_item_rules(
                    getattr(items_rules, type_name), type_name
                ))
        
        return result
    
    def _extract_string_item_rules(self, rules: Any) -> List[Dict[str, Any]]:
        """Extract string validation rules for repeated items."""
        result = []
        if rules.HasField('const_value'):
            result.append({'rule': RULE_EQ, 'constraint_id': 'string.const', 'value': rules.const_value})
        if rules.HasField('min_len'):
            result.append({'rule': RULE_MIN_LEN, 'constraint_id': 'string.min_len', 'value': rules.min_len})
        if rules.HasField('max_len'):
            result.append({'rule': RULE_MAX_LEN, 'constraint_id': 'string.max_len', 'value': rules.max_len})
        if rules.HasField('prefix'):
            result.append({'rule': RULE_PREFIX, 'constraint_id': 'string.prefix', 'value': rules.prefix})
        if rules.HasField('suffix'):
            result.append({'rule': RULE_SUFFIX, 'constraint_id': 'string.suffix', 'value': rules.suffix})
        if rules.HasField('contains'):
            result.append({'rule': RULE_CONTAINS, 'constraint_id': 'string.contains', 'value': rules.contains})
        if rules.HasField('ascii') and rules.ascii:
            result.append({'rule': RULE_ASCII, 'constraint_id': 'string.ascii'})
        if getattr(rules, 'email', False):
            result.append({'rule': RULE_EMAIL, 'constraint_id': 'string.email'})
        if getattr(rules, 'hostname', False):
            result.append({'rule': RULE_HOSTNAME, 'constraint_id': 'string.hostname'})
        if getattr(rules, 'ip', False):
            result.append({'rule': RULE_IP, 'constraint_id': 'string.ip'})
        if getattr(rules, 'ipv4', False):
            result.append({'rule': RULE_IPV4, 'constraint_id': 'string.ipv4'})
        if getattr(rules, 'ipv6', False):
            result.append({'rule': RULE_IPV6, 'constraint_id': 'string.ipv6'})
        if hasattr(rules, 'in') and getattr(rules, 'in'):
            result.append({'rule': RULE_IN, 'constraint_id': 'string.in', 'values': list(getattr(rules, 'in'))})
        if rules.not_in:
            result.append({'rule': RULE_NOT_IN, 'constraint_id': 'string.not_in', 'values': list(rules.not_in)})
        return result
    
    def _extract_numeric_item_rules(self, rules: Any, type_name: str) -> List[Dict[str, Any]]:
        """Extract numeric validation rules for repeated items."""
        result = []
        if rules.HasField('const_value'):
            result.append({'rule': RULE_EQ, 'constraint_id': f'{type_name}.const', 'value': rules.const_value})
        if rules.HasField('lt'):
            result.append({'rule': RULE_LT, 'constraint_id': f'{type_name}.lt', 'value': rules.lt})
        if rules.HasField('lte'):
            result.append({'rule': RULE_LTE, 'constraint_id': f'{type_name}.lte', 'value': rules.lte})
        if rules.HasField('gt'):
            result.append({'rule': RULE_GT, 'constraint_id': f'{type_name}.gt', 'value': rules.gt})
        if rules.HasField('gte'):
            result.append({'rule': RULE_GTE, 'constraint_id': f'{type_name}.gte', 'value': rules.gte})
        if hasattr(rules, 'in') and getattr(rules, 'in'):
            result.append({'rule': RULE_IN, 'constraint_id': f'{type_name}.in', 'values': list(getattr(rules, 'in'))})
        if rules.not_in:
            result.append({'rule': RULE_NOT_IN, 'constraint_id': f'{type_name}.not_in', 'values': list(rules.not_in)})
        return result
    
    def _extract_bool_item_rules(self, rules: Any) -> List[Dict[str, Any]]:
        """Extract bool validation rules for repeated items."""
        result = []
        if rules.HasField('const_value'):
            result.append({'rule': RULE_EQ, 'constraint_id': 'bool.const', 'value': rules.const_value})
        return result
    
    def _extract_enum_item_rules(self, rules: Any) -> List[Dict[str, Any]]:
        """Extract enum validation rules for repeated items."""
        result = []
        if rules.HasField('const_value'):
            result.append({'rule': RULE_EQ, 'constraint_id': 'enum.const', 'value': rules.const_value})
        if rules.HasField('defined_only') and rules.defined_only:
            result.append({'rule': RULE_ENUM_DEFINED, 'constraint_id': 'enum.defined_only', 'value': rules.defined_only})
        if hasattr(rules, 'in') and getattr(rules, 'in'):
            result.append({'rule': RULE_IN, 'constraint_id': 'enum.in', 'values': list(getattr(rules, 'in'))})
        if rules.not_in:
            result.append({'rule': RULE_NOT_IN, 'constraint_id': 'enum.not_in', 'values': list(rules.not_in)})
        return result
    
    def _parse_map_rules(self, rules: Any) -> None:
        """
        Parse validation rules for map fields.
        
        Map rules include min/max pair counts, the no_sparse constraint and
        the keys/values rules, which apply to every entry's key and value
        (RULE_MAP_ENTRIES, emitted by ValidatorGenerator._emit_map_entries).

        Args:
            rules: The MapRules message from validate.proto
        """
        if rules.HasField('min_pairs'):
            self.rules.append(ValidationRule(RULE_MIN_ITEMS, 'map.min_pairs', {'value': rules.min_pairs}))
        if rules.HasField('max_pairs'):
            self.rules.append(ValidationRule(RULE_MAX_ITEMS, 'map.max_pairs', {'value': rules.max_pairs}))
        if rules.HasField('no_sparse') and rules.no_sparse:
            self.rules.append(ValidationRule(RULE_NO_SPARSE, 'map.no_sparse'))
        if rules.HasField('keys') or rules.HasField('values'):
            self.rules.append(ValidationRule(RULE_MAP_ENTRIES, 'map', {
                'key_rules': rules.keys if rules.HasField('keys') else None,
                'value_rules': rules.values if rules.HasField('values') else None,
            }))
    
    def _parse_any_rules(self, rules: Any) -> None:
        """
        Parse validation rules for google.protobuf.Any fields.
        
        Any field rules restrict which type URLs are allowed or forbidden.
        
        Args:
            rules: The AnyRules message from validate.proto
        """
        if hasattr(rules, 'in') and getattr(rules, 'in'):
            self.rules.append(ValidationRule(RULE_ANY_IN, 'any.in', {'values': list(getattr(rules, 'in'))}))
        if hasattr(rules, 'not_in') and getattr(rules, 'not_in'):
            self.rules.append(ValidationRule(RULE_ANY_NOT_IN, 'any.not_in', {'values': list(getattr(rules, 'not_in'))}))
    
    def _parse_timestamp_rules(self, rules: Any) -> None:
        """
        Parse validation rules for google.protobuf.Timestamp fields.
        
        Timestamp field rules can check if timestamp is before/after current time
        or within a specified duration from now.
        
        Args:
            rules: The TimestampRules message from validate.proto
        """
        if hasattr(rules, 'gt_now') and rules.gt_now:
            self.rules.append(ValidationRule(RULE_TIMESTAMP_GT_NOW, 'timestamp.gt_now'))
        if hasattr(rules, 'lt_now') and rules.lt_now:
            self.rules.append(ValidationRule(RULE_TIMESTAMP_LT_NOW, 'timestamp.lt_now'))
        if hasattr(rules, 'within') and rules.HasField('within'):
            seconds = rules.within.seconds if hasattr(rules.within, 'seconds') else 0
            self.rules.append(ValidationRule(RULE_TIMESTAMP_WITHIN, 'timestamp.within', {'seconds': seconds}))
class MessageValidator:
    """
    Handles validation for an entire protobuf message.
    
    This class aggregates:
    - Field validators for regular fields
    - Oneof validators for oneof groups
    - Message-level validation rules
    
    It coordinates the parsing of all validation constraints for a message
    and makes them available for code generation.
    
    Attributes:
        message: The protobuf message descriptor
        field_validators: OrderedDict mapping field names to FieldValidator objects
        oneof_validators: OrderedDict mapping oneof names to their validators
        message_rules: List of message-level ValidationRule objects
        proto_file: The ProtoFile object containing this message
    """
    
    def __init__(self, message: Any, message_rules: Optional[Any] = None,
                 proto_file: Optional[Any] = None):
        """
        Initialize a MessageValidator for a given message.
        
        Args:
            message: The protobuf message descriptor
            message_rules: The MessageRules option from validate.proto (or None)
            proto_file: The ProtoFile object containing this message
        """
        self.message = message
        self.field_validators = OrderedDict()
        self.oneof_validators = OrderedDict()
        self.message_rules: List[ValidationRule] = []
        self.proto_file = proto_file
        
        # Parse field-level and oneof rules
        self._parse_field_validators()
        
        # Parse message-level rules
        if message_rules:
            self.parse_message_rules(message_rules)
    
    def _parse_field_validators(self) -> None:
        """
        Parse validation rules for all fields in the message.
        
        This method iterates through all fields, identifies oneofs, and creates
        FieldValidator objects for fields that have validation rules.
        """
        for field in getattr(self.message, 'fields', []) or []:
            # Check if this is a oneof container
            if hasattr(field, 'pbtype') and field.pbtype == 'oneof':
                self._parse_oneof_field(field)
            elif hasattr(field, 'validate_rules') and field.validate_rules:
                # Regular field with validation rules
                fv = FieldValidator(
                    field, field.validate_rules, self.proto_file, self.message
                )
                self.field_validators[field.name] = fv
    
    def _parse_oneof_field(self, oneof: Any) -> None:
        """
        Parse validation rules for fields within a oneof group.
        
        Args:
            oneof: The oneof field descriptor
        """
        oneof_name = oneof.name
        oneof_fields_with_rules = []
        
        for oneof_member in getattr(oneof, 'fields', []) or []:
            if hasattr(oneof_member, 'validate_rules') and oneof_member.validate_rules:
                fv = FieldValidator(
                    oneof_member, oneof_member.validate_rules,
                    self.proto_file, self.message
                )
                oneof_fields_with_rules.append((oneof_member, fv))
        
        if oneof_fields_with_rules:
            self.oneof_validators[oneof_name] = {
                'oneof': oneof,
                'members': oneof_fields_with_rules
            }
    
    def parse_message_rules(self, rules: Any) -> None:
        """
        Parse message-level validation rules.
        
        Message-level rules include:
        - requires: Fields that must be present
        - mutex: Fields that are mutually exclusive
        - at_least: At least N of a set of fields must be present
        
        Args:
            rules: The MessageRules option from validate.proto
        """
        if rules.requires:
            for field_name in rules.requires:
                self.message_rules.append(ValidationRule('REQUIRES', 'message.requires', {'field': field_name}))
        
        if rules.mutex:
            for group in rules.mutex:
                self.message_rules.append(ValidationRule('MUTEX', 'message.mutex', {'fields': list(group.fields)}))
        
        if rules.at_least:
            for rule in rules.at_least:
                self.message_rules.append(ValidationRule('AT_LEAST', 'message.at_least', 
                                                       {'n': rule.n, 'fields': list(rule.fields)}))
