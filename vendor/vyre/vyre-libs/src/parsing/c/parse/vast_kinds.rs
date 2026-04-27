//! Public VAST node kind constants produced by the C parser.

/// Number of `u32` words in one packed C expression-shape row.
pub const C_EXPR_SHAPE_STRIDE_U32: u32 = 8;

/// No expression-shape node is represented by this row.
pub const C_EXPR_SHAPE_NONE: u32 = 0;
/// C binary or assignment operator expression-shape node.
pub const C_EXPR_SHAPE_BINARY: u32 = 1;
/// C ternary conditional expression-shape node.
pub const C_EXPR_SHAPE_CONDITIONAL: u32 = 2;
/// Not an associative C expression operator.
pub const C_EXPR_ASSOC_NONE: u32 = 0;
/// Left-associative C expression operator.
pub const C_EXPR_ASSOC_LEFT: u32 = 1;
/// Right-associative C expression operator.
pub const C_EXPR_ASSOC_RIGHT: u32 = 2;

/// Parser-local VAST kind for GNU `asm` / `__asm__` inline assembly statements.
pub const C_AST_KIND_INLINE_ASM: u32 = 0xC011_A500;
/// Parser-local VAST kind for the template string in GNU extended asm.
pub const C_AST_KIND_ASM_TEMPLATE: u32 = 0xC011_A501;
/// Parser-local VAST kind for GNU extended asm output operands.
pub const C_AST_KIND_ASM_OUTPUT_OPERAND: u32 = 0xC011_A502;
/// Parser-local VAST kind for GNU extended asm input operands.
pub const C_AST_KIND_ASM_INPUT_OPERAND: u32 = 0xC011_A503;
/// Parser-local VAST kind for GNU extended asm clobber strings.
pub const C_AST_KIND_ASM_CLOBBERS_LIST: u32 = 0xC011_A504;
/// Parser-local VAST kind for GNU `asm goto` label operands.
pub const C_AST_KIND_ASM_GOTO_LABELS: u32 = 0xC011_A505;
/// Parser-local VAST kind for GNU `asm` qualifiers such as `volatile` and `goto`.
pub const C_AST_KIND_ASM_QUALIFIER: u32 = 0xC011_A506;
/// Parser-local VAST kind for GNU `__attribute__` syntax nodes.
pub const C_AST_KIND_GNU_ATTRIBUTE: u32 = 0xC011_A771;
/// Parser-local VAST kind for GNU `section` attributes.
pub const C_AST_KIND_ATTRIBUTE_SECTION: u32 = 0xC011_A772;
/// Parser-local VAST kind for GNU `weak` attributes.
pub const C_AST_KIND_ATTRIBUTE_WEAK: u32 = 0xC011_A773;
/// Parser-local VAST kind for GNU `alias` attributes.
pub const C_AST_KIND_ATTRIBUTE_ALIAS: u32 = 0xC011_A774;
/// Parser-local VAST kind for GNU `aligned` attributes.
pub const C_AST_KIND_ATTRIBUTE_ALIGNED: u32 = 0xC011_A775;
/// Parser-local VAST kind for GNU `used` attributes.
pub const C_AST_KIND_ATTRIBUTE_USED: u32 = 0xC011_A776;
/// Parser-local VAST kind for GNU `unused` attributes.
pub const C_AST_KIND_ATTRIBUTE_UNUSED: u32 = 0xC011_A777;
/// Parser-local VAST kind for GNU `naked` attributes.
pub const C_AST_KIND_ATTRIBUTE_NAKED: u32 = 0xC011_A778;
/// Parser-local VAST kind for GNU `visibility` attributes.
pub const C_AST_KIND_ATTRIBUTE_VISIBILITY: u32 = 0xC011_A779;
/// Parser-local VAST kind for GNU `packed` attributes.
pub const C_AST_KIND_ATTRIBUTE_PACKED: u32 = 0xC011_A77A;
/// Parser-local VAST kind for GNU `cleanup` attributes.
pub const C_AST_KIND_ATTRIBUTE_CLEANUP: u32 = 0xC011_A77B;
/// Parser-local VAST kind for GNU `constructor` attributes.
pub const C_AST_KIND_ATTRIBUTE_CONSTRUCTOR: u32 = 0xC011_A77C;
/// Parser-local VAST kind for GNU `destructor` attributes.
pub const C_AST_KIND_ATTRIBUTE_DESTRUCTOR: u32 = 0xC011_A77D;
/// Parser-local VAST kind for GNU `mode` attributes.
pub const C_AST_KIND_ATTRIBUTE_MODE: u32 = 0xC011_A77E;
/// Parser-local VAST kind for GNU `noinline` attributes.
pub const C_AST_KIND_ATTRIBUTE_NOINLINE: u32 = 0xC011_A77F;
/// Parser-local VAST kind for GNU `always_inline` attributes.
pub const C_AST_KIND_ATTRIBUTE_ALWAYS_INLINE: u32 = 0xC011_A780;
/// Parser-local VAST kind for GNU `cold` attributes.
pub const C_AST_KIND_ATTRIBUTE_COLD: u32 = 0xC011_A781;
/// Parser-local VAST kind for GNU `hot` attributes.
pub const C_AST_KIND_ATTRIBUTE_HOT: u32 = 0xC011_A782;
/// Parser-local VAST kind for GNU `pure` attributes.
pub const C_AST_KIND_ATTRIBUTE_PURE: u32 = 0xC011_A783;
/// Parser-local VAST kind for GNU `const` attributes.
pub const C_AST_KIND_ATTRIBUTE_CONST: u32 = 0xC011_A784;
/// Parser-local VAST kind for GNU `format` attributes.
pub const C_AST_KIND_ATTRIBUTE_FORMAT: u32 = 0xC011_A785;
/// Parser-local VAST kind for GNU `fallthrough` attributes.
pub const C_AST_KIND_ATTRIBUTE_FALLTHROUGH: u32 = 0xC011_A786;
/// Parser-local VAST kind for GNU labels-as-values address expressions.
pub const C_AST_KIND_GNU_LABEL_ADDRESS_EXPR: u32 = 0xC011_AADD;
/// Parser-local VAST kind for C/GNU label definitions (`identifier:`).
pub const C_AST_KIND_LABEL_STMT: u32 = 0xC011_5714;
/// Parser-local VAST kind for GNU statement expressions (`({ ... })`).
pub const C_AST_KIND_GNU_STATEMENT_EXPR: u32 = 0xC011_E00C;
/// Parser-local VAST kind for GNU `__builtin_expect(...)` expressions.
pub const C_AST_KIND_BUILTIN_EXPECT_EXPR: u32 = 0xC011_E00D;
/// Parser-local VAST kind for GNU `__builtin_offsetof(...)` expressions.
pub const C_AST_KIND_BUILTIN_OFFSETOF_EXPR: u32 = 0xC011_E00E;
/// Parser-local VAST kind for GNU `__builtin_object_size(...)` expressions.
pub const C_AST_KIND_BUILTIN_OBJECT_SIZE_EXPR: u32 = 0xC011_E00F;
/// Parser-local VAST kind for GNU `__builtin_prefetch(...)` expressions.
pub const C_AST_KIND_BUILTIN_PREFETCH_EXPR: u32 = 0xC011_E010;
/// Parser-local VAST kind for GNU `__builtin_unreachable()` statements.
pub const C_AST_KIND_BUILTIN_UNREACHABLE_STMT: u32 = 0xC011_5715;
/// Parser-local VAST kind for GNU checked-overflow builtin expressions.
pub const C_AST_KIND_BUILTIN_OVERFLOW_EXPR: u32 = 0xC011_E012;
/// Parser-local VAST kind for GNU `__builtin_classify_type(...)` expressions.
pub const C_AST_KIND_BUILTIN_CLASSIFY_TYPE_EXPR: u32 = 0xC011_E013;
/// Parser-local VAST kind for GNU local label declarations (`__label__ x;`).
pub const C_AST_KIND_GNU_LOCAL_LABEL_DECL: u32 = 0xC011_5716;
/// Parser-local VAST kind for C `if` statement nodes.
pub const C_AST_KIND_IF_STMT: u32 = 0xC011_5701;
/// Parser-local VAST kind for C `else` branch statement nodes.
pub const C_AST_KIND_ELSE_STMT: u32 = 0xC011_5702;
/// Parser-local VAST kind for C `switch` statement nodes.
pub const C_AST_KIND_SWITCH_STMT: u32 = 0xC011_5703;
/// Parser-local VAST kind for C `case` label statement nodes.
pub const C_AST_KIND_CASE_STMT: u32 = 0xC011_5704;
/// Parser-local VAST kind for C `default` label statement nodes.
pub const C_AST_KIND_DEFAULT_STMT: u32 = 0xC011_5705;
/// Parser-local VAST kind for C `for` loop statement nodes.
pub const C_AST_KIND_FOR_STMT: u32 = 0xC011_5706;
/// Parser-local VAST kind for C `while` loop statement nodes.
pub const C_AST_KIND_WHILE_STMT: u32 = 0xC011_5707;
/// Parser-local VAST kind for C `do` loop statement nodes.
pub const C_AST_KIND_DO_STMT: u32 = 0xC011_5708;
/// Parser-local VAST kind for C `return` jump statement nodes.
pub const C_AST_KIND_RETURN_STMT: u32 = 0xC011_5709;
/// Parser-local VAST kind for C `break` jump statement nodes.
pub const C_AST_KIND_BREAK_STMT: u32 = 0xC011_570A;
/// Parser-local VAST kind for C `continue` jump statement nodes.
pub const C_AST_KIND_CONTINUE_STMT: u32 = 0xC011_570B;
/// Parser-local VAST kind for C `goto` jump statement nodes.
pub const C_AST_KIND_GOTO_STMT: u32 = 0xC011_570C;
/// Parser-local VAST kind for C assignment expression operator nodes.
pub const C_AST_KIND_ASSIGN_EXPR: u32 = 0xC011_E001;
/// Parser-local VAST kind for C member access operator nodes.
pub const C_AST_KIND_MEMBER_ACCESS_EXPR: u32 = 0xC011_E002;
/// Parser-local VAST kind for C `sizeof` expression nodes.
pub const C_AST_KIND_SIZEOF_EXPR: u32 = 0xC011_E003;
/// Parser-local VAST kind for C11 `_Alignof` expression nodes.
pub const C_AST_KIND_ALIGNOF_EXPR: u32 = 0xC011_E011;
/// Parser-local VAST kind for C ternary conditional marker nodes.
pub const C_AST_KIND_CONDITIONAL_EXPR: u32 = 0xC011_E004;
/// Parser-local VAST kind for C unary expression operator nodes.
pub const C_AST_KIND_UNARY_EXPR: u32 = 0xC011_E005;
/// Parser-local VAST kind for C array subscript delimiter nodes.
pub const C_AST_KIND_ARRAY_SUBSCRIPT_EXPR: u32 = 0xC011_E006;
/// Parser-local VAST kind for GNU `__builtin_constant_p(...)` expressions.
pub const C_AST_KIND_BUILTIN_CONSTANT_P_EXPR: u32 = 0xC011_E007;
/// Parser-local VAST kind for GNU `__builtin_choose_expr(...)` expressions.
pub const C_AST_KIND_BUILTIN_CHOOSE_EXPR: u32 = 0xC011_E008;
/// Parser-local VAST kind for GNU `__builtin_types_compatible_p(...)` expressions.
pub const C_AST_KIND_BUILTIN_TYPES_COMPATIBLE_P_EXPR: u32 = 0xC011_E009;
/// Parser-local VAST kind for C11 `_Generic(...)` selection expressions.
pub const C_AST_KIND_GENERIC_SELECTION_EXPR: u32 = 0xC011_E00A;
/// Parser-local VAST kind for GNU range designator ellipsis markers.
pub const C_AST_KIND_RANGE_DESIGNATOR_EXPR: u32 = 0xC011_E00B;
/// Parser-local VAST kind for C pointer declarator `*` nodes.
pub const C_AST_KIND_POINTER_DECL: u32 = 0xC011_D001;
/// Parser-local VAST kind for C array declarator `[` suffix nodes.
pub const C_AST_KIND_ARRAY_DECL: u32 = 0xC011_D002;
/// Parser-local VAST kind for C function declarator parameter-list nodes.
pub const C_AST_KIND_FUNCTION_DECLARATOR: u32 = 0xC011_D003;
/// Parser-local VAST kind for C cast-expression type-name paren nodes.
pub const C_AST_KIND_CAST_EXPR: u32 = 0xC011_CA57;
/// Parser-local VAST kind for C compound-literal type-name paren nodes.
pub const C_AST_KIND_COMPOUND_LITERAL_EXPR: u32 = 0xC011_C012;
/// Parser-local VAST kind for C initializer-list brace nodes.
pub const C_AST_KIND_INITIALIZER_LIST: u32 = 0xC011_1A57;
/// Parser-local VAST kind for C struct/union field declarator identifier nodes.
pub const C_AST_KIND_FIELD_DECL: u32 = 0xC011_F1E1;
/// Parser-local VAST kind for C enum enumerator identifier nodes.
pub const C_AST_KIND_ENUMERATOR_DECL: u32 = 0xC011_EE11;
/// Parser-local VAST kind for C `struct` tag declaration/specifier nodes.
pub const C_AST_KIND_STRUCT_DECL: u32 = 0xC011_570D;
/// Parser-local VAST kind for C `union` tag declaration/specifier nodes.
pub const C_AST_KIND_UNION_DECL: u32 = 0xC011_570E;
/// Parser-local VAST kind for C `enum` tag declaration/specifier nodes.
pub const C_AST_KIND_ENUM_DECL: u32 = 0xC011_570F;
/// Parser-local VAST kind for C `typedef` declaration nodes.
pub const C_AST_KIND_TYPEDEF_DECL: u32 = 0xC011_5710;
/// Parser-local VAST kind for C function definition declarator identifiers.
pub const C_AST_KIND_FUNCTION_DEFINITION: u32 = 0xC011_5711;
/// Parser-local VAST kind for C bit-field declarator identifier nodes.
pub const C_AST_KIND_BIT_FIELD_DECL: u32 = 0xC011_5712;
/// Parser-local VAST kind for C11 `_Static_assert(...)` declaration nodes.
pub const C_AST_KIND_STATIC_ASSERT_DECL: u32 = 0xC011_5713;
