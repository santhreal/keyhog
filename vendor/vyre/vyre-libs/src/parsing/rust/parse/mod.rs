//! Nano-subset Rust parser.

use crate::parsing::rust::lex::lexer::core::Token;
use crate::parsing::rust::lex::tokens::*;

/// Expression AST.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// Integer literal with source offset and value.
    LiteralInt(u32, u64),
    /// Boolean literal with source offset and value.
    LiteralBool(u32, bool),
    /// Variable reference by source offset.
    Var(u32),
    /// Binary operation.
    Binary {
        /// Operator token kind.
        op: u16,
        /// Left-hand side.
        lhs: Box<Expr>,
        /// Right-hand side.
        rhs: Box<Expr>,
    },
    /// Borrow expression.
    Borrow {
        /// Whether the borrow is mutable.
        mutable: bool,
        /// Borrowed expression.
        expr: Box<Expr>,
    },
    /// Dereference.
    Deref(Box<Expr>),
    /// Function call.
    Call {
        /// Function name source offset.
        name: u32,
        /// Arguments.
        args: Vec<Expr>,
    },
    /// Block expression.
    Block(Vec<Stmt>),
    /// Conditional.
    If {
        /// Condition.
        cond: Box<Expr>,
        /// Then block.
        then_block: Box<Expr>,
        /// Else block (optional).
        else_block: Option<Box<Expr>>,
    },
}

/// Statement AST.
#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    /// Let binding.
    Let {
        /// Whether the binding is mutable.
        mutable: bool,
        /// Name source offset.
        name: u32,
        /// Declared type.
        ty: Type,
        /// Initializer expression.
        init: Expr,
    },
    /// Expression statement.
    Expr(Expr),
    /// Return statement.
    Return(Option<Expr>),
}

/// Types in the nano-subset.
#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    /// 32-bit signed integer.
    I32,
    /// Boolean.
    Bool,
    /// Unit type.
    Unit,
    /// Reference type.
    Ref {
        /// Whether the reference is mutable.
        mutable: bool,
        /// Inner type.
        inner: Box<Type>,
    },
}

/// Function definition.
#[derive(Debug, Clone, PartialEq)]
pub struct Function {
    /// Name source offset.
    pub name: u32,
    /// Parameters: (name offset, type).
    pub params: Vec<(u32, Type)>,
    /// Return type.
    pub ret: Type,
    /// Body statements.
    pub body: Vec<Stmt>,
}

/// A parsed module.
#[derive(Debug, Clone, PartialEq)]
pub struct Module {
    /// Functions in the module.
    pub functions: Vec<Function>,
}

/// Parse error.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseError {
    /// Error message.
    pub message: String,
    /// Token index where the error occurred.
    pub token_index: usize,
}

/// Parse a token stream into a `Module`.
pub fn parse(source: &[u8], tokens: &[Token]) -> Result<Module, ParseError> {
    let mut p = Parser { source, tokens, pos: 0 };
    p.parse_module()
}

struct Parser<'a> {
    source: &'a [u8],
    tokens: &'a [Token],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> &Token {
        &self.tokens[self.pos.min(self.tokens.len() - 1)]
    }

    fn advance(&mut self) -> &Token {
        let tok = &self.tokens[self.pos.min(self.tokens.len() - 1)];
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
        tok
    }

    fn expect(&mut self, kind: u16) -> Result<&Token, ParseError> {
        let tok = self.peek();
        if tok.kind == kind {
            Ok(self.advance())
        } else {
            Err(ParseError {
                message: format!("expected token kind {}, got {}", kind, tok.kind),
                token_index: self.pos,
            })
        }
    }

    fn parse_module(&mut self) -> Result<Module, ParseError> {
        let mut functions = Vec::new();
        while self.peek().kind != EOF {
            functions.push(self.parse_function()?);
        }
        Ok(Module { functions })
    }

    fn parse_function(&mut self) -> Result<Function, ParseError> {
        self.expect(KW_FN)?;
        let name = self.expect(IDENT)?.start;
        self.expect(LPAREN)?;
        let params = self.parse_params()?;
        self.expect(RPAREN)?;
        let ret = if self.peek().kind == ARROW {
            self.advance();
            self.parse_type()?
        } else {
            Type::Unit
        };
        let body = self.parse_block()?;
        Ok(Function { name, params, ret, body })
    }

    fn parse_params(&mut self) -> Result<Vec<(u32, Type)>, ParseError> {
        let mut params = Vec::new();
        if self.peek().kind == RPAREN {
            return Ok(params);
        }
        loop {
            let name = self.expect(IDENT)?.start;
            self.expect(COLON)?;
            let ty = self.parse_type()?;
            params.push((name, ty));
            if self.peek().kind == COMMA {
                self.advance();
            } else {
                break;
            }
        }
        Ok(params)
    }

    fn parse_type(&mut self) -> Result<Type, ParseError> {
        match self.peek().kind {
            KW_I32 => { self.advance(); Ok(Type::I32) }
            KW_BOOL => { self.advance(); Ok(Type::Bool) }
            AMP | AMP_MUT => {
                let mutable = self.peek().kind == AMP_MUT;
                self.advance();
                let inner = self.parse_type()?;
                Ok(Type::Ref { mutable, inner: Box::new(inner) })
            }
            _ => Err(ParseError { message: "expected type".into(), token_index: self.pos }),
        }
    }

    fn parse_block(&mut self) -> Result<Vec<Stmt>, ParseError> {
        self.expect(LBRACE)?;
        let mut stmts = Vec::new();
        while self.peek().kind != RBRACE && self.peek().kind != EOF {
            stmts.push(self.parse_stmt()?);
        }
        self.expect(RBRACE)?;
        Ok(stmts)
    }

    fn parse_stmt(&mut self) -> Result<Stmt, ParseError> {
        match self.peek().kind {
            KW_LET => self.parse_let(),
            KW_RETURN => self.parse_return(),
            _ => {
                let expr = self.parse_expr()?;
                self.expect(SEMI)?;
                Ok(Stmt::Expr(expr))
            }
        }
    }

    fn parse_let(&mut self) -> Result<Stmt, ParseError> {
        self.expect(KW_LET)?;
        let mutable = if self.peek().kind == KW_MUT { self.advance(); true } else { false };
        let name = self.expect(IDENT)?.start;
        self.expect(COLON)?;
        let ty = self.parse_type()?;
        self.expect(ASSIGN)?;
        let init = self.parse_expr()?;
        self.expect(SEMI)?;
        Ok(Stmt::Let { mutable, name, ty, init })
    }

    fn parse_return(&mut self) -> Result<Stmt, ParseError> {
        self.expect(KW_RETURN)?;
        let expr = if self.peek().kind != SEMI { Some(self.parse_expr()?) } else { None };
        self.expect(SEMI)?;
        Ok(Stmt::Return(expr))
    }

    fn parse_expr(&mut self) -> Result<Expr, ParseError> { self.parse_cmp() }

    fn parse_cmp(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_term()?;
        while matches!(self.peek().kind, EQ | LT) {
            let op = self.advance().kind;
            lhs = Expr::Binary { op, lhs: Box::new(lhs), rhs: Box::new(self.parse_term()?) };
        }
        Ok(lhs)
    }

    fn parse_term(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_factor()?;
        while matches!(self.peek().kind, PLUS | MINUS) {
            let op = self.advance().kind;
            lhs = Expr::Binary { op, lhs: Box::new(lhs), rhs: Box::new(self.parse_factor()?) };
        }
        Ok(lhs)
    }

    fn parse_factor(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_unary()?;
        while matches!(self.peek().kind, STAR | SLASH) {
            let op = self.advance().kind;
            lhs = Expr::Binary { op, lhs: Box::new(lhs), rhs: Box::new(self.parse_unary()?) };
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        match self.peek().kind {
            AMP | AMP_MUT => {
                let mutable = self.peek().kind == AMP_MUT;
                self.advance();
                Ok(Expr::Borrow { mutable, expr: Box::new(self.parse_unary()?) })
            }
            STAR => { self.advance(); Ok(Expr::Deref(Box::new(self.parse_unary()?))) }
            _ => self.parse_primary(),
        }
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        match self.peek().kind {
            LITERAL_INT => {
                let tok = *self.advance();
                let val = tok.text(self.source).parse::<u64>().unwrap_or(0);
                Ok(Expr::LiteralInt(tok.start, val))
            }
            LITERAL_BOOL => {
                let tok = *self.advance();
                let b = tok.text(self.source) == "true";
                Ok(Expr::LiteralBool(tok.start, b))
            }
            IDENT => {
                let name = self.advance().start;
                if self.peek().kind == LPAREN {
                    self.advance();
                    let mut args = Vec::new();
                    if self.peek().kind != RPAREN {
                        loop {
                            args.push(self.parse_expr()?);
                            if self.peek().kind == COMMA { self.advance(); } else { break; }
                        }
                    }
                    self.expect(RPAREN)?;
                    Ok(Expr::Call { name, args })
                } else {
                    Ok(Expr::Var(name))
                }
            }
            LBRACE => Ok(Expr::Block(self.parse_block()?)),
            KW_IF => {
                self.advance();
                let cond = Box::new(self.parse_expr()?);
                let then_block = Box::new(Expr::Block(self.parse_block()?));
                let else_block = if self.peek().kind == KW_ELSE {
                    self.advance();
                    if self.peek().kind == KW_IF {
                        Some(Box::new(self.parse_expr()?))
                    } else {
                        Some(Box::new(Expr::Block(self.parse_block()?)))
                    }
                } else { None };
                Ok(Expr::If { cond, then_block, else_block })
            }
            _ => Err(ParseError { message: "unexpected token in expression".into(), token_index: self.pos }),
        }
    }
}
