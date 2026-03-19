#include "rd_parser.h"

#include <algorithm>
#include <climits>
#include <functional>
#include <set>
#include <sstream>
#include <unordered_set>

#include "log.h"
#include "util/int_parser.h"

namespace bpftrace {

// Public Methods

ast::Program *RDParser::parse()
{
  input_ = &ctx_.source_->contents;
  pos_ = 0;
  line_ = 1;
  col_ = 1;
  return parse_program();
}

// For the CMacroExpander pass
std::optional<ast::Expression> RDParser::parse_expr()
{
  input_ = &ctx_.source_->contents;
  pos_ = 0;
  line_ = 1;
  col_ = 1;
  skip_whitespace();
  if (at_end()) {
    return std::nullopt;
  }
  auto expr = parse_expression();
  skip_whitespace();
  if (!at_end()) {
    error("unexpected input");
  }
  if (ctx_.diagnostics().ok()) {
    return expr;
  }
  return std::nullopt;
}

// Grammar rules

ast::Program *RDParser::parse_program()
{
  ast::RootImportList imports;
  ast::RootStatements root_stmts;
  std::optional<std::string> header;

  // Preamble: config and imports must appear before everything else.
  // They can be in any order relative to each other.
  ast::CStatementList c_stmts;
  ast::Config *config = nullptr;
  skip_whitespace();

  // Skip shebang line (e.g. "#!/usr/bin/env bpftrace")
  if (peek() == '#' && peek(1) == '!') {
    size_t header_start = pos_;
    while (!at_end() && peek() != '\n') {
      advance();
    }
    if (!at_end() && peek() == '\n') {
      advance();
    }
    header = input_->substr(header_start, pos_ - header_start);
    skip_whitespace();
  }

  while (!at_end()) {
    // Config block (at most one).
    if (check_keyword("config")) {
      if (!config) {
        config = parse_config();
      } else {
        auto current_pos = get_current_line_col();
        match("config");
        error("duplicate config block",
              current_pos.line,
              current_pos.col,
              line_,
              col_);
        skip_config_block();
      }
      skip_whitespace();
      continue;
    }
    // Root-level imports.
    if (check_keyword("import")) {
      auto *imp = parse_root_import();
      if (imp) {
        imports.push_back(imp);
      }
      skip_whitespace();
      continue;
    }
    break;
  }

  // C definitions: #include, struct/union/enum definitions.
  // Must appear after config/imports but before probes/macros/functions.
  skip_whitespace();
  while (!at_end()) {
    // C preprocessor directives: #include, #define, etc.
    if (peek() == '#' && peek(1) != '!') {
      c_stmts.push_back(parse_c_preprocessor());
      skip_whitespace();
      continue;
    }
    // C struct/union/enum definitions: struct Name { ... }
    if ((check_keyword("struct") || check_keyword("union") ||
         check_keyword("enum")) &&
        looks_like_c_definition()) {
      c_stmts.push_back(parse_c_definition());
      skip_whitespace();
      continue;
    }
    break;
  }

  // Main loop: probes, macros, functions, and map declarations.
  while (!at_end()) {
    skip_whitespace();
    if (at_end()) {
      break;
    }
    size_t before = pos_;
    if (peek() == '#' && peek(1) != '!') {
      auto current_pos = get_current_line_col();
      c_stmts.push_back(parse_c_preprocessor());
      error("C definitions must appear before probes and functions",
            current_pos.line,
            current_pos.col,
            line_,
            col_);
    } else if ((check_keyword("struct") || check_keyword("union") ||
                check_keyword("enum"))) {
      if (looks_like_c_definition()) {
        auto current_pos = get_current_line_col();
        c_stmts.push_back(parse_c_definition());
        error("C definitions must appear before probes and functions",
              current_pos.line,
              current_pos.col,
              line_,
              col_);
      } else {
        // Not a C definition — treat as probe.
        auto *probe = parse_probe();
        if (probe) {
          root_stmts.emplace_back(probe);
        }
      }
    } else if (check_keyword("config")) {
      auto current_pos = get_current_line_col();
      match("config");
      error("config must appear before probes and functions",
            current_pos.line,
            current_pos.col,
            line_,
            col_);
      skip_config_block();
    } else if (check_keyword("import")) {
      auto current_pos = get_current_line_col();
      match("import");
      error("imports must appear before probes and functions",
            current_pos.line,
            current_pos.col,
            line_,
            col_);
      while (!at_end() && peek() != ';' && peek() != '\n') {
        advance();
      }
      match(';');
    } else if (check_keyword("macro")) {
      auto *macro = parse_macro();
      if (macro) {
        root_stmts.emplace_back(macro);
      }
    } else if (check_keyword("fn")) {
      auto *subprog = parse_subprog();
      if (subprog) {
        root_stmts.emplace_back(subprog);
      }
    } else if (check_keyword("let")) {
      // At root level, `let @...` is a map declaration.
      constexpr std::string_view let_kw = "let";
      size_t p = pos_;
      while (in_bounds(p) && std::isspace(at(p))) {
        p++;
      }
      p += let_kw.size();
      while (in_bounds(p) && std::isspace(at(p))) {
        p++;
      }
      if (in_bounds(p) && at(p) == '@') {
        auto *map_decl = parse_map_decl_stmt();
        if (map_decl) {
          root_stmts.emplace_back(map_decl);
        }
      } else {
        error("root-level let statements need to be map declarations, e.g. let "
              "@a = hash(2);");
        advance();
      }
    } else {
      auto *probe = parse_probe();
      if (probe) {
        root_stmts.emplace_back(probe);
      }
    }
    // If nothing was consumed, skip the current character to avoid
    // an infinite loop (e.g. when parsing stdlib files that contain
    // only macros and the last token wasn't recognized).
    if (pos_ == before) {
      error("unexpected input");
      advance();
    }
    skip_whitespace();
  }

  auto loc = make_loc(1, 1, line_, col_);
  return ctx_.make_node<ast::Program>(loc,
                                      std::move(c_stmts),
                                      config,
                                      std::move(imports),
                                      std::move(root_stmts),
                                      std::move(header));
}

ast::CStatement *RDParser::parse_c_preprocessor()
{
  auto [begin_line, begin_col] = get_current_line_col();
  std::string line;
  while (!at_end() && peek() != '\n') {
    line += peek();
    advance();
  }
  // Trim trailing whitespace.
  while (!line.empty() && std::isspace(line.back())) {
    line.pop_back();
  }
  auto loc = make_loc(begin_line, begin_col, line_, col_);
  if (!at_end() && peek() == '\n') {
    advance();
  }
  return ctx_.make_node<ast::CStatement>(loc, std::move(line));
}

ast::CStatement *RDParser::parse_c_definition()
{
  auto [begin_line, begin_col] = get_current_line_col();
  std::string def;
  // Consume keyword and name up to '{'.
  while (!at_end() && peek() != '{') {
    def += peek();
    advance();
  }
  // Consume balanced braces, skipping string/char literals and comments.
  int depth = 0;
  while (!at_end()) {
    char c = peek();
    if (c == '"' || c == '\'') {
      // String or character literal: consume until matching unescaped quote.
      char quote = c;
      def += c;
      advance();
      while (!at_end() && peek() != quote) {
        if (peek() == '\\') {
          def += peek();
          advance();
          if (at_end()) {
            break;
          }
        }
        def += peek();
        advance();
      }
      if (!at_end()) {
        def += peek(); // closing quote
        advance();
      }
      continue;
    }
    if (c == '/' && peek(1) != '\0') {
      char next = peek(1);
      if (next == '/') {
        // Line comment: consume until newline.
        while (!at_end() && peek() != '\n') {
          def += peek();
          advance();
        }
        continue;
      }
      if (next == '*') {
        // Block comment: consume until "*/".
        def += peek();
        advance(); // '/'
        def += peek();
        advance(); // '*'
        while (!at_end()) {
          if (peek() == '*' && peek(1) == '/') {
            def += peek();
            advance(); // '*'
            def += peek();
            advance(); // '/'
            break;
          }
          def += peek();
          advance();
        }
        continue;
      }
    }
    if (c == '{') {
      depth++;
    } else if (c == '}') {
      depth--;
    }
    def += c;
    advance();
    if (depth == 0) {
      break;
    }
  }
  // Trim trailing whitespace.
  while (!def.empty() && std::isspace(def.back())) {
    def.pop_back();
  }
  // Ensure trailing semicolon.
  if (!def.empty() && def.back() != ';') {
    def += ";";
  }
  // Consume optional trailing semicolon from source.
  skip_whitespace();
  if (!at_end() && peek() == ';') {
    advance();
  }
  auto loc = make_loc(begin_line, begin_col, line_, col_);
  return ctx_.make_node<ast::CStatement>(loc, std::move(def));
}

ast::Config *RDParser::parse_config()
{
  auto [begin_line, begin_col] = get_current_line_col();
  if (!match("config")) {
    return nullptr;
  }

  if (!expect('=')) {
    return nullptr;
  }
  if (!expect('{')) {
    return nullptr;
  }

  ast::ConfigStatementList stmts;
  skip_whitespace();
  while (peek() != '}' && !at_end()) {
    auto [stmt_line, stmt_col] = get_current_line_col();
    auto key = consume_identifier();
    if (key.empty()) {
      error("expected config key");
      break;
    }
    if (!expect('=')) {
      break;
    }

    skip_whitespace();
    auto stmt_loc = make_loc(stmt_line, stmt_col, line_, col_);

    if (peek() == '"') {
      auto val = consume_string();
      stmt_loc = make_loc(stmt_line, stmt_col, line_, col_);
      stmts.push_back(ctx_.make_node<ast::AssignConfigVarStatement>(
          stmt_loc, std::move(key), std::move(val)));
    } else if (check_keyword("true") || check_keyword("false")) {
      bool val = check_keyword("true");
      if (val) {
        match("true");
      } else {
        match("false");
      }
      stmt_loc = make_loc(stmt_line, stmt_col, line_, col_);
      stmts.push_back(ctx_.make_node<ast::AssignConfigVarStatement>(
          stmt_loc, std::move(key), val));
    } else if (std::isdigit(peek())) {
      auto int_str = consume_integer_str();
      auto res = util::to_uint(int_str, 0);
      if (!res) {
        error("invalid integer in config");
        break;
      }
      stmt_loc = make_loc(stmt_line, stmt_col, line_, col_);
      stmts.push_back(ctx_.make_node<ast::AssignConfigVarStatement>(
          stmt_loc, std::move(key), static_cast<uint64_t>(*res)));
    } else {
      auto val = consume_identifier();
      stmt_loc = make_loc(stmt_line, stmt_col, line_, col_);
      stmts.push_back(ctx_.make_node<ast::AssignConfigVarStatement>(
          stmt_loc, std::move(key), std::move(val)));
    }
    skip_whitespace();
    if (peek() != '}' && !match(';')) {
      expect(';');
      // Skip to closing '}' to avoid cascading errors.
      while (!at_end() && peek() != '}') {
        advance();
      }
      break;
    }
    match(';');
    skip_whitespace();
  }

  expect('}');
  auto loc = make_loc(begin_line, begin_col, line_, col_);
  return ctx_.make_node<ast::Config>(loc, std::move(stmts));
}

void RDParser::skip_config_block()
{
  skip_whitespace();
  if (match('=')) {
    skip_whitespace();
    if (match('{')) {
      int depth = 1;
      while (!at_end() && depth > 0) {
        if (peek() == '{') {
          depth++;
        } else if (peek() == '}') {
          depth--;
        }
        if (depth > 0) {
          advance();
        }
      }
      if (!at_end()) {
        advance(); // skip closing '}'
      }
    }
  }
}

ast::RootImport *RDParser::parse_root_import()
{
  auto [begin_line, begin_col] = get_current_line_col();
  if (!match("import")) {
    error("expected 'import'");
    return nullptr;
  }

  skip_whitespace();
  if (peek() != '"') {
    error("expected string after 'import'");
    return nullptr;
  }
  auto path = consume_string();
  auto loc = make_loc(begin_line, begin_col, line_, col_);
  if (!match(';')) {
    error("expected ';' after import");
    return nullptr;
  }

  return ctx_.make_node<ast::RootImport>(loc, std::move(path));
}

ast::Macro *RDParser::parse_macro()
{
  auto [begin_line, begin_col] = get_current_line_col();
  if (!match("macro")) {
    error("expected 'macro'");
    return nullptr;
  }

  auto name = consume_identifier();
  if (name.empty()) {
    error("expected macro name");
    return nullptr;
  }
  auto name_loc = make_loc(begin_line, begin_col, line_, col_);

  if (!expect('(')) {
    return nullptr;
  }

  // Parse macro arguments: $var, @map, or plain identifiers.
  ast::ExpressionList args;
  skip_whitespace();
  if (peek() != ')') {
    args.push_back(parse_macro_arg());
    while (match(',')) {
      args.push_back(parse_macro_arg());
    }
  }

  if (!expect(')')) {
    return nullptr;
  }

  auto *block = parse_block();
  if (!block) {
    return nullptr;
  }

  return ctx_.make_node<ast::Macro>(
      name_loc, std::move(name), std::move(args), block);
}

ast::Expression RDParser::parse_macro_arg()
{
  skip_whitespace();
  auto [begin_line, begin_col] = get_current_line_col();

  if (peek() == '$') {
    advance();
    auto var_name = consume_identifier();
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *var = ctx_.make_node<ast::Variable>(loc, "$" + var_name);
    return { var };
  }

  if (peek() == '@') {
    advance();
    auto map_name = consume_identifier();
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *map = ctx_.make_node<ast::Map>(loc, "@" + map_name);
    return { map };
  }

  auto ident = consume_identifier();
  if (!ident.empty()) {
    if (is_builtin(ident)) {
      error("builtin '" + ident + "' can't be used as a macro argument",
            begin_line,
            begin_col,
            line_,
            col_);
      auto *none = make_none();
      return { none };
    }
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *id = ctx_.make_node<ast::Identifier>(loc, std::move(ident));
    return { id };
  }

  error("expected macro argument ($var, @map, or identifier)");
  auto *none = make_none();
  return { none };
}

ast::Subprog *RDParser::parse_subprog()
{
  auto [begin_line, begin_col] = get_current_line_col();
  if (!match("fn")) {
    error("expected 'fn'");
    return nullptr;
  }

  auto name = consume_identifier();
  if (name.empty()) {
    error("expected function name");
    return nullptr;
  }
  auto name_loc = make_loc(begin_line, begin_col, line_, col_);

  if (!expect('(')) {
    return nullptr;
  }

  ast::SubprogArgList args;
  skip_whitespace();
  if (peek() != ')') {
    // Parse first arg: $var : type
    while (true) {
      skip_whitespace();
      auto [arg_line, arg_col] = get_current_line_col();
      if (peek() != '$') {
        error("expected variable in function argument");
        break;
      }
      advance();
      auto var_name = consume_identifier();
      auto var_loc = make_loc(arg_line, arg_col, line_, col_);
      auto *var = ctx_.make_node<ast::Variable>(var_loc, "$" + var_name);
      if (!expect(':')) {
        break;
      }
      auto *type = parse_type_annotation();
      if (!type) {
        break;
      }
      auto arg_loc = make_loc(arg_line, arg_col, line_, col_);
      args.push_back(ctx_.make_node<ast::SubprogArg>(arg_loc, var, type));
      if (!match(',')) {
        break;
      }
    }
  }

  if (!expect(')')) {
    return nullptr;
  }
  if (!expect(':')) {
    return nullptr;
  }

  auto *return_type = parse_type_annotation();
  if (!return_type) {
    return nullptr;
  }

  auto *block = parse_block(false);
  if (!block) {
    return nullptr;
  }

  return ctx_.make_node<ast::Subprog>(
      name_loc, std::move(name), return_type, std::move(args), block);
}

ast::MapDeclStatement *RDParser::parse_map_decl_stmt()
{
  auto [begin_line, begin_col] = get_current_line_col();
  if (!match("let")) {
    error("expected 'let'");
    return nullptr;
  }

  skip_whitespace();
  if (peek() != '@') {
    error("expected '@' in map declaration");
    return nullptr;
  }
  advance();
  auto map_name = consume_identifier();
  std::string full_name = "@" + map_name;
  if (map_name.empty()) {
    full_name = "@";
  }

  if (!expect('=')) {
    return nullptr;
  }

  auto type_name = consume_identifier();
  if (type_name.empty()) {
    error("expected map type name");
    return nullptr;
  }

  if (!expect('(')) {
    return nullptr;
  }
  auto int_str = consume_integer_str();
  auto res = util::to_uint(int_str, 0);
  if (!res) {
    error("expected positive integer for map declaration max entries");
    return nullptr;
  }
  if (!expect(')')) {
    return nullptr;
  }
  match(';');
  auto loc = make_loc(begin_line, begin_col, line_, col_);

  return ctx_.make_node<ast::MapDeclStatement>(
      loc, std::move(full_name), std::move(type_name), *res);
}

ast::Probe *RDParser::parse_probe()
{
  auto [begin_line, begin_col] = get_current_line_col();
  ast::AttachPointList attach_points;

  auto *ap = parse_attach_point();
  if (!ap) {
    return nullptr;
  }
  attach_points.push_back(ap);

  // Multiple attach points separated by commas.
  while (match(',')) {
    skip_whitespace();
    // Allow trailing comma.
    if (peek() == '/' || peek() == '{') {
      break;
    }
    ap = parse_attach_point();
    if (!ap) {
      break;
    }
    attach_points.push_back(ap);
  }

  // The probe's location spans only the attach points (not the block).
  // Use the last attach point's end location.
  const auto &last_ap_loc = attach_points.back()->loc->current;
  auto ap_loc = make_loc(
      begin_line, begin_col, last_ap_loc.end.line, last_ap_loc.end.column);

  auto [pred_start_line, pred_start_col] = get_current_line_col();
  auto pred = parse_predicate();
  auto [pred_end_line, pred_end_col] = get_current_line_col();

  auto *block = parse_block(false);
  if (!block) {
    return nullptr;
  }

  if (pred.has_value()) {
    // Desugar predicate into: { if pred { <original block> } }
    auto pred_loc = make_loc(
        pred_start_line, pred_start_col, pred_end_line, pred_end_col);
    auto *none = ctx_.make_node<ast::None>(pred_loc);
    auto *cond = ctx_.make_node<ast::IfExpr>(
        pred_loc, pred.value(), block, none);
    block = ctx_.make_node<ast::BlockExpr>(pred_loc,
                                           ast::StatementList{},
                                           cond);
  }

  return ctx_.make_node<ast::Probe>(ap_loc, std::move(attach_points), block);
}

ast::AttachPoint *RDParser::parse_attach_point()
{
  skip_whitespace();
  auto [begin_line, begin_col] = get_current_line_col();

  // Consume everything up to a character that ends the attach point: '{', '/',
  // ',' or unescaped whitespace that is followed by one of those characters
  std::string raw;
  while (!at_end()) {
    char c = peek();

    if (c == '{' || c == ',') {
      break;
    }

    // '/' could be a predicate start or part of a path. It's a path
    // component if we've seen a ':' in the raw text (paths appear after
    // the provider separator, e.g. uprobe:/my/program:func).
    if (c == '/' && !raw.empty() && raw.find(':') == std::string::npos) {
      // No ':' seen yet — this '/' can't be a path, it's a predicate but check
      // it's not a comment.
      if (peek(1) != '\0') {
        char next = peek(1);
        if (next != '/' && next != '*') {
          break;
        }
      } else {
        break;
      }
    }

    if (std::isspace(c)) {
      size_t p = pos_;
      while (in_bounds(p) && std::isspace(at(p))) {
        p++;
      }
      if (!in_bounds(p)) {
        break;
      }
      char after = at(p);
      if (after == '{' || after == ',' || after == '/') {
        break;
      }
      // If we hit a newline and the next non-ws char doesn't continue
      // the attach point, stop. Otherwise consume the whitespace.
      break;
    }

    // Quoted string: consume entirely (for things like uprobe:"lib":func).
    if (c == '"') {
      raw += c;
      advance();
      while (!at_end() && peek() != '"') {
        if (peek() == '\\') {
          raw += peek();
          advance();
          if (!at_end()) {
            raw += peek();
            advance();
          }
          continue;
        }
        raw += peek();
        advance();
      }
      if (!at_end()) {
        raw += peek(); // closing quote
        advance();
      }
      continue;
    }

    raw += c;
    advance();
  }

  if (raw.empty()) {
    error("expected attach point");
    return nullptr;
  }

  auto loc = make_loc(begin_line, begin_col, line_, col_);
  return ctx_.make_node<ast::AttachPoint>(loc, std::move(raw), false);
}

std::optional<ast::Expression> RDParser::parse_predicate()
{
  skip_whitespace();
  if (peek() != '/') {
    return std::nullopt;
  }

  // Make sure this is a predicate '/' and not a comment '//' or '/*'.
  if (peek(1) != '\0') {
    char next = peek(1);
    if (next == '/' || next == '*') {
      return std::nullopt;
    }
  }

  advance();
  auto expr = parse_expression();

  if (!expect('/')) {
    error("expected '/' to close predicate");
  }

  return expr;
}

ast::BlockExpr *RDParser::parse_block(bool allow_trailing_expr)
{
  auto [block_line, block_col] = get_current_line_col();
  if (!expect('{')) {
    return nullptr;
  }

  ast::StatementList stmts;
  std::optional<ast::Expression> trailing_expr;
  skip_whitespace();

  while (peek() != '}' && !at_end()) {
    size_t before = pos_;
    // Statement-level import: import "path";
    if (check_keyword("import")) {
      auto *imp = parse_statement_import();
      if (imp) {
        stmts.emplace_back(imp);
      }
      skip_whitespace();
      if (pos_ == before) {
        error("unexpected input in block");
        advance();
      }
      continue;
    }
    // While/unroll statements.
    if (check_keyword("while") || check_keyword("unroll")) {
      auto stmt = parse_while_or_unroll();
      stmts.push_back(std::move(stmt));
      skip_whitespace();
      continue;
    }
    // For statements.
    if (check_keyword("for")) {
      auto stmt = parse_for();
      stmts.push_back(std::move(stmt));
      skip_whitespace();
      continue;
    }
    // Jump statements: break, continue, return.
    if (check_keyword("break")) {
      auto [begin_line, begin_col] = get_current_line_col();
      match("break");
      expect_stmt_end();
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      auto *jump = ctx_.make_node<ast::Jump>(loc, ast::JumpType::BREAK);
      stmts.emplace_back(jump);
      skip_whitespace();
      continue;
    }
    if (check_keyword("continue")) {
      auto [begin_line, begin_col] = get_current_line_col();
      match("continue");
      expect_stmt_end();
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      auto *jump = ctx_.make_node<ast::Jump>(loc, ast::JumpType::CONTINUE);
      stmts.emplace_back(jump);
      skip_whitespace();
      continue;
    }
    if (check_keyword("return")) {
      auto [begin_line, begin_col] = get_current_line_col();
      match("return");
      skip_whitespace();
      if (peek() == ';' || peek() == '}') {
        expect_stmt_end();
        auto loc = make_loc(begin_line, begin_col, line_, col_);
        auto *jump = ctx_.make_node<ast::Jump>(loc, ast::JumpType::RETURN);
        stmts.emplace_back(jump);
      } else {
        auto expr = parse_expression();
        expect_stmt_end();
        auto loc = make_loc(begin_line, begin_col, line_, col_);
        auto *jump = ctx_.make_node<ast::Jump>(loc,
                                               ast::JumpType::RETURN,
                                               std::move(expr));
        stmts.emplace_back(jump);
      }
      skip_whitespace();
      continue;
    }
    // Discard expression: _ = expr;
    if (peek() == '_') {
      // Check if next non-ws after '_' is '='
      size_t p = pos_ + 1;
      while (in_bounds(p) && std::isspace(at(p))) {
        p++;
      }
      if (in_bounds(p) && at(p) == '=' &&
          (!in_bounds(p + 1) || at(p + 1) != '=')) {
        auto [begin_line, begin_col] = get_current_line_col();
        advance(); // consume '_'
        skip_whitespace();
        advance(); // consume '='
        auto expr = parse_expression();
        auto loc = make_loc(begin_line, begin_col, line_, col_);
        match(';');
        auto *discard = ctx_.make_node<ast::DiscardExpr>(loc, std::move(expr));
        stmts.emplace_back(discard);
        skip_whitespace();
        continue;
      }
    }
    // Check if this is a statement (assignment/let) or an expression.
    if (check_keyword("let")) {
      auto stmt = parse_statement();
      stmts.push_back(std::move(stmt));
    } else if (peek() == '$' || peek() == '@') {
      parse_sigiled_stmt_or_trailing_expr(allow_trailing_expr,
                                          stmts,
                                          trailing_expr);
    } else {
      auto [begin_line, begin_col] = get_current_line_col();
      auto expr = parse_expression();
      skip_whitespace();

      if (peek() == ';') {
        advance();
        auto loc = make_loc(begin_line, begin_col, line_, col_);
        auto *expr_stmt = ctx_.make_node<ast::ExprStatement>(loc,
                                                             std::move(expr));
        stmts.emplace_back(expr_stmt);
      } else if (peek() == '}') {
        // No semicolon before closing brace: trailing expression.
        trailing_expr = std::move(expr);
      } else {
        auto loc = make_loc(begin_line, begin_col, line_, col_);
        auto *expr_stmt = ctx_.make_node<ast::ExprStatement>(loc,
                                                             std::move(expr));
        if (!expr_stmt->expr.is<ast::IfExpr>() &&
            !expr_stmt->expr.is<ast::BlockExpr>()) {
          error("expected ';'");
        }
        stmts.emplace_back(expr_stmt);
      }
    }
    if (pos_ == before) {
      error("unexpected input in block");
      advance();
    }
    skip_whitespace();
  }

  if (!expect('}')) {
    return nullptr;
  }

  auto loc = make_loc(block_line, block_col, line_, col_);

  if (trailing_expr) {
    if (allow_trailing_expr) {
      return ctx_.make_node<ast::BlockExpr>(loc,
                                            std::move(stmts),
                                            std::move(*trailing_expr));
    }
    // Normalize nested block expressions before converting to statement.
    normalize_block_expression(*trailing_expr);
    // Convert trailing expression to a statement (none_block semantics).
    auto *expr_stmt = ctx_.make_node<ast::ExprStatement>(
        loc, std::move(*trailing_expr));
    stmts.emplace_back(expr_stmt);
  }
  auto *none = ctx_.make_node<ast::None>(loc);
  return ctx_.make_node<ast::BlockExpr>(loc,
                                        std::move(stmts),
                                        ast::Expression(none));
}

void RDParser::normalize_block_expression(ast::Expression &expr)
{
  if (auto *block = expr.as<ast::BlockExpr>()) {
    for (auto &stmt : block->stmts) {
      if (auto *expr_stmt = stmt.as<ast::ExprStatement>()) {
        normalize_block_expression(expr_stmt->expr);
      }
    }

    if (!block->expr.as<ast::None>()) {
      normalize_block_expression(block->expr);
      auto *expr_stmt = ctx_.make_node<ast::ExprStatement>(
          block->loc, std::move(block->expr));
      block->stmts.emplace_back(expr_stmt);
      auto *none = ctx_.make_node<ast::None>(block->loc);
      block->expr = ast::Expression(none);
    }
  }

  if (auto *if_expr = expr.as<ast::IfExpr>()) {
    normalize_block_expression(if_expr->left);
    normalize_block_expression(if_expr->right);
  }
}

bool RDParser::parse_sigiled_stmt_or_trailing_expr(
    bool allow_trailing_expr,
    ast::StatementList &stmts,
    std::optional<ast::Expression> &trailing_expr)
{
  auto sp = save_point();
  auto stmt = parse_statement();
  skip_whitespace();

  if (!allow_trailing_expr || peek() != '}') {
    stmts.push_back(std::move(stmt));
    return true;
  }

  auto *expr_stmt = stmt.as<ast::ExprStatement>();
  if (!expr_stmt) {
    stmts.push_back(std::move(stmt));
    return true;
  }

  sp.restore();
  auto expr = parse_expression();
  skip_whitespace();
  if (peek() == '}') {
    trailing_expr = std::move(expr);
    return true;
  }

  match(';');
  auto loc = make_loc(sp.line, sp.col, line_, col_);
  expr_stmt = ctx_.make_node<ast::ExprStatement>(loc, std::move(expr));
  stmts.emplace_back(expr_stmt);
  return true;
}

ast::StatementImport *RDParser::parse_statement_import()
{
  auto [begin_line, begin_col] = get_current_line_col();
  if (!match("import")) {
    error("expected 'import'");
    return nullptr;
  }

  skip_whitespace();
  if (peek() != '"') {
    error("expected string after 'import'");
    return nullptr;
  }
  auto path = consume_string();
  auto loc = make_loc(begin_line, begin_col, line_, col_);
  if (!match(';')) {
    error("expected ';' after import");
    return nullptr;
  }

  return ctx_.make_node<ast::StatementImport>(loc, std::move(path));
}

ast::Statement RDParser::parse_while_or_unroll()
{
  auto [begin_line, begin_col] = get_current_line_col();
  bool is_while = check_keyword("while");
  if (is_while) {
    match("while");
  } else {
    match("unroll");
  }

  // The condition is parsed as a unary expression (not a full expression)
  // so that the opening '{' of the block is not consumed as part of a
  // binary expression. Use parentheses for compound conditions:
  // while ($a > 0) { ... }
  auto cond = parse_unary();
  auto *block = parse_block(false);
  auto loc = make_loc(begin_line, begin_col, line_, col_);

  if (is_while) {
    auto *w = ctx_.make_node<ast::While>(loc, std::move(cond), block);
    return { w };
  }
  auto *u = ctx_.make_node<ast::Unroll>(loc, std::move(cond), block);
  return { u };
}

ast::Statement RDParser::parse_for()
{
  auto [begin_line, begin_col] = get_current_line_col();
  match("for");

  bool has_parens = match('(');

  skip_whitespace();
  if (peek() != '$') {
    error("expected variable in for loop");
    skip_to_block_end();
    auto *none = make_none();
    auto *es = ctx_.make_node<ast::ExprStatement>(none->loc,
                                                  ast::Expression(none));
    return { es };
  }
  auto [var_line, var_col] = get_current_line_col();
  advance(); // consume '$'
  auto var_name = consume_identifier();
  auto var_loc = make_loc(var_line, var_col, line_, col_);
  auto *var = ctx_.make_node<ast::Variable>(var_loc, "$" + var_name);

  if (!expect(':')) {
    skip_to_block_end();
    auto *none = make_none();
    auto *es = ctx_.make_node<ast::ExprStatement>(none->loc,
                                                  ast::Expression(none));
    return { es };
  }

  skip_whitespace();

  auto first = parse_primary();
  skip_whitespace();

  // Check for range: first..end
  if (peek() == '.' && peek(1) == '.') {
    advance(2);
    auto end = parse_primary();
    auto range_loc = make_loc(begin_line, begin_col, line_, col_);
    auto *range = ctx_.make_node<ast::Range>(range_loc,
                                             std::move(first),
                                             std::move(end));
    if (has_parens) {
      expect(')');
    }
    auto *block = parse_block(false);
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *f = ctx_.make_node<ast::For>(loc, var, range, block);
    return { f };
  }

  // Must be a map.
  if (has_parens) {
    expect(')');
  }
  auto *block = parse_block(false);
  auto loc = make_loc(begin_line, begin_col, line_, col_);

  auto *map_ptr = first.as<ast::Map>();
  if (!map_ptr) {
    error("expected map or range in for loop");
    auto *none = make_none();
    auto *es = ctx_.make_node<ast::ExprStatement>(none->loc,
                                                  ast::Expression(none));
    return { es };
  }
  auto *f = ctx_.make_node<ast::For>(loc, var, map_ptr, block);
  return { f };
}

void RDParser::skip_to_block_end()
{
  // Skip past a closing ')' if present, then skip the block '{...}'.
  // This is used for error recovery in for/while loops to avoid cascading
  // errors from unconsumed tokens.
  while (!at_end() && peek() != '{' && peek() != '}') {
    advance();
  }
  if (!at_end() && peek() == '{') {
    advance();
    int depth = 1;
    while (!at_end() && depth > 0) {
      if (peek() == '{') {
        depth++;
      } else if (peek() == '}') {
        depth--;
      }
      advance();
    }
  }
}

void RDParser::expect_stmt_end()
{
  skip_whitespace();
  if (peek() != '}') {
    expect(';');
  } else {
    match(';');
  }
}

// Try to match a compound assignment operator.
std::optional<ast::Operator> RDParser::try_compound_op()
{
  skip_whitespace();
  if (at_end()) {
    return std::nullopt;
  }

  char c = peek();
  char next = peek(1);

  // Three-char operators
  if (c == '<' && next == '<' && in_bounds(pos_ + 2) && at(pos_ + 2) == '=') {
    advance(3);
    return ast::Operator::LEFT;
  }
  if (c == '>' && next == '>' && in_bounds(pos_ + 2) && at(pos_ + 2) == '=') {
    advance(3);
    return ast::Operator::RIGHT;
  }

  // Two-char operators
  if (next == '=') {
    switch (c) {
      case '+':
        advance(2);
        return ast::Operator::PLUS;
      case '-':
        advance(2);
        return ast::Operator::MINUS;
      case '*':
        advance(2);
        return ast::Operator::MUL;
      case '/':
        advance(2);
        return ast::Operator::DIV;
      case '%':
        advance(2);
        return ast::Operator::MOD;
      case '&':
        advance(2);
        return ast::Operator::BAND;
      case '|':
        advance(2);
        return ast::Operator::BOR;
      case '^':
        advance(2);
        return ast::Operator::BXOR;
      default:
        break;
    }
  }

  return std::nullopt;
}

ast::Statement RDParser::make_assignment_or_expr(ast::Expression lhs,
                                                 int stmt_line,
                                                 int stmt_col)
{
  skip_whitespace();

  // Simple assignment: lhs = expr
  if (peek() == '=' && peek(1) != '=') {
    advance();
    auto rhs = parse_expression();
    auto loc = make_loc(stmt_line, stmt_col, line_, col_);
    expect_stmt_end();
    auto *map = lhs.as<ast::Map>();
    auto *map_access = lhs.as<ast::MapAccess>();
    if (map) {
      auto *assign = ctx_.make_node<ast::AssignScalarMapStatement>(
          loc, map, std::move(rhs));
      return { assign };
    }
    if (map_access) {
      auto *assign = ctx_.make_node<ast::AssignMapStatement>(loc,
                                                             map_access,
                                                             std::move(rhs));
      return { assign };
    }
    // Must be a variable.
    auto *var = lhs.as<ast::Variable>();
    auto *assign = ctx_.make_node<ast::AssignVarStatement>(loc,
                                                           var,
                                                           std::move(rhs));
    return { assign };
  }

  // Compound assignment: lhs += expr etc.
  {
    auto sp = save_point();
    auto compound = try_compound_op();
    if (compound) {
      auto rhs = parse_expression();
      auto op_loc = make_loc(sp.line, sp.col, line_, col_);
      auto *binop = ctx_.make_node<ast::Binop>(
          op_loc, lhs, *compound, std::move(rhs));
      auto loc = make_loc(stmt_line, stmt_col, line_, col_);
      expect_stmt_end();
      auto *map = lhs.as<ast::Map>();
      auto *map_access = lhs.as<ast::MapAccess>();
      if (map) {
        auto *assign = ctx_.make_node<ast::AssignScalarMapStatement>(
            loc, map, ast::Expression(binop));
        return { assign };
      }
      if (map_access) {
        auto *assign = ctx_.make_node<ast::AssignMapStatement>(
            loc, map_access, ast::Expression(binop));
        return { assign };
      }
      auto *var = lhs.as<ast::Variable>();
      auto *assign = ctx_.make_node<ast::AssignVarStatement>(
          loc, var, ast::Expression(binop));
      return { assign };
    }
    sp.restore();
  }

  // Post-increment/decrement: lhs++ or lhs--
  if (peek() == '+' && peek(1) == '+') {
    advance(2);
    auto loc = make_loc(stmt_line, stmt_col, line_, col_);
    match(';');
    auto *unop = ctx_.make_node<ast::Unop>(loc,
                                           std::move(lhs),
                                           ast::Operator::POST_INCREMENT);
    auto *es = ctx_.make_node<ast::ExprStatement>(loc, ast::Expression(unop));
    return { es };
  }
  if (peek() == '-' && peek(1) == '-') {
    advance(2);
    auto loc = make_loc(stmt_line, stmt_col, line_, col_);
    match(';');
    auto *unop = ctx_.make_node<ast::Unop>(loc,
                                           std::move(lhs),
                                           ast::Operator::POST_DECREMENT);
    auto *es = ctx_.make_node<ast::ExprStatement>(loc, ast::Expression(unop));
    return { es };
  }

  // Not an assignment, treat as expression statement.
  // First apply postfix operators (e.g. $x[0], $x.field), then continue
  // parsing any remaining binary operators (e.g. $x[0] == 102).
  auto postfix = parse_postfix(std::move(lhs));
  // Check for assignment after postfix (e.g. $x.field = expr)
  skip_whitespace();
  if (peek() == '=' && peek(1) != '=') {
    // Tuple and record fields are immutable.
    if (postfix.as<ast::TupleAccess>() || postfix.as<ast::FieldAccess>()) {
      advance();
      parse_expression();
      auto loc = make_loc(stmt_line, stmt_col, line_, col_);
      error("Tuples and records are immutable once created. "
            "Consider creating a new value and assigning it instead.",
            stmt_line,
            stmt_col,
            loc.end.line,
            loc.end.column);
      match(';');
      auto *none = make_none();
      auto *es = ctx_.make_node<ast::ExprStatement>(none->loc,
                                                    ast::Expression(none));
      return { es };
    }
    advance();
    auto rhs = parse_expression();
    auto loc = make_loc(stmt_line, stmt_col, line_, col_);
    match(';');
    auto *var = postfix.as<ast::Variable>();
    if (var) {
      auto *assign = ctx_.make_node<ast::AssignVarStatement>(loc,
                                                             var,
                                                             std::move(rhs));
      return { assign };
    }
    // Assignment to an invalid target (not a variable, map, or map access).
    error("invalid assignment target",
          stmt_line,
          stmt_col,
          loc.end.line,
          loc.end.column);
    auto *none = make_none();
    auto *es = ctx_.make_node<ast::ExprStatement>(none->loc,
                                                  ast::Expression(none));
    return { es };
  }
  // Continue parsing as a full expression (binary ops, ternary, etc.).
  auto expr = parse_binary(0, std::move(postfix));
  auto loc = make_loc(stmt_line, stmt_col, line_, col_);
  match(';');
  auto *expr_stmt = ctx_.make_node<ast::ExprStatement>(loc, std::move(expr));
  return { expr_stmt };
}

ast::Statement RDParser::parse_statement()
{
  auto [stmt_line, stmt_col] = get_current_line_col();
  skip_whitespace();

  // Let statement: let $x; let $x = expr; let $x : type = expr;
  if (match("let")) {
    skip_whitespace();
    if (peek() != '$') {
      error("expected variable after 'let'");
      auto *none = make_none();
      auto *expr_stmt = ctx_.make_node<ast::ExprStatement>(
          none->loc, ast::Expression(none));
      return { expr_stmt };
    }
    auto [var_line, var_col] = get_current_line_col();
    advance(); // consume '$'
    auto var_name = consume_identifier();
    auto var_loc = make_loc(var_line, var_col, line_, col_);
    auto *var = ctx_.make_node<ast::Variable>(var_loc, "$" + var_name);
    // The declaration location spans from 'let' through the variable name.
    auto decl_loc = make_loc(stmt_line, stmt_col, line_, col_);

    // Check for optional type annotation.
    ast::Typeof *type_annotation = nullptr;
    skip_whitespace();
    if (peek() == ':') {
      advance();
      type_annotation = parse_type_annotation();
    }

    skip_whitespace();
    if (peek() == '=') {
      // let $x = expr; or let $x : type = expr;
      advance();
      auto rhs = parse_expression();
      auto loc = make_loc(stmt_line, stmt_col, line_, col_);
      match(';');
      ast::VarDeclStatement *decl;
      if (type_annotation) {
        decl = ctx_.make_node<ast::VarDeclStatement>(decl_loc,
                                                     var,
                                                     type_annotation);
      } else {
        decl = ctx_.make_node<ast::VarDeclStatement>(decl_loc, var);
      }
      auto *assign = ctx_.make_node<ast::AssignVarStatement>(loc,
                                                             decl,
                                                             std::move(rhs));
      return { assign };
    }

    // let $x; or let $x : type;
    auto loc = make_loc(stmt_line, stmt_col, line_, col_);
    match(';');
    ast::VarDeclStatement *decl;
    if (type_annotation) {
      decl = ctx_.make_node<ast::VarDeclStatement>(decl_loc,
                                                   var,
                                                   type_annotation);
    } else {
      decl = ctx_.make_node<ast::VarDeclStatement>(decl_loc, var);
    }
    return { decl };
  }

  // Variable: $x = expr; or $x += expr; or $x++ etc.
  if (peek() == '$') {
    // Check for positional parameter ($N) or param count ($#).
    if (std::isdigit(static_cast<unsigned char>(peek(1))) || peek(1) == '#') {
      // Not a variable — fall through to expression parsing.
      auto expr = parse_expression();
      auto loc = make_loc(stmt_line, stmt_col, line_, col_);
      match(';');
      auto *expr_stmt = ctx_.make_node<ast::ExprStatement>(loc,
                                                           std::move(expr));
      return { expr_stmt };
    }
    auto [var_line, var_col] = get_current_line_col();
    advance();
    auto var_name = consume_identifier();
    auto var_loc = make_loc(var_line, var_col, line_, col_);
    auto *var = ctx_.make_node<ast::Variable>(var_loc, "$" + var_name);
    return make_assignment_or_expr(ast::Expression(var), stmt_line, stmt_col);
  }

  // Map: @x = expr; or @x[key] = expr; or @x += expr; etc.
  if (peek() == '@') {
    auto [map_line, map_col] = get_current_line_col();
    advance();
    auto map_expr = parse_map_with_optional_keys(map_line, map_col);
    return make_assignment_or_expr(std::move(map_expr), stmt_line, stmt_col);
  }

  auto expr = parse_expression();
  auto loc = make_loc(stmt_line, stmt_col, line_, col_);
  match(';');
  auto *expr_stmt = ctx_.make_node<ast::ExprStatement>(loc, std::move(expr));
  return { expr_stmt };
}

// Type parsing

SizedType RDParser::parse_sized_type()
{
  auto name = consume_identifier();

  if (name == "struct" || name == "union" || name == "enum") {
    auto type_name = consume_identifier();
    SizedType stype = ast::ident_to_sized_type(name + " " + type_name);
    skip_whitespace();
    while (peek() == '*') {
      advance();
      stype = CreatePointer(stype);
      skip_whitespace();
    }
    if (peek() == '[') {
      advance();
      auto int_str = consume_integer_str();
      auto res = util::to_uint(int_str, 0);
      expect(']');
      return CreateArray(res ? *res : 0, stype);
    }
    return stype;
  }

  if (name.empty()) {
    error("expected type name");
    return CreateNone();
  }

  // Known type name (e.g. "uint32", "string", "void")
  auto known = ident_to_type(name);
  if (known) {
    SizedType stype = *known;
    skip_whitespace();
    if (peek() == '[') {
      advance();
      skip_whitespace();
      uint64_t size = 0;
      if (peek() != ']') {
        auto int_str = consume_integer_str();
        auto res = util::to_uint(int_str, 0);
        size = res ? *res : 0;
      }
      expect(']');
      // For sized types (string, buffer, inet), [N] sets the type's
      // size parameter. For other types, [N] creates an array.
      if (stype.IsStringTy()) {
        stype = CreateString(size);
      } else if (stype.IsBufferTy()) {
        stype = CreateBuffer(size);
      } else if (stype.IsInetTy()) {
        stype = CreateInet(size);
      } else {
        stype = CreateArray(size, stype);
      }
    }
    skip_whitespace();
    while (peek() == '*') {
      advance();
      stype = CreatePointer(stype);
      skip_whitespace();
    }
    return stype;
  }

  // Treat as a struct/typedef type.
  int ptr_level = 0;
  skip_whitespace();
  while (peek() == '*') {
    advance();
    ptr_level++;
    skip_whitespace();
  }
  return ast::ident_to_c_struct(name, ptr_level);
}

// Try to parse a type name. Returns the SizedType if successful, or
// std::nullopt if the next tokens don't look like a type (position is
// restored in that case).
std::optional<SizedType> RDParser::try_parse_sized_type()
{
  if (looks_like_type()) {
    return parse_sized_type();
  }

  auto sp = save_point();
  auto name = consume_identifier();
  auto known = ident_to_type(name);
  if (known) {
    return *known;
  }

  sp.restore();
  return std::nullopt;
}

ast::Typeof *RDParser::parse_type_annotation()
{
  skip_whitespace();
  auto [begin_line, begin_col] = get_current_line_col();

  // typeof(expr_or_type)
  if (check_keyword("typeof")) {
    match("typeof");
    expect('(');
    skip_whitespace();

    auto stype = try_parse_sized_type();
    if (stype) {
      expect(')');
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      return ctx_.make_node<ast::Typeof>(loc, *stype);
    }
    auto expr = parse_expression();
    expect(')');
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    return ctx_.make_node<ast::Typeof>(loc, std::move(expr));
  }

  // Check if the next token looks like a type name. If so, parse as type.
  // Otherwise, parse as an expression (e.g. typeinfo(expr)).
  auto stype = try_parse_sized_type();
  if (stype) {
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    return ctx_.make_node<ast::Typeof>(loc, *stype);
  }

  // Not a type — parse as expression.
  auto expr = parse_expression();
  auto loc = make_loc(begin_line, begin_col, line_, col_);
  return ctx_.make_node<ast::Typeof>(loc, std::move(expr));
}

// Expression grammar

// Entry point for parsing any expression. Ternary is currently the
// lowest-precedence operator, but this wrapper keeps callers insulated
// if the grammar changes.
ast::Expression RDParser::parse_expression()
{
  return parse_ternary();
}

// Ternary: expr ? expr : expr  or  expr ? : expr
ast::Expression RDParser::parse_ternary()
{
  auto expr = parse_binary(0);
  auto sp = save_point();
  skip_whitespace();

  if (peek() == '?') {
    const auto &expr_begin = expr.loc()->current.begin;
    advance();
    skip_whitespace();

    ast::Expression then_expr;
    if (peek() == ':') {
      // Short form: expr ?: expr
      advance();
      auto else_expr = parse_ternary();
      auto loc = make_loc(expr_begin.line, expr_begin.column, line_, col_);
      auto *if_node = ctx_.make_node<ast::IfExpr>(
          loc, expr, expr, std::move(else_expr));
      return { if_node };
    }

    then_expr = parse_ternary();
    expect(':');
    auto else_expr = parse_ternary();
    auto loc = make_loc(expr_begin.line, expr_begin.column, line_, col_);
    auto *if_node = ctx_.make_node<ast::IfExpr>(
        loc, expr, std::move(then_expr), std::move(else_expr));
    return { if_node };
  }

  sp.restore();
  return expr;
}

namespace {

struct BinopInfo {
  ast::Operator op;
  int prec;
};

// Returns the operator and precedence for a binary operator token,
// or std::nullopt if the current position is not a binary operator.
std::optional<BinopInfo> get_binop(const std::string &input, size_t pos)
{
  if (pos >= input.size()) {
    return std::nullopt;
  }

  char c = input[pos];
  char next = (pos + 1 < input.size()) ? input[pos + 1] : '\0';

  // Skip compound assignments — they are not binary ops in expression context.
  if (next == '=' && (c == '+' || c == '-' || c == '*' || c == '/' ||
                      c == '%' || c == '&' || c == '|' || c == '^')) {
    return std::nullopt;
  }
  // <<= and >>=
  if ((c == '<' && next == '<') || (c == '>' && next == '>')) {
    if (pos + 2 < input.size() && input[pos + 2] == '=') {
      return std::nullopt;
    }
  }

  // Two-character operators first.
  if (c == '|' && next == '|') {
    return BinopInfo{ .op = ast::Operator::LOR, .prec = 1 };
  }
  if (c == '&' && next == '&') {
    return BinopInfo{ .op = ast::Operator::LAND, .prec = 2 };
  }
  if (c == '=' && next == '=') {
    return BinopInfo{ .op = ast::Operator::EQ, .prec = 6 };
  }
  if (c == '!' && next == '=') {
    return BinopInfo{ .op = ast::Operator::NE, .prec = 6 };
  }
  if (c == '<' && next == '=') {
    return BinopInfo{ .op = ast::Operator::LE, .prec = 7 };
  }
  if (c == '>' && next == '=') {
    return BinopInfo{ .op = ast::Operator::GE, .prec = 7 };
  }
  if (c == '<' && next == '<') {
    return BinopInfo{ .op = ast::Operator::LEFT, .prec = 8 };
  }
  if (c == '>' && next == '>') {
    return BinopInfo{ .op = ast::Operator::RIGHT, .prec = 8 };
  }

  // Single-character operators.
  if (c == '|' && next != '|') {
    return BinopInfo{ .op = ast::Operator::BOR, .prec = 3 };
  }
  if (c == '^') {
    return BinopInfo{ .op = ast::Operator::BXOR, .prec = 4 };
  }
  if (c == '&' && next != '&') {
    return BinopInfo{ .op = ast::Operator::BAND, .prec = 5 };
  }
  if (c == '<' && next != '<' && next != '=') {
    return BinopInfo{ .op = ast::Operator::LT, .prec = 7 };
  }
  if (c == '>' && next != '>' && next != '=') {
    return BinopInfo{ .op = ast::Operator::GT, .prec = 7 };
  }
  if (c == '+' && next != '+') {
    return BinopInfo{ .op = ast::Operator::PLUS, .prec = 9 };
  }
  if (c == '-' && next != '-') {
    return BinopInfo{ .op = ast::Operator::MINUS, .prec = 9 };
  }
  if (c == '*') {
    return BinopInfo{ .op = ast::Operator::MUL, .prec = 10 };
  }
  if (c == '/') {
    // If '/' is followed (after whitespace) by '{', it's the end of a
    // predicate, not a division operator
    size_t p = pos + 1;
    while (p < input.size() && std::isspace(input[p])) {
      p++;
    }
    if (p < input.size() && input[p] == '{') {
      return std::nullopt;
    }
    return BinopInfo{ .op = ast::Operator::DIV, .prec = 10 };
  }
  if (c == '%') {
    return BinopInfo{ .op = ast::Operator::MOD, .prec = 10 };
  }

  return std::nullopt;
}

int op_length(ast::Operator op)
{
  switch (op) {
    case ast::Operator::LOR:
    case ast::Operator::LAND:
    case ast::Operator::EQ:
    case ast::Operator::NE:
    case ast::Operator::LE:
    case ast::Operator::GE:
    case ast::Operator::LEFT:
    case ast::Operator::RIGHT:
      return 2;
    default:
      return 1;
  }
}

} // namespace

// Precedence-climbing binary expression parser.
ast::Expression RDParser::parse_binary(int min_prec)
{
  return parse_binary(min_prec, parse_unary());
}

ast::Expression RDParser::parse_binary(int min_prec, ast::Expression left)
{
  while (true) {
    auto sp = save_point();
    skip_whitespace();
    auto info = get_binop(*input_, pos_);
    if (!info || info->prec < min_prec) {
      sp.restore();
      break;
    }

    const auto &left_begin = left.loc()->current.begin;
    int len = op_length(info->op);
    for (int i = 0; i < len; i++) {
      advance();
    }

    auto right = parse_binary(info->prec + 1);
    auto loc = make_loc(left_begin.line, left_begin.column, line_, col_);
    auto *binop = ctx_.make_node<ast::Binop>(
        loc, std::move(left), info->op, std::move(right));
    left = ast::Expression(binop);
  }

  return left;
}

// Unary prefix expressions: *expr, -expr, !expr, ~expr, ++$var, --$var
ast::Expression RDParser::parse_unary()
{
  skip_whitespace();
  auto [begin_line, begin_col] = get_current_line_col();

  // Pre-increment: ++$var or ++@map
  if (peek() == '+' && peek(1) == '+') {
    advance(2);
    auto expr = parse_unary();
    if (!expr.as<ast::Variable>() && !expr.as<ast::Map>()) {
      error("increment/decrement requires a variable or map",
            expr.loc()->current.begin.line,
            expr.loc()->current.begin.column,
            expr.loc()->current.end.line,
            expr.loc()->current.end.column);
    }
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *unop = ctx_.make_node<ast::Unop>(loc,
                                           std::move(expr),
                                           ast::Operator::PRE_INCREMENT);
    return { unop };
  }

  // Pre-decrement: --$var or --@map
  if (peek() == '-' && peek(1) == '-') {
    advance(2);
    auto expr = parse_unary();
    if (!expr.as<ast::Variable>() && !expr.as<ast::Map>()) {
      error("increment/decrement requires a variable or map",
            expr.loc()->current.begin.line,
            expr.loc()->current.begin.column,
            expr.loc()->current.end.line,
            expr.loc()->current.end.column);
    }
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *unop = ctx_.make_node<ast::Unop>(loc,
                                           std::move(expr),
                                           ast::Operator::PRE_DECREMENT);
    return { unop };
  }

  // Address-of: &$var or &@map
  if (peek() == '&') {
    advance();
    skip_whitespace();
    if (peek() == '$') {
      auto [var_line, var_col] = get_current_line_col();
      advance();
      auto var_name = consume_identifier();
      auto var_loc = make_loc(var_line, var_col, line_, col_);
      auto *var = ctx_.make_node<ast::Variable>(var_loc, "$" + var_name);
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      auto *addr = ctx_.make_node<ast::VariableAddr>(loc, var);
      return { addr };
    }
    if (peek() == '@') {
      auto [map_line, map_col] = get_current_line_col();
      advance();
      auto map_name = consume_identifier();
      auto map_loc = make_loc(map_line, map_col, line_, col_);
      auto *map = ctx_.make_node<ast::Map>(map_loc, "@" + map_name);
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      auto *addr = ctx_.make_node<ast::MapAddr>(loc, map);
      return { addr };
    }
    // & without $ or @ — parse as BAND unary (unlikely but safe fallback)
    auto expr = parse_unary();
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *unop = ctx_.make_node<ast::Unop>(loc,
                                           std::move(expr),
                                           ast::Operator::BAND);
    return { unop };
  }

  ast::Operator op;
  if (peek() == '*') {
    op = ast::Operator::MUL;
  } else if (peek() == '!' && peek(1) != '=') {
    op = ast::Operator::LNOT;
  } else if (peek() == '~') {
    op = ast::Operator::BNOT;
  } else if (peek() == '-' && peek(1) != '-') {
    op = ast::Operator::MINUS;
  } else {
    return parse_postfix(parse_primary());
  }

  advance();
  auto expr = parse_unary();
  auto loc = make_loc(begin_line, begin_col, line_, col_);
  auto *unop = ctx_.make_node<ast::Unop>(loc, std::move(expr), op);
  return { unop };
}

// Postfix operations: .field, ->field, .N (tuple), [expr], ++, --
ast::Expression RDParser::parse_postfix(ast::Expression expr)
{
  while (true) {
    // Save position before whitespace lookahead so we don't advance
    // past the end of the expression when no postfix op is found.
    auto sp = save_point();
    skip_whitespace();
    const auto &expr_begin = expr.loc()->current.begin;

    // Field access: expr.field or tuple access: expr.N
    if (peek() == '.') {
      // Make sure it's not '..' (range operator)
      if (peek(1) == '.') {
        break;
      }
      advance();
      skip_whitespace();

      // Tuple access: expr.N
      if (std::isdigit(peek())) {
        auto int_str = consume_integer_str();
        auto res = util::to_uint(int_str, 0);
        auto loc = make_loc(expr_begin.line, expr_begin.column, line_, col_);
        auto *ta = ctx_.make_node<ast::TupleAccess>(
            loc, std::move(expr), static_cast<ssize_t>(res ? *res : 0));
        expr = ast::Expression(ta);
        continue;
      }

      // Field access: expr.field
      auto field = consume_identifier();
      if (field.empty()) {
        error("expected field name after '.'");
        break;
      }
      auto loc = make_loc(expr_begin.line, expr_begin.column, line_, col_);
      auto *fa = ctx_.make_node<ast::FieldAccess>(loc,
                                                  std::move(expr),
                                                  std::move(field));
      expr = ast::Expression(fa);
      continue;
    }

    // Arrow access: expr->field
    if (peek() == '-' && peek(1) == '>') {
      advance(2);
      auto field = consume_identifier();
      if (field.empty()) {
        error("expected field name after '->'");
        break;
      }
      auto loc = make_loc(expr_begin.line, expr_begin.column, line_, col_);
      auto *fa = ctx_.make_node<ast::FieldAccess>(loc,
                                                  std::move(expr),
                                                  std::move(field));
      expr = ast::Expression(fa);
      continue;
    }

    // Array access: expr[index]
    if (peek() == '[') {
      advance();
      auto index = parse_expression();
      expect(']');
      auto loc = make_loc(expr_begin.line, expr_begin.column, line_, col_);
      auto *aa = ctx_.make_node<ast::ArrayAccess>(loc,
                                                  std::move(expr),
                                                  std::move(index));
      expr = ast::Expression(aa);
      continue;
    }

    // Post-increment: expr++
    if (peek() == '+' && peek(1) == '+') {
      if (!expr.as<ast::Variable>() && !expr.as<ast::Map>()) {
        auto [op_line, op_col] = get_current_line_col();
        advance(2);
        error("increment/decrement requires a variable or map",
              op_line,
              op_col,
              line_,
              col_);
        break;
      }
      advance(2);
      auto loc = make_loc(expr_begin.line, expr_begin.column, line_, col_);
      auto *unop = ctx_.make_node<ast::Unop>(loc,
                                             std::move(expr),
                                             ast::Operator::POST_INCREMENT);
      expr = ast::Expression(unop);
      continue;
    }

    // Post-decrement: expr--
    if (peek() == '-' && peek(1) == '-') {
      if (!expr.as<ast::Variable>() && !expr.as<ast::Map>()) {
        auto [op_line, op_col] = get_current_line_col();
        advance(2);
        error("increment/decrement requires a variable or map",
              op_line,
              op_col,
              line_,
              col_);
        break;
      }
      advance(2);
      auto loc = make_loc(expr_begin.line, expr_begin.column, line_, col_);
      auto *unop = ctx_.make_node<ast::Unop>(loc,
                                             std::move(expr),
                                             ast::Operator::POST_DECREMENT);
      expr = ast::Expression(unop);
      continue;
    }

    // No postfix op found
    sp.restore();
    break;
  }

  return expr;
}

// Primary expressions: atoms, calls, parenthesized/tuple/record exprs,
// if-expressions, sizeof, offsetof, typeinfo, comptime.
ast::Expression RDParser::parse_primary()
{
  skip_whitespace();
  auto [begin_line, begin_col] = get_current_line_col();

  // Parenthesized expression, cast, tuple, or record.
  if (peek() == '(') {
    return parse_paren_expr();
  }

  // If expression: if cond { expr } else { expr }
  if (match("if")) {
    auto cond = parse_unary();
    auto *then_block = parse_block();
    skip_whitespace();
    ast::Expression else_expr;
    if (match("else")) {
      skip_whitespace();
      if (peek() == '{') {
        auto *else_block = parse_block();
        else_expr = ast::Expression(else_block);
      } else if (check_keyword("if")) {
        // else if ...
        else_expr = parse_primary();
      } else {
        auto *else_block = parse_block();
        else_expr = ast::Expression(else_block);
      }
    } else {
      auto *none = make_none();
      else_expr = ast::Expression(none);
    }
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *if_node = ctx_.make_node<ast::IfExpr>(
        loc, std::move(cond), then_block, std::move(else_expr));
    return { if_node };
  }

  // sizeof(type_or_expr)
  if (match("sizeof")) {
    expect('(');
    skip_whitespace();

    auto stype = try_parse_sized_type();
    if (stype) {
      expect(')');
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      auto *s = ctx_.make_node<ast::Sizeof>(loc, *stype);
      return { s };
    }
    auto expr = parse_expression();
    expect(')');
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *s = ctx_.make_node<ast::Sizeof>(loc, std::move(expr));
    return { s };
  }

  // offsetof(type, field.field...)
  if (match("offsetof")) {
    expect('(');
    skip_whitespace();

    // Try type first (struct Name)
    auto sp = save_point();
    auto ident = consume_identifier();
    bool is_struct_type = (ident == "struct" || ident == "union" ||
                           ident == "enum");
    sp.restore();

    if (is_struct_type) {
      auto stype = parse_sized_type();
      expect(',');
      auto fields = parse_field_list();
      expect(')');
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      auto *o = ctx_.make_node<ast::Offsetof>(loc, stype, std::move(fields));
      return { o };
    }
    // Expression form: offsetof(expr, field)
    auto expr = parse_expression();
    expect(',');
    auto fields = parse_field_list();
    expect(')');
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *o = ctx_.make_node<ast::Offsetof>(loc,
                                            std::move(expr),
                                            std::move(fields));
    return { o };
  }

  // typeinfo(type_or_expr)
  if (match("typeinfo")) {
    expect('(');
    auto *typeof_node = parse_type_annotation();
    expect(')');
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *ti = ctx_.make_node<ast::Typeinfo>(loc, typeof_node);
    return { ti };
  }

  // comptime expr
  if (match("comptime")) {
    auto expr = parse_unary();
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *ct = ctx_.make_node<ast::Comptime>(loc, std::move(expr));
    return { ct };
  }

  // Block expression: { stmts; expr }
  if (peek() == '{') {
    auto *block = parse_block();
    if (block) {
      return { block };
    }
    auto *none = make_none();
    return { none };
  }

  // Try to read an identifier - could be a function call, builtin, or keyword.
  auto name = consume_identifier();
  if (!name.empty()) {
    auto name_loc = make_loc(begin_line, begin_col, line_, col_);

    // Boolean literals.
    if (name == "true" || name == "false") {
      auto *boolean = ctx_.make_node<ast::Boolean>(name_loc, name == "true");
      return { boolean };
    }

    skip_whitespace();
    if (peek() == '(') {
      return parse_call_expression(name, name_loc);
    }
    if (is_builtin(name)) {
      auto *builtin = ctx_.make_node<ast::Builtin>(name_loc, std::move(name));
      return { builtin };
    }
    // Just an identifier.
    auto *ident = ctx_.make_node<ast::Identifier>(name_loc, std::move(name));
    return { ident };
  }

  // Try a map (@name or @name[key]).
  if (peek() == '@') {
    advance();
    return parse_map_with_optional_keys(begin_line, begin_col);
  }

  // Try a variable ($name), positional parameter ($N), or param count ($#).
  if (peek() == '$') {
    advance();

    if (peek() == '#') {
      advance();
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      auto *ppc = ctx_.make_node<ast::PositionalParameterCount>(loc);
      return { ppc };
    }

    if (std::isdigit(peek())) {
      std::string digits;
      while (!at_end() && std::isdigit(peek())) {
        digits += peek();
        advance();
      }
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      try {
        long n = std::stol(digits);
        if (n < 1) {
          error("param $" + digits + " is out of integer range [1, " +
                    std::to_string(std::numeric_limits<long>::max()) + "]",
                begin_line,
                begin_col,
                line_,
                col_);
        }
        auto *pp = ctx_.make_node<ast::PositionalParameter>(loc, n);
        return { pp };
      } catch (...) {
        error("param $" + digits + " is out of integer range [1, " +
                  std::to_string(std::numeric_limits<long>::max()) + "]",
              begin_line,
              begin_col,
              line_,
              col_);
        auto *pp = ctx_.make_node<ast::PositionalParameter>(loc, 0);
        return { pp };
      }
    }

    auto var_name = consume_identifier();
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *var = ctx_.make_node<ast::Variable>(loc, "$" + var_name);
    return { var };
  }

  // Try an integer literal.
  if (std::isdigit(peek())) {
    auto int_str = consume_integer_str();
    auto res = util::to_uint(int_str, 0);
    if (!res) {
      std::stringstream ss;
      ss << res.takeError();
      error(ss.str(), begin_line, begin_col, line_, col_);
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      auto *integer = ctx_.make_node<ast::Integer>(loc, 0);
      return { integer };
    }
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *integer = ctx_.make_node<ast::Integer>(loc, *res, std::move(int_str));
    return { integer };
  }

  // Try a string literal.
  if (peek() == '"') {
    auto str = consume_string();
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *string_node = ctx_.make_node<ast::String>(loc, std::move(str));
    return { string_node };
  }

  error("expected expression");
  auto *none = make_none();
  return { none };
}

// Parse parenthesized expressions, casts, tuples, and records.
ast::Expression RDParser::parse_paren_expr()
{
  auto [begin_line, begin_col] = get_current_line_col();

  advance(); // consume '('
  skip_whitespace();

  // Empty tuple: ()
  if (peek() == ')') {
    advance();
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *tuple = ctx_.make_node<ast::Tuple>(loc, ast::ExpressionList{});
    return { tuple };
  }

  if (auto record = try_parse_record(begin_line, begin_col)) {
    return std::move(*record);
  }

  if (auto cast = try_parse_cast_expr(begin_line, begin_col)) {
    return std::move(*cast);
  }

  return parse_tuple_or_grouping_expr(begin_line, begin_col);
}

std::optional<ast::Expression> RDParser::try_parse_record(int begin_line,
                                                          int begin_col)
{
  // (ident=expr, ident_b=expr)
  size_t p = skip_whitespace(pos_);
  if (!in_bounds(p) ||
      (!std::isalpha(static_cast<unsigned char>(at(p))) && at(p) != '_')) {
    return std::nullopt;
  }

  size_t id_start = p;
  p = scan_identifier_end(p);
  size_t id_end = p;
  p = skip_whitespace(p);
  if (!in_bounds(p) || at(p) != '=' || (in_bounds(p + 1) && at(p + 1) == '=')) {
    return std::nullopt;
  }

  if (is_builtin(view(id_start, id_end))) {
    return std::nullopt;
  }

  ast::NamedArgumentList named_args;
  std::set<std::string> seen_names;
  bool record_error = false;
  while (true) {
    skip_whitespace();
    auto [arg_line, arg_col] = get_current_line_col();
    auto arg_name = consume_identifier();
    if (arg_name.empty()) {
      error("expected identifier");
      record_error = true;
      break;
    }
    expect('=');
    auto arg_expr = parse_expression();
    auto arg_loc = make_loc(arg_line, arg_col, line_, col_);
    if (seen_names.contains(arg_name)) {
      error("Named argument list already contains name: " + arg_name,
            arg_line,
            arg_col,
            line_,
            col_);
    } else {
      seen_names.insert(arg_name);
    }
    named_args.push_back(ctx_.make_node<ast::NamedArgument>(
        arg_loc, std::move(arg_name), std::move(arg_expr)));
    if (!match(',')) {
      break;
    }
  }

  if (record_error) {
    // Skip to closing ')' to avoid cascading errors.
    int depth = 1;
    while (!at_end() && depth > 0) {
      if (peek() == '(') {
        depth++;
      } else if (peek() == ')') {
        depth--;
      }
      if (depth > 0) {
        advance();
      }
    }
  }

  expect(')');
  auto loc = make_loc(begin_line, begin_col, line_, col_);
  auto *record = ctx_.make_node<ast::Record>(loc, std::move(named_args));
  return ast::Expression(record);
}

std::optional<ast::Expression> RDParser::try_parse_cast_expr(int begin_line,
                                                             int begin_col)
{
  auto sp = save_point();

  bool looks_like_cast = false;
  size_t p = skip_whitespace(pos_);
  if (in_bounds(p) &&
      (std::isalpha(static_cast<unsigned char>(at(p))) || at(p) == '_')) {
    size_t ident_start = p;
    p = scan_identifier_end(p);

    auto ident = view(ident_start, p);
    p = skip_whitespace(p);

    if (ident == "typeof") {
      if (in_bounds(p) && at(p) == '(') {
        int depth = 1;
        p++;
        while (in_bounds(p) && depth > 0) {
          if (at(p) == '(') {
            depth++;
          } else if (at(p) == ')') {
            depth--;
          }
          p++;
        }
        p = skip_whitespace(p);
        while (in_bounds(p) && at(p) == '*') {
          p++;
          p = skip_whitespace(p);
        }
        looks_like_cast = in_bounds(p) && at(p) == ')';
      }
    } else {
      if (ident == "struct" || ident == "union" || ident == "enum") {
        p = scan_identifier_end(p);
        p = skip_whitespace(p);
      }

      if (in_bounds(p) && at(p) == '[') {
        p++;
        while (in_bounds(p) && at(p) != ']') {
          p++;
        }
        if (in_bounds(p)) {
          p++;
        }
        p = skip_whitespace(p);
      }

      if (in_bounds(p) && at(p) == '*') {
        while (in_bounds(p) && at(p) == '*') {
          p++;
          p = skip_whitespace(p);
        }
        looks_like_cast = in_bounds(p) && at(p) == ')';
      } else if (in_bounds(p) && at(p) == ')') {
        looks_like_cast = !is_builtin(ident);
      }
    }
  }

  if (!looks_like_cast) {
    sp.restore();
    return std::nullopt;
  }

  auto *typeof_node = parse_type_annotation();
  if (!expect(')') || !can_start_expression()) {
    sp.restore();
    return std::nullopt;
  }

  auto loc = make_loc(begin_line, begin_col, line_, col_);
  auto cast_target = parse_unary();
  auto *cast = ctx_.make_node<ast::Cast>(loc,
                                         typeof_node,
                                         std::move(cast_target));
  return ast::Expression(cast);
}

ast::Expression RDParser::parse_tuple_or_grouping_expr(int begin_line,
                                                       int begin_col)
{
  auto first = parse_expression();
  skip_whitespace();

  // Check for tuple: (expr, ...) or (expr,)
  if (peek() == ',') {
    advance();
    skip_whitespace();

    ast::ExpressionList elems;
    elems.push_back(std::move(first));

    // (expr,) — single-element tuple with trailing comma
    if (peek() == ')') {
      advance();
      auto loc = make_loc(begin_line, begin_col, line_, col_);
      auto *tuple = ctx_.make_node<ast::Tuple>(loc, std::move(elems));
      return { tuple };
    }

    // Multi-element tuple
    elems.push_back(parse_expression());
    while (match(',')) {
      skip_whitespace();
      if (peek() == ')') {
        break; // trailing comma
      }
      elems.push_back(parse_expression());
    }
    expect(')');
    auto loc = make_loc(begin_line, begin_col, line_, col_);
    auto *tuple = ctx_.make_node<ast::Tuple>(loc, std::move(elems));
    return { tuple };
  }

  // Simple parenthesized expression.
  expect(')');
  return first;
}

ast::Expression RDParser::parse_call_expression(
    const std::string &name,
    const ast::SourceLocation &start_loc)
{
  expect('(');

  ast::ExpressionList args;
  skip_whitespace();
  if (peek() != ')') {
    args.push_back(parse_expression());
    while (match(',')) {
      args.push_back(parse_expression());
    }
  }

  expect(')');

  auto loc = make_loc(
      start_loc.begin.line, start_loc.begin.column, line_, col_);
  auto *call = ctx_.make_node<ast::Call>(loc,
                                         std::string(name),
                                         std::move(args));
  return { call };
}

// Expression helpers

ast::Expression RDParser::parse_map_with_optional_keys(int begin_line,
                                                       int begin_col)
{
  auto map_name = consume_identifier(); // may be empty for anonymous map
  auto map_loc = make_loc(begin_line, begin_col, line_, col_);
  auto *map = ctx_.make_node<ast::Map>(map_loc, "@" + map_name);
  skip_whitespace();
  if (peek() != '[') {
    return { map };
  }

  advance();
  ast::ExpressionList keys;
  keys.push_back(parse_expression());
  while (match(',')) {
    keys.push_back(parse_expression());
  }
  expect(']');
  auto access_loc = make_loc(begin_line, begin_col, line_, col_);
  ast::Expression key_expr;
  if (keys.size() > 1) {
    auto *tuple = ctx_.make_node<ast::Tuple>(access_loc, std::move(keys));
    key_expr = ast::Expression(tuple);
  } else {
    key_expr = std::move(keys.back());
  }
  auto *map_access = ctx_.make_node<ast::MapAccess>(access_loc,
                                                    map,
                                                    std::move(key_expr));
  return { map_access };
}

std::vector<std::string> RDParser::parse_field_list()
{
  std::vector<std::string> fields;
  fields.push_back(consume_identifier());
  while (true) {
    skip_whitespace();
    if (match('.')) {
      fields.push_back(consume_identifier());
    } else {
      break;
    }
  }
  return fields;
}

// Lexer helpers

void RDParser::advance(int n)
{
  for (int i = 0; i < n && !at_end(); i++) {
    if (at(pos_) == '\n') {
      line_++;
      col_ = 1;
    } else {
      col_++;
    }
    pos_++;
  }
}

char RDParser::peek(size_t offset) const
{
  if (!in_bounds(pos_ + offset)) {
    return '\0';
  }
  return at(pos_ + offset);
}

bool RDParser::at_end() const
{
  return !in_bounds(pos_);
}

void RDParser::skip_whitespace()
{
  auto previous_non_hspace = [this]() -> char {
    size_t p = pos_;
    while (p > 0) {
      p--;
      char c = at(p);
      if (c != ' ' && c != '\t' && c != '\r') {
        return c;
      }
    }
    return '\0';
  };

  auto consume_line_comment = [this]() {
    advance(2);
    if (!at_end() && peek() == ' ') {
      advance();
    }

    int begin_line = line_;
    int begin_col = col_;
    while (!at_end() && peek() != '\n') {
      advance();
    }

    ctx_.add_comment(make_loc(begin_line, begin_col, line_, col_));
  };

  auto consume_block_comment = [this]() {
    advance(2);
    if (!at_end() && peek() == ' ') {
      advance();
    }

    while (!at_end()) {
      int begin_line = line_;
      int begin_col = col_;
      while (!at_end() && peek() != '\n' && (peek() != '*' || peek(1) != '/')) {
        advance();
      }

      if (line_ != begin_line || col_ != begin_col) {
        ctx_.add_comment(make_loc(begin_line, begin_col, line_, col_));
      }

      if (!at_end() && peek() == '*' && peek(1) == '/') {
        advance(2);
        break;
      }

      if (at_end()) {
        break;
      }

      advance();

      while (!at_end() && (peek() == ' ' || peek() == '\t' || peek() == '\r')) {
        advance();
      }

      if (peek() == '*' && peek(1) == '/') {
        continue;
      }

      bool stripped_stars = false;
      while (!at_end() && peek() == '*') {
        stripped_stars = true;
        advance();
      }
      if (stripped_stars && !at_end() && peek() == ' ') {
        advance();
      }

      if (peek() == '\n' || (peek() == '*' && peek(1) == '/')) {
        ctx_.add_comment(make_loc(line_, col_, line_, col_));
      }
    }
  };

  bool just_consumed_comment = false;
  while (!at_end()) {
    if (peek() == ' ' || peek() == '\t' || peek() == '\r') {
      advance();
    } else if (peek() == '\n') {
      int begin_line = line_;
      int begin_col = col_;
      bool suppress_vspace = just_consumed_comment;
      if (!suppress_vspace) {
        char prev = previous_non_hspace();
        suppress_vspace = prev == ';' || prev == '{' || prev == '}';
      }

      advance();
      if (!suppress_vspace) {
        ctx_.add_vspace(make_loc(begin_line, begin_col, line_, col_), 1);
      }
      just_consumed_comment = false;
    } else if (peek() == '/' && peek(1) != '\0') {
      if (peek(1) == '/') {
        consume_line_comment();
        just_consumed_comment = true;
      } else if (peek(1) == '*') {
        consume_block_comment();
        just_consumed_comment = true;
      } else {
        break;
      }
    } else {
      break;
    }
  }
}

size_t RDParser::skip_whitespace(size_t pos) const
{
  while (in_bounds(pos)) {
    if (std::isspace(static_cast<unsigned char>(at(pos)))) {
      pos++;
    } else if (at(pos) == '/' && in_bounds(pos + 1)) {
      if (at(pos + 1) == '/') {
        while (in_bounds(pos) && at(pos) != '\n') {
          pos++;
        }
      } else if (at(pos + 1) == '*') {
        pos += 2;
        while (in_bounds(pos)) {
          if (at(pos) == '*' && in_bounds(pos + 1) && at(pos + 1) == '/') {
            pos += 2;
            break;
          }
          pos++;
        }
      } else {
        break;
      }
    } else {
      break;
    }
  }
  return pos;
}

size_t RDParser::scan_identifier_end(size_t pos) const
{
  while (in_bounds(pos) && (std::isalnum(static_cast<unsigned char>(at(pos))) ||
                            at(pos) == '_')) {
    pos++;
  }
  return pos;
}

std::string_view RDParser::view(size_t start, size_t end) const
{
  return std::string_view(*input_).substr(start, end - start);
}

bool RDParser::match(char c)
{
  skip_whitespace();
  if (peek() == c) {
    advance();
    return true;
  }
  return false;
}

bool RDParser::match(const std::string &s)
{
  skip_whitespace();
  if (!in_bounds(pos_ + s.size() - 1)) {
    return false;
  }
  for (size_t i = 0; i < s.size(); i++) {
    if (at(pos_ + i) != s[i]) {
      return false;
    }
  }
  // Make sure the keyword isn't a prefix of a longer identifier.
  if (in_bounds(pos_ + s.size()) &&
      (std::isalnum(at(pos_ + s.size())) || at(pos_ + s.size()) == '_')) {
    return false;
  }
  for (size_t i = 0; i < s.size(); i++) {
    advance();
  }
  return true;
}

bool RDParser::check_keyword(const std::string &s) const
{
  size_t p = skip_whitespace(pos_);
  if (!in_bounds(p + s.size() - 1)) {
    return false;
  }
  for (size_t i = 0; i < s.size(); i++) {
    if (at(p + i) != s[i]) {
      return false;
    }
  }
  // Ensure it's not a prefix of a longer identifier.
  return !in_bounds(p + s.size()) ||
         (!std::isalnum(at(p + s.size())) && at(p + s.size()) != '_');
}

bool RDParser::expect(char c)
{
  if (!match(c)) {
    error(std::string("expected '") + c + "'");
    return false;
  }
  return true;
}

std::string RDParser::consume_identifier()
{
  skip_whitespace();
  if (!std::isalpha(static_cast<unsigned char>(peek())) && peek() != '_') {
    return "";
  }
  size_t start = pos_;
  size_t end = scan_identifier_end(pos_);
  pos_ = end;
  col_ += static_cast<int>(end - start);
  return std::string(view(start, end));
}

std::string RDParser::consume_string()
{
  // Opening quote already confirmed by caller, consume it.
  advance();
  std::string result;
  while (!at_end() && peek() != '"') {
    if (peek() == '\n') {
      error("unterminated string");
      return result;
    }
    if (peek() == '\\') {
      int esc_line = line_;
      int esc_col = col_;
      advance();
      if (at_end()) {
        error("unterminated string");
        return result;
      }
      switch (peek()) {
        case 'n':
          result += '\n';
          break;
        case 't':
          result += '\t';
          break;
        case 'r':
          result += '\r';
          break;
        case '"':
          result += '"';
          break;
        case '\\':
          result += '\\';
          break;
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7': {
          // Octal escape: up to 3 octal digits.
          std::string oct;
          oct += peek();
          advance();
          for (int i = 0; i < 2 && !at_end() && peek() >= '0' && peek() <= '7';
               i++) {
            oct += peek();
            advance();
          }
          long value = std::strtol(oct.c_str(), nullptr, 8);
          if (value > UCHAR_MAX) {
            error("octal escape sequence out of range '\\" + oct + "'",
                  esc_line,
                  esc_col,
                  line_,
                  col_);
          }
          result += static_cast<char>(value);
          continue; // Already advanced past octal digits.
        }
        case 'x':
        case 'X': {
          advance();
          std::string hex;
          for (int i = 0; i < 2 && !at_end() && std::isxdigit(peek()); i++) {
            hex += peek();
            advance();
          }
          if (hex.empty()) {
            error("invalid hex escape sequence");
          } else {
            result += static_cast<char>(std::strtol(hex.c_str(), nullptr, 16));
          }
          continue; // Already advanced past hex digits.
        }
        default:
          error(std::string("invalid escape character '\\") + peek() + "'");
          break;
      }
    } else {
      result += peek();
    }
    advance();
  }
  if (!at_end()) {
    advance(); // Closing quote.
  }
  return result;
}

// Consume an integer literal as a raw string. Handles decimal, hex (0x...),
// exponent notation (NeM), underscore separators, and optional suffixes.
std::string RDParser::consume_integer_str()
{
  skip_whitespace();
  std::string result;

  // Hex prefix
  if (peek() == '0' && (peek(1) == 'x' || peek(1) == 'X')) {
    result += peek();
    advance();
    result += peek();
    advance();
    while (!at_end() && (std::isxdigit(peek()) || peek() == '_')) {
      result += peek();
      advance();
    }
    if (!result.empty() && result.back() == '_') {
      error("trailing underscore in integer literal",
            line_,
            col_ - 1,
            line_,
            col_);
    }
    return result;
  }

  // Decimal digits with possible underscores
  while (!at_end() && (std::isdigit(peek()) || peek() == '_')) {
    result += peek();
    advance();
  }

  if (!result.empty() && result.back() == '_') {
    error(
        "trailing underscore in integer literal", line_, col_ - 1, line_, col_);
  }

  // Exponent notation: e.g. 1e6
  if (!at_end() && (peek() == 'e' || peek() == 'E')) {
    result += peek();
    advance();
    while (!at_end() && (std::isdigit(peek()) || peek() == '_')) {
      result += peek();
      advance();
    }
    if (!result.empty() && result.back() == '_') {
      error("trailing underscore in integer literal",
            line_,
            col_ - 1,
            line_,
            col_);
    }
  }

  // Optional suffix (u, l, ll, ul, ull, ns, us, ms, s, m, h, d)
  if (!at_end()) {
    // Check for time/size suffixes: ns, us, ms
    if ((peek() == 'n' || peek() == 'u' || peek() == 'm') && peek(1) == 's') {
      result += peek();
      advance();
      result += peek();
      advance();
    } else if (peek() == 's' || peek() == 'm' || peek() == 'h' ||
               peek() == 'd') {
      result += peek();
      advance();
    } else if (peek() == 'u' || peek() == 'U') {
      result += peek();
      advance();
      // Possible 'l' or 'll' after 'u'
      if (!at_end() && (peek() == 'l' || peek() == 'L')) {
        result += peek();
        advance();
        if (!at_end() && (peek() == 'l' || peek() == 'L')) {
          result += peek();
          advance();
        }
      }
    } else if (peek() == 'l' || peek() == 'L') {
      result += peek();
      advance();
      if (!at_end() && (peek() == 'l' || peek() == 'L')) {
        result += peek();
        advance();
      }
    }
  }

  // If alphanumeric characters still follow, the suffix is invalid.
  // Consume them to avoid cascading errors.
  if (!at_end() && (std::isalpha(peek()) || peek() == '_')) {
    auto [err_line, err_col] = get_current_line_col();
    std::string bad;
    while (!at_end() && (std::isalnum(peek()) || peek() == '_')) {
      bad += peek();
      advance();
    }
    error(
        "invalid integer suffix '" + bad + "'", err_line, err_col, line_, col_);
  }

  return result;
}

// Error reporting

void RDParser::error(const std::string &msg)
{
  auto sp = save_point();
  skip_whitespace();
  auto [begin_line, begin_col] = get_current_line_col();

  // Scan past the current token to find its end.
  if (!at_end()) {
    char c = peek();
    if (std::isalpha(c) || c == '_') {
      while (!at_end() && (std::isalnum(peek()) || peek() == '_')) {
        advance();
      }
    } else if (std::isdigit(c)) {
      while (!at_end() && (std::isalnum(peek()) || peek() == '.')) {
        advance();
      }
    } else if (c == '@' || c == '$') {
      advance();
      while (!at_end() && (std::isalnum(peek()) || peek() == '_')) {
        advance();
      }
    } else {
      advance();
    }
  }

  auto [end_line, end_col] = get_current_line_col();
  sp.restore();

  error(msg, begin_line, begin_col, end_line, end_col);
}

void RDParser::error(const std::string &msg,
                     int begin_line,
                     int begin_col,
                     int end_line,
                     int end_col)
{
  auto loc = make_loc(begin_line, begin_col, end_line, end_col);
  ast::SourceLocation valid(ctx_.source());
  valid.begin = loc.begin;
  valid.end = loc.end;
  ctx_.state_->diagnostics_->addError(
      std::make_shared<ast::LocationChain>(std::move(valid)))
      << msg;
}

// Source location tracking

ast::SourceLocation RDParser::make_loc(int begin_line,
                                       int begin_col,
                                       int end_line,
                                       int end_col) const
{
  ast::SourceLocation loc(ctx_.source());
  loc.begin.line = begin_line;
  loc.begin.column = begin_col;
  loc.end.line = end_line;
  loc.end.column = end_col;
  return loc;
}

ast::None *RDParser::make_none()
{
  return ctx_.make_node<ast::None>(make_loc(line_, col_, line_, col_));
}

RDParser::LineCol RDParser::get_current_line_col()
{
  return { .line = line_, .col = col_ };
}

// Lookahead helpers

bool RDParser::is_builtin(std::string_view name)
{
  static const std::unordered_set<std::string_view> builtins = {
    "args",
    "ctx",
    "kstack",
    "nsecs",
    "pid",
    "tid",
    "ustack",
    "__builtin_cgroup",
    "__builtin_comm",
    "__builtin_cpid",
    "__builtin_cpu",
    "__builtin_curtask",
    "__builtin_elapsed",
    "__builtin_func",
    "__builtin_gid",
    "__builtin_jiffies",
    "__builtin_ncpus",
    "__builtin_probe",
    "__builtin_rand",
    "__builtin_retval",
    "__builtin_uid",
    "__builtin_usermode",
    "__builtin_username",
  };
  if (builtins.contains(name)) {
    return true;
  }

  // Handle parameterized builtins: arg0-arg9+, sarg0-sarg9
  if (name.size() >= 4 && name.starts_with("arg") &&
      std::all_of(name.begin() + 3, name.end(), [](char c) {
        return std::isdigit(static_cast<unsigned char>(c));
      })) {
    return true;
  }
  if (name.size() >= 5 && name.starts_with("sarg") &&
      std::all_of(name.begin() + 4, name.end(), [](char c) {
        return std::isdigit(static_cast<unsigned char>(c));
      })) {
    return true;
  }

  return false;
}

bool RDParser::can_start_expression() const
{
  return can_start_expression(pos_);
}

bool RDParser::can_start_expression(size_t pos) const
{
  size_t p = skip_whitespace(pos);
  if (!in_bounds(p)) {
    return false;
  }

  char c = at(p);
  return std::isdigit(static_cast<unsigned char>(c)) || c == '$' || c == '@' ||
         c == '"' || c == '(' || c == '-' || c == '!' || c == '~' || c == '*' ||
         c == '&' || std::isalpha(static_cast<unsigned char>(c)) || c == '_';
}

bool RDParser::looks_like_type() const
{
  size_t save = skip_whitespace(pos_);
  // Read identifier (must start with alpha or underscore).
  size_t id_start = save;
  if (!in_bounds(save) ||
      (!std::isalpha(static_cast<unsigned char>(at(save))) &&
       at(save) != '_')) {
    return false;
  }
  save = scan_identifier_end(save);
  auto ident = view(id_start, save);
  if (ident == "struct" || ident == "union" || ident == "enum") {
    return true;
  }
  // Builtins are values, not types — don't treat them as types even if
  // followed by '*' or '['.
  if (is_builtin(ident)) {
    return false;
  }
  // Check for ident followed by '*' (pointer type). Bare identifiers
  // followed by ')' are parsed as expressions and resolved to types by
  // later passes.
  save = skip_whitespace(save);
  if (in_bounds(save) && at(save) == '*') {
    return true;
  }
  // Only treat ident followed by '[' as a type if it's a known type name
  // (e.g. "int32[4]", "string[64]"). Unknown identifiers followed by '['
  // are array access expressions (e.g. "exp[0]").
  if (in_bounds(save) && at(save) == '[') {
    return ident_to_type(std::string(ident)).has_value();
  }
  return false;
}

bool RDParser::looks_like_c_definition() const
{
  size_t p = skip_whitespace(pos_);
  // Skip keyword (struct/union/enum).
  p = scan_identifier_end(p);
  p = skip_whitespace(p);
  // Skip optional name.
  if (in_bounds(p) &&
      (std::isalpha(static_cast<unsigned char>(at(p))) || at(p) == '_')) {
    p = scan_identifier_end(p);
    p = skip_whitespace(p);
  }
  return in_bounds(p) && at(p) == '{';
}

} // namespace bpftrace
