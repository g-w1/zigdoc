// STOLEN FROM ZLS:

const std = @import("std");
const ast = std.zig.ast;
const mem = std.mem;

/// Gets a declaration's doc comments, caller must free memory when a value is returned
/// Like:
///```zig
///var comments = getFunctionDocComments(allocator, tree, func);
///defer if (comments) |comments_pointer| allocator.free(comments_pointer);
///```
pub fn getDocComments(
    allocator: *std.mem.Allocator,
    tree: ast.Tree,
    node: ast.Node.Index,
) !?[]const u8 {
    if (getDocCommentTokenIndex(tree, node)) |doc_comment_index| {
        return try collectDocComments(allocator, tree, doc_comment_index);
    }
    return null;
}

pub fn collectDocComments(
    allocator: *std.mem.Allocator,
    tree: ast.Tree,
    doc_comments: ast.TokenIndex,
) ![]const u8 {
    var lines = std.ArrayList([]const u8).init(allocator);
    defer lines.deinit();

    const token_tags = tree.tokens.items(.tag);

    var curr_line_tok = doc_comments;
    while (true) : (curr_line_tok += 1) {
        switch (token_tags[curr_line_tok]) {
            .doc_comment, .container_doc_comment => {
                try lines.append(std.mem.trim(u8, tree.tokenSlice(curr_line_tok)[3..], &std.ascii.spaces));
            },
            else => break,
        }
    }

    return std.mem.join(allocator, "\n", lines.items);
}

pub fn getDocCommentTokenIndex(tree: ast.Tree, node: ast.Node.Index) ?ast.TokenIndex {
    const tags = tree.nodes.items(.tag);
    const tokens = tree.tokens.items(.tag);
    const current = tree.nodes.items(.main_token)[node];

    var idx = current;
    if (idx == 0) return null;
    switch (tags[node]) {
        .fn_proto,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_proto_multi,
        .fn_decl,
        => {
            idx -= 1;
            if (tokens[idx] == .keyword_extern and idx > 0)
                idx -= 1;
            if (tokens[idx] == .keyword_pub and idx > 0)
                idx -= 1;
        },
        .local_var_decl,
        .global_var_decl,
        .aligned_var_decl,
        .simple_var_decl,
        => {
            idx -= 1;
            if (tokens[idx] == .keyword_pub and idx > 0)
                idx -= 1;
        },
        else => idx -= 1,
    }

    // Find first doc comment token
    if (tokens[idx] == .doc_comment or tokens[idx] == .container_doc_comment) {
        while (idx > 0 and
            (tokens[idx] == .doc_comment or tokens[idx] == .container_doc_comment))
        {
            idx -= 1;
        }
        return idx + @boolToInt(tokens[idx] != .doc_comment and tokens[idx] != .container_doc_comment);
    }

    return null;
}

/// Gets a function signature (keywords, name, return value)
pub fn getFunctionSignature(tree: ast.Tree, func: ast.full.FnProto) []const u8 {
    const start = if (func.extern_export_inline_token) |ex| tokenLocation(tree, ex) else tokenLocation(tree, func.ast.fn_token);
    // return type can be 0 when user wrote incorrect fn signature
    // to ensure we don't break, just end the signature at end of fn token
    if (func.ast.return_type == 0) return tree.source[start.start..start.end];
    const end = tokenLocation(tree, lastToken(tree, func.ast.return_type)).end;
    return tree.source[start.start..end];
}

pub fn tokenLocation(tree: ast.Tree, token_index: ast.TokenIndex) Loc {
    const start = tree.tokens.items(.start)[token_index];
    const tag = tree.tokens.items(.tag)[token_index];

    // For some tokens, re-tokenization is needed to find the end.
    var tokenizer: std.zig.Tokenizer = .{
        .buffer = tree.source,
        .index = start,
        .pending_invalid_token = null,
    };

    const token = tokenizer.next();
    std.debug.assert(token.tag == tag);
    return .{ .start = token.loc.start, .end = token.loc.end };
}

/// Token location inside source
pub const Loc = struct {
    start: usize,
    end: usize,
};

// Updated version from std that allows for failures
// by removing the unreachables and returning up to that point
// so that we can always provide information while the user is still typing
pub fn lastToken(tree: ast.Tree, node: ast.Node.Index) ast.TokenIndex {
    const Node = ast.Node;
    const TokenIndex = ast.TokenIndex;
    const tags = tree.nodes.items(.tag);
    const datas = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const token_starts = tree.tokens.items(.start);
    const token_tags = tree.tokens.items(.tag);
    var n = node;
    var end_offset: TokenIndex = 0;
    while (true) switch (tags[n]) {
        .root => return @intCast(TokenIndex, tree.tokens.len - 1),

        .@"usingnamespace",
        .bool_not,
        .negation,
        .bit_not,
        .negation_wrap,
        .address_of,
        .@"try",
        .@"await",
        .optional_type,
        .@"resume",
        .@"nosuspend",
        .@"comptime",
        => n = datas[n].lhs,

        .test_decl,
        .@"errdefer",
        .@"defer",
        .@"catch",
        .equal_equal,
        .bang_equal,
        .less_than,
        .greater_than,
        .less_or_equal,
        .greater_or_equal,
        .assign_mul,
        .assign_div,
        .assign_mod,
        .assign_add,
        .assign_sub,
        .assign_bit_shift_left,
        .assign_bit_shift_right,
        .assign_bit_and,
        .assign_bit_xor,
        .assign_bit_or,
        .assign_mul_wrap,
        .assign_add_wrap,
        .assign_sub_wrap,
        .assign,
        .merge_error_sets,
        .mul,
        .div,
        .mod,
        .array_mult,
        .mul_wrap,
        .add,
        .sub,
        .array_cat,
        .add_wrap,
        .sub_wrap,
        .bit_shift_left,
        .bit_shift_right,
        .bit_and,
        .bit_xor,
        .bit_or,
        .@"orelse",
        .bool_and,
        .bool_or,
        .anyframe_type,
        .error_union,
        .if_simple,
        .while_simple,
        .for_simple,
        .fn_proto_simple,
        .fn_proto_multi,
        .ptr_type_aligned,
        .ptr_type_sentinel,
        .ptr_type,
        .ptr_type_bit_range,
        .array_type,
        .switch_case_one,
        .switch_case,
        .switch_range,
        => n = datas[n].rhs,

        .field_access,
        .unwrap_optional,
        .grouped_expression,
        .multiline_string_literal,
        .error_set_decl,
        .asm_simple,
        .asm_output,
        .asm_input,
        .error_value,
        => return datas[n].rhs + end_offset,

        .@"anytype",
        .anyframe_literal,
        .char_literal,
        .integer_literal,
        .float_literal,
        .false_literal,
        .true_literal,
        .null_literal,
        .undefined_literal,
        .unreachable_literal,
        .identifier,
        .deref,
        .enum_literal,
        .string_literal,
        => return main_tokens[n] + end_offset,

        .@"return" => if (datas[n].lhs != 0) {
            n = datas[n].lhs;
        } else {
            return main_tokens[n] + end_offset;
        },

        .call, .async_call => {
            end_offset += 1; // for the rparen
            const params = tree.extraData(datas[n].rhs, Node.SubRange);
            if (params.end - params.start == 0) {
                return main_tokens[n] + end_offset;
            }
            n = tree.extra_data[params.end - 1]; // last parameter
        },
        .tagged_union_enum_tag => {
            const members = tree.extraData(datas[n].rhs, Node.SubRange);
            if (members.end - members.start == 0) {
                end_offset += 4; // for the rparen + rparen + lbrace + rbrace
                n = datas[n].lhs;
            } else {
                end_offset += 1; // for the rbrace
                n = tree.extra_data[members.end - 1]; // last parameter
            }
        },
        .call_comma,
        .async_call_comma,
        .tagged_union_enum_tag_trailing,
        => {
            end_offset += 2; // for the comma/semicolon + rparen/rbrace
            const params = tree.extraData(datas[n].rhs, Node.SubRange);
            std.debug.assert(params.end > params.start);
            n = tree.extra_data[params.end - 1]; // last parameter
        },
        .@"switch" => {
            const cases = tree.extraData(datas[n].rhs, Node.SubRange);
            if (cases.end - cases.start == 0) {
                end_offset += 3; // rparen, lbrace, rbrace
                n = datas[n].lhs; // condition expression
            } else {
                end_offset += 1; // for the rbrace
                n = tree.extra_data[cases.end - 1]; // last case
            }
        },
        .container_decl_arg => {
            const members = tree.extraData(datas[n].rhs, Node.SubRange);
            if (members.end - members.start == 0) {
                end_offset += 3; // for the rparen + lbrace + rbrace
                n = datas[n].lhs;
            } else {
                end_offset += 1; // for the rbrace
                n = tree.extra_data[members.end - 1]; // last parameter
            }
        },
        .@"asm" => {
            const extra = tree.extraData(datas[n].rhs, Node.Asm);
            return extra.rparen + end_offset;
        },
        .array_init,
        .struct_init,
        => {
            const elements = tree.extraData(datas[n].rhs, Node.SubRange);
            std.debug.assert(elements.end - elements.start > 0);
            end_offset += 1; // for the rbrace
            n = tree.extra_data[elements.end - 1]; // last element
        },
        .array_init_comma,
        .struct_init_comma,
        .container_decl_arg_trailing,
        .switch_comma,
        => {
            const members = tree.extraData(datas[n].rhs, Node.SubRange);
            std.debug.assert(members.end - members.start > 0);
            end_offset += 2; // for the comma + rbrace
            n = tree.extra_data[members.end - 1]; // last parameter
        },
        .array_init_dot,
        .struct_init_dot,
        .block,
        .container_decl,
        .tagged_union,
        .builtin_call,
        => {
            std.debug.assert(datas[n].rhs - datas[n].lhs > 0);
            end_offset += 1; // for the rbrace
            n = tree.extra_data[datas[n].rhs - 1]; // last statement
        },
        .array_init_dot_comma,
        .struct_init_dot_comma,
        .block_semicolon,
        .container_decl_trailing,
        .tagged_union_trailing,
        .builtin_call_comma,
        => {
            std.debug.assert(datas[n].rhs - datas[n].lhs > 0);
            end_offset += 2; // for the comma/semicolon + rbrace/rparen
            n = tree.extra_data[datas[n].rhs - 1]; // last member
        },
        .call_one,
        .async_call_one,
        .array_access,
        => {
            end_offset += 1; // for the rparen/rbracket
            if (datas[n].rhs == 0) {
                return main_tokens[n] + end_offset;
            }
            n = datas[n].rhs;
        },
        .array_init_dot_two,
        .block_two,
        .builtin_call_two,
        .struct_init_dot_two,
        .container_decl_two,
        .tagged_union_two,
        => {
            if (datas[n].rhs != 0) {
                end_offset += 1; // for the rparen/rbrace
                n = datas[n].rhs;
            } else if (datas[n].lhs != 0) {
                end_offset += 1; // for the rparen/rbrace
                n = datas[n].lhs;
            } else {
                switch (tags[n]) {
                    .array_init_dot_two,
                    .block_two,
                    .struct_init_dot_two,
                    => end_offset += 1, // rbrace
                    .builtin_call_two => end_offset += 2, // lparen/lbrace + rparen/rbrace
                    .container_decl_two => {
                        var i: u32 = 2; // lbrace + rbrace
                        while (token_tags[main_tokens[n] + i] == .container_doc_comment) i += 1;
                        end_offset += i;
                    },
                    .tagged_union_two => {
                        var i: u32 = 5; // (enum) {}
                        while (token_tags[main_tokens[n] + i] == .container_doc_comment) i += 1;
                        end_offset += i;
                    },
                    else => unreachable,
                }
                return main_tokens[n] + end_offset;
            }
        },
        .array_init_dot_two_comma,
        .builtin_call_two_comma,
        .block_two_semicolon,
        .struct_init_dot_two_comma,
        .container_decl_two_trailing,
        .tagged_union_two_trailing,
        => {
            end_offset += 2; // for the comma/semicolon + rbrace/rparen
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else if (datas[n].lhs != 0) {
                n = datas[n].lhs;
            } else {
                return main_tokens[n] + end_offset; // returns { }
            }
        },
        .simple_var_decl => {
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else if (datas[n].lhs != 0) {
                n = datas[n].lhs;
            } else {
                end_offset += 1; // from mut token to name
                return main_tokens[n] + end_offset;
            }
        },
        .aligned_var_decl => {
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else if (datas[n].lhs != 0) {
                end_offset += 1; // for the rparen
                n = datas[n].lhs;
            } else {
                end_offset += 1; // from mut token to name
                return main_tokens[n] + end_offset;
            }
        },
        .global_var_decl => {
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else {
                const extra = tree.extraData(datas[n].lhs, Node.GlobalVarDecl);
                if (extra.section_node != 0) {
                    end_offset += 1; // for the rparen
                    n = extra.section_node;
                } else if (extra.align_node != 0) {
                    end_offset += 1; // for the rparen
                    n = extra.align_node;
                } else if (extra.type_node != 0) {
                    n = extra.type_node;
                } else {
                    end_offset += 1; // from mut token to name
                    return main_tokens[n] + end_offset;
                }
            }
        },
        .local_var_decl => {
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else {
                const extra = tree.extraData(datas[n].lhs, Node.LocalVarDecl);
                if (extra.align_node != 0) {
                    end_offset += 1; // for the rparen
                    n = extra.align_node;
                } else if (extra.type_node != 0) {
                    n = extra.type_node;
                } else {
                    end_offset += 1; // from mut token to name
                    return main_tokens[n] + end_offset;
                }
            }
        },
        .container_field_init => {
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else if (datas[n].lhs != 0) {
                n = datas[n].lhs;
            } else {
                return main_tokens[n] + end_offset;
            }
        },
        .container_field_align => {
            if (datas[n].rhs != 0) {
                end_offset += 1; // for the rparen
                n = datas[n].rhs;
            } else if (datas[n].lhs != 0) {
                n = datas[n].lhs;
            } else {
                return main_tokens[n] + end_offset;
            }
        },
        .container_field => {
            const extra = tree.extraData(datas[n].rhs, Node.ContainerField);
            if (extra.value_expr != 0) {
                n = extra.value_expr;
            } else if (extra.align_expr != 0) {
                end_offset += 1; // for the rparen
                n = extra.align_expr;
            } else if (datas[n].lhs != 0) {
                n = datas[n].lhs;
            } else {
                return main_tokens[n] + end_offset;
            }
        },

        .array_init_one,
        .struct_init_one,
        => {
            end_offset += 1; // rbrace
            if (datas[n].rhs == 0) {
                return main_tokens[n] + end_offset;
            } else {
                n = datas[n].rhs;
            }
        },
        .slice_open,
        .call_one_comma,
        .async_call_one_comma,
        .array_init_one_comma,
        .struct_init_one_comma,
        => {
            end_offset += 2; // ellipsis2 + rbracket, or comma + rparen
            n = datas[n].rhs;
            std.debug.assert(n != 0);
        },
        .slice => {
            const extra = tree.extraData(datas[n].rhs, Node.Slice);
            std.debug.assert(extra.end != 0); // should have used slice_open
            end_offset += 1; // rbracket
            n = extra.end;
        },
        .slice_sentinel => {
            const extra = tree.extraData(datas[n].rhs, Node.SliceSentinel);
            std.debug.assert(extra.sentinel != 0); // should have used slice
            end_offset += 1; // rbracket
            n = extra.sentinel;
        },

        .@"continue" => {
            if (datas[n].lhs != 0) {
                return datas[n].lhs + end_offset;
            } else {
                return main_tokens[n] + end_offset;
            }
        },
        .@"break" => {
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else if (datas[n].lhs != 0) {
                return datas[n].lhs + end_offset;
            } else {
                return main_tokens[n] + end_offset;
            }
        },
        .fn_decl => {
            if (datas[n].rhs != 0) {
                n = datas[n].rhs;
            } else {
                n = datas[n].lhs;
            }
        },
        .fn_proto_one => {
            const extra = tree.extraData(datas[n].lhs, Node.FnProtoOne);
            // linksection, callconv, align can appear in any order, so we
            // find the last one here.
            var max_node: Node.Index = datas[n].rhs;
            var max_start = token_starts[main_tokens[max_node]];
            var max_offset: TokenIndex = 0;
            if (extra.align_expr != 0) {
                const start = token_starts[main_tokens[extra.align_expr]];
                if (start > max_start) {
                    max_node = extra.align_expr;
                    max_start = start;
                    max_offset = 1; // for the rparen
                }
            }
            if (extra.section_expr != 0) {
                const start = token_starts[main_tokens[extra.section_expr]];
                if (start > max_start) {
                    max_node = extra.section_expr;
                    max_start = start;
                    max_offset = 1; // for the rparen
                }
            }
            if (extra.callconv_expr != 0) {
                const start = token_starts[main_tokens[extra.callconv_expr]];
                if (start > max_start) {
                    max_node = extra.callconv_expr;
                    max_start = start;
                    max_offset = 1; // for the rparen
                }
            }
            n = max_node;
            end_offset += max_offset;
        },
        .fn_proto => {
            const extra = tree.extraData(datas[n].lhs, Node.FnProto);
            // linksection, callconv, align can appear in any order, so we
            // find the last one here.
            var max_node: Node.Index = datas[n].rhs;
            var max_start = token_starts[main_tokens[max_node]];
            var max_offset: TokenIndex = 0;
            if (extra.align_expr != 0) {
                const start = token_starts[main_tokens[extra.align_expr]];
                if (start > max_start) {
                    max_node = extra.align_expr;
                    max_start = start;
                    max_offset = 1; // for the rparen
                }
            }
            if (extra.section_expr != 0) {
                const start = token_starts[main_tokens[extra.section_expr]];
                if (start > max_start) {
                    max_node = extra.section_expr;
                    max_start = start;
                    max_offset = 1; // for the rparen
                }
            }
            if (extra.callconv_expr != 0) {
                const start = token_starts[main_tokens[extra.callconv_expr]];
                if (start > max_start) {
                    max_node = extra.callconv_expr;
                    max_start = start;
                    max_offset = 1; // for the rparen
                }
            }
            n = max_node;
            end_offset += max_offset;
        },
        .while_cont => {
            const extra = tree.extraData(datas[n].rhs, Node.WhileCont);
            std.debug.assert(extra.then_expr != 0);
            n = extra.then_expr;
        },
        .@"while" => {
            const extra = tree.extraData(datas[n].rhs, Node.While);
            std.debug.assert(extra.else_expr != 0);
            n = extra.else_expr;
        },
        .@"if", .@"for" => {
            const extra = tree.extraData(datas[n].rhs, Node.If);
            std.debug.assert(extra.else_expr != 0);
            n = extra.else_expr;
        },
        .@"suspend" => {
            if (datas[n].lhs != 0) {
                n = datas[n].lhs;
            } else {
                return main_tokens[n] + end_offset;
            }
        },
        .array_type_sentinel => {
            const extra = tree.extraData(datas[n].rhs, Node.ArrayTypeSentinel);
            n = extra.elem_type;
        },
    };
}

pub fn fnProto(tree: ast.Tree, node: ast.Node.Index, buf: *[1]ast.Node.Index) ?ast.full.FnProto {
    return switch (tree.nodes.items(.tag)[node]) {
        .fn_proto => tree.fnProto(node),
        .fn_proto_multi => tree.fnProtoMulti(node),
        .fn_proto_one => tree.fnProtoOne(buf, node),
        .fn_proto_simple => tree.fnProtoSimple(buf, node),
        .fn_decl => fnProto(tree, tree.nodes.items(.data)[node].lhs, buf),
        else => null,
    };
}

/// Gets a function signature (keywords, name, return value)
pub fn getVariableSignature(tree: ast.Tree, var_decl: ast.full.VarDecl) []const u8 {
    const start = tokenLocation(tree, var_decl.ast.mut_token).start;
    const end = tokenLocation(tree, lastToken(tree, var_decl.ast.init_node)).end;
    return tree.source[start..end];
}

/// Returns an `ast.full.VarDecl` for a given node index.
/// Returns null if the tag doesn't match
pub fn varDecl(tree: ast.Tree, node_idx: ast.Node.Index) ?ast.full.VarDecl {
    return switch (tree.nodes.items(.tag)[node_idx]) {
        .global_var_decl => tree.globalVarDecl(node_idx),
        .local_var_decl => tree.localVarDecl(node_idx),
        .aligned_var_decl => tree.alignedVarDecl(node_idx),
        .simple_var_decl => tree.simpleVarDecl(node_idx),
        else => null,
    };
}

pub fn isNodePublic(tree: ast.Tree, node: ast.Node.Index) bool {
    var buf: [1]ast.Node.Index = undefined;
    return switch (tree.nodes.items(.tag)[node]) {
        .global_var_decl,
        .local_var_decl,
        .simple_var_decl,
        .aligned_var_decl,
        => varDecl(tree, node).?.visib_token != null,
        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_decl,
        => fnProto(tree, node, &buf).?.visib_token != null,
        else => true,
    };
}

pub fn isTypeFunction(tree: ast.Tree, func: ast.full.FnProto) bool {
    return typeIsType(tree, func.ast.return_type);
}

/// The type node is "type"
fn typeIsType(tree: ast.Tree, node: ast.Node.Index) bool {
    if (tree.nodes.items(.tag)[node] == .identifier) {
        return std.mem.eql(u8, tree.tokenSlice(tree.nodes.items(.main_token)[node]), "type");
    }
    return false;
}

pub fn findReturnStatement(tree: ast.Tree, fn_decl: ast.full.FnProto, body: ast.Node.Index) ?ast.Node.Index {
    var already_found = false;
    return findReturnStatementInternal(tree, fn_decl, body, &already_found);
}

fn findReturnStatementInternal(
    tree: ast.Tree,
    fn_decl: ast.full.FnProto,
    body: ast.Node.Index,
    already_found: *bool,
) ?ast.Node.Index {
    var result: ?ast.Node.Index = null;

    const node_tags = tree.nodes.items(.tag);
    const datas = tree.nodes.items(.data);

    if (!isBlock(tree, body)) return null;

    const statements: []const ast.Node.Index = switch (node_tags[body]) {
        .block, .block_semicolon => tree.extra_data[datas[body].lhs..datas[body].rhs],
        .block_two, .block_two_semicolon => blk: {
            const statements = &[_]ast.Node.Index{ datas[body].lhs, datas[body].rhs };
            const len: usize = if (datas[body].lhs == 0)
                @as(usize, 0)
            else if (datas[body].rhs == 0)
                @as(usize, 1)
            else
                @as(usize, 2);
            break :blk statements[0..len];
        },
        else => unreachable,
    };

    for (statements) |child_idx| {
        if (node_tags[child_idx] == .@"return") {
            if (datas[child_idx].lhs != 0) {
                const lhs = datas[child_idx].lhs;
                if (isCall(tree, lhs)) {
                    const call_name = getDeclName(tree, datas[lhs].lhs);
                    if (call_name) |name| {
                        if (std.mem.eql(u8, name, tree.tokenSlice(fn_decl.name_token.?))) {
                            continue;
                        }
                    }
                }
            }

            if (already_found.*) return null;
            already_found.* = true;
            result = child_idx;
            continue;
        }

        result = findReturnStatementInternal(tree, fn_decl, child_idx, already_found);
    }

    return result;
}

fn isBlock(tree: ast.Tree, node: ast.Node.Index) bool {
    return switch (tree.nodes.items(.tag)[node]) {
        .block,
        .block_semicolon,
        .block_two,
        .block_two_semicolon,
        => true,
        else => false,
    };
}

/// Returns `true` when the given `node` is one of the call tags
fn isCall(tree: ast.Tree, node: ast.Node.Index) bool {
    return switch (tree.nodes.items(.tag)[node]) {
        .call,
        .call_comma,
        .call_one,
        .call_one_comma,
        .async_call,
        .async_call_comma,
        .async_call_one,
        .async_call_one_comma,
        => true,
        else => false,
    };
}

fn getDeclName(tree: ast.Tree, node: ast.Node.Index) ?[]const u8 {
    const name = tree.tokenSlice(getDeclNameToken(tree, node) orelse return null);
    return switch (tree.nodes.items(.tag)[node]) {
        .test_decl => name[1 .. name.len - 1],
        else => name,
    };
}

pub fn getDeclNameToken(tree: ast.Tree, node: ast.Node.Index) ?ast.TokenIndex {
    const tags = tree.nodes.items(.tag);
    const main_token = tree.nodes.items(.main_token)[node];
    return switch (tags[node]) {
        // regular declaration names. + 1 to mut token because name comes after 'const'/'var'
        .local_var_decl => tree.localVarDecl(node).ast.mut_token + 1,
        .global_var_decl => tree.globalVarDecl(node).ast.mut_token + 1,
        .simple_var_decl => tree.simpleVarDecl(node).ast.mut_token + 1,
        .aligned_var_decl => tree.alignedVarDecl(node).ast.mut_token + 1,

        // function declaration names
        .fn_proto,
        .fn_proto_multi,
        .fn_proto_one,
        .fn_proto_simple,
        .fn_decl,
        => blk: {
            var params: [1]ast.Node.Index = undefined;
            break :blk fnProto(tree, node, &params).?.name_token;
        },

        // containers
        .container_field => tree.containerField(node).ast.name_token,
        .container_field_init => tree.containerFieldInit(node).ast.name_token,
        .container_field_align => tree.containerFieldAlign(node).ast.name_token,

        .identifier => main_token,
        .error_value => main_token + 2, // 'error'.<main_token +2>

        // lhs of main token is name token, so use `node` - 1
        .test_decl => if (tree.tokens.items(.tag)[main_token + 1] == .string_literal)
            return main_token + 1
        else
            null,
        else => null,
    };
}

// stolen from zig-doctest :^P

pub fn escapeHtml(allocator: *mem.Allocator, input: []const u8) ![]u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    const out = buf.writer();
    try writeEscaped(out, input);
    return buf.toOwnedSlice();
}

pub fn writeEscaped(out: anytype, input: []const u8) !void {
    for (input) |c| {
        try switch (c) {
            '&' => out.writeAll("&amp;"),
            '<' => out.writeAll("&lt;"),
            '>' => out.writeAll("&gt;"),
            '"' => out.writeAll("&quot;"),
            else => out.writeByte(c),
        };
    }
}
pub fn highlightZigCode(raw_src: []const u8, out: anytype, pre: bool) !void {
    // TODO: who should be doing this cleanup?
    const src = mem.trim(u8, raw_src, " \n");
    if (pre)
        try out.writeAll("<pre><code class=\"zig\">")
    else
        try out.writeAll("<code class=\"zig\">");
    var tokenizer = std.zig.Tokenizer.init(src);
    var index: usize = 0;
    var next_tok_is_fn = false;
    while (true) {
        const prev_tok_was_fn = next_tok_is_fn;
        next_tok_is_fn = false;

        const token = tokenizer.next();
        try writeEscaped(out, src[index..token.loc.start]);
        switch (token.tag) {
            .eof => break,

            .keyword_align,
            .keyword_and,
            .keyword_asm,
            .keyword_async,
            .keyword_await,
            .keyword_break,
            .keyword_catch,
            .keyword_comptime,
            .keyword_const,
            .keyword_continue,
            .keyword_defer,
            .keyword_else,
            .keyword_enum,
            .keyword_errdefer,
            .keyword_error,
            .keyword_export,
            .keyword_extern,
            .keyword_for,
            .keyword_if,
            .keyword_inline,
            .keyword_noalias,
            .keyword_noinline,
            .keyword_nosuspend,
            .keyword_opaque,
            .keyword_or,
            .keyword_orelse,
            .keyword_packed,
            .keyword_anyframe,
            .keyword_pub,
            .keyword_resume,
            .keyword_return,
            .keyword_linksection,
            .keyword_callconv,
            .keyword_struct,
            .keyword_suspend,
            .keyword_switch,
            .keyword_test,
            .keyword_threadlocal,
            .keyword_try,
            .keyword_union,
            .keyword_unreachable,
            .keyword_usingnamespace,
            .keyword_var,
            .keyword_volatile,
            .keyword_allowzero,
            .keyword_while,
            .keyword_anytype,
            => {
                try out.writeAll("<span class=\"tok tok-kw\">");
                try writeEscaped(out, src[token.loc.start..token.loc.end]);
                try out.writeAll("</span>");
            },

            .keyword_fn => {
                try out.writeAll("<span class=\"tok tok-kw\">");
                try writeEscaped(out, src[token.loc.start..token.loc.end]);
                try out.writeAll("</span>");
                next_tok_is_fn = true;
            },

            .keyword_undefined,
            .keyword_null,
            .keyword_true,
            .keyword_false,
            => {
                try out.writeAll("<span class=\"tok tok-null\">");
                try writeEscaped(out, src[token.loc.start..token.loc.end]);
                try out.writeAll("</span>");
            },

            .string_literal,
            .multiline_string_literal_line,
            .char_literal,
            => {
                try out.writeAll("<span class=\"tok tok-str\">");
                try writeEscaped(out, src[token.loc.start..token.loc.end]);
                try out.writeAll("</span>");
            },

            .builtin => {
                try out.writeAll("<span class=\"tok tok-builtin\">");
                try writeEscaped(out, src[token.loc.start..token.loc.end]);
                try out.writeAll("</span>");
            },

            .doc_comment,
            .container_doc_comment,
            => {
                try out.writeAll("<span class=\"tok tok-comment\">");
                try writeEscaped(out, src[token.loc.start..token.loc.end]);
                try out.writeAll("</span>");
            },

            .identifier => {
                if (prev_tok_was_fn) {
                    try out.writeAll("<span class=\"tok tok-fn\">");
                    try writeEscaped(out, src[token.loc.start..token.loc.end]);
                    try out.writeAll("</span>");
                } else {
                    const is_int = blk: {
                        if (src[token.loc.start] != 'i' and src[token.loc.start] != 'u')
                            break :blk false;
                        var i = token.loc.start + 1;
                        if (i == token.loc.end)
                            break :blk false;
                        while (i != token.loc.end) : (i += 1) {
                            if (src[i] < '0' or src[i] > '9')
                                break :blk false;
                        }
                        break :blk true;
                    };
                    if (is_int or isType(src[token.loc.start..token.loc.end])) {
                        try out.writeAll("<span class=\"tok tok-type\">");
                        try writeEscaped(out, src[token.loc.start..token.loc.end]);
                        try out.writeAll("</span>");
                    } else {
                        try out.writeAll("<span class=\"tok\">");
                        try writeEscaped(out, src[token.loc.start..token.loc.end]);
                        try out.writeAll("</span>");
                    }
                }
            },

            .integer_literal,
            .float_literal,
            => {
                try out.writeAll("<span class=\"tok tok-number\">");
                try writeEscaped(out, src[token.loc.start..token.loc.end]);
                try out.writeAll("</span>");
            },

            .bang,
            .pipe,
            .pipe_pipe,
            .pipe_equal,
            .equal,
            .equal_equal,
            .equal_angle_bracket_right,
            .bang_equal,
            .l_paren,
            .r_paren,
            .semicolon,
            .percent,
            .percent_equal,
            .l_brace,
            .r_brace,
            .l_bracket,
            .r_bracket,
            .period,
            .period_asterisk,
            .ellipsis2,
            .ellipsis3,
            .caret,
            .caret_equal,
            .plus,
            .plus_plus,
            .plus_equal,
            .plus_percent,
            .plus_percent_equal,
            .minus,
            .minus_equal,
            .minus_percent,
            .minus_percent_equal,
            .asterisk,
            .asterisk_equal,
            .asterisk_asterisk,
            .asterisk_percent,
            .asterisk_percent_equal,
            .arrow,
            .colon,
            .slash,
            .slash_equal,
            .comma,
            .ampersand,
            .ampersand_equal,
            .question_mark,
            .angle_bracket_left,
            .angle_bracket_left_equal,
            .angle_bracket_angle_bracket_left,
            .angle_bracket_angle_bracket_left_equal,
            .angle_bracket_right,
            .angle_bracket_right_equal,
            .angle_bracket_angle_bracket_right,
            .angle_bracket_angle_bracket_right_equal,
            .tilde,
            => {
                try out.writeAll("<span class=\"tok tok-symbol\">");
                try writeEscaped(out, src[token.loc.start..token.loc.end]);
                try out.writeAll("</span>");
            },
            .invalid, .invalid_ampersands, .invalid_periodasterisks => {}, // do nothing on parse error
        }
        index = token.loc.end;
    }
    if (pre)
        try out.writeAll("</code></pre>")
    else
        try out.writeAll("</code>");
}

const builtin_types = [_][]const u8{
    "f16",         "f32",      "f64",    "f128",     "c_longdouble", "c_short",
    "c_ushort",    "c_int",    "c_uint", "c_long",   "c_ulong",      "c_longlong",
    "c_ulonglong", "c_char",   "c_void", "void",     "bool",         "isize",
    "usize",       "noreturn", "type",   "anyerror", "comptime_int", "comptime_float",
};

fn isType(name: []const u8) bool {
    for (builtin_types) |t| {
        if (mem.eql(u8, t, name))
            return true;
    }
    return false;
}
