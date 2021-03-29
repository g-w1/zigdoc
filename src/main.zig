const std = @import("std");

const ast = std.zig.ast;

const util = @import("utils.zig");

var tree: ast.Tree = undefined;

const AnalysedDecl = struct {
    /// The doc comment of the decl
    /// Owned by this decl
    dc: ?[]const u8,

    pl: []const u8,

    sub_cont_ty: ?[]const u8 = null,

    md: ?[]AnalysedDecl = null,

    src: struct {
        line: usize,
        column: usize,
    },

    fn deinit(self: *@This(), ally: *std.mem.Allocator) void {
        if (self.md) |more| {
            for (more) |*item| {
                item.deinit(ally);
            }
            ally.free(more);
        }
        if (self.dc) |dc| {
            ally.free(dc);
        }
        ally.free(self.pl);
        self.* = undefined;
    }
    pub fn jsonStringify(self: AnalysedDecl, options: anytype, writer: anytype) !void {
        try writer.writeAll("{");
        if (self.dc) |d| {
            try writer.writeAll("\"doc_comment\":");
            try std.json.stringify(d, options, writer);
            try writer.writeAll(",");
        }
        try writer.writeAll("\"pl\":");
        try std.json.stringify(self.pl, options, writer);
        try writer.writeAll(",");
        if (self.sub_cont_ty) |s| {
            try writer.writeAll("\"sub_container_type\":");
            try std.json.stringify(s, options, writer);
            try writer.writeAll(",");
        }
        try writer.writeAll("\"src\":");
        try std.json.stringify(self.src, options, writer);
        try writer.writeAll(",");
        if (self.md) |m| {
            try writer.writeAll("\"more_decls\":");
            try std.json.stringify(m, options, writer);
        } else {
            try writer.writeAll("\"more_decls\":[]");
        }
        try writer.writeAll("}");
    }
    pub fn htmlStringify(self: AnalysedDecl, writer: anytype) std.fs.File.WriteError!void {
        try writer.writeAll("<div class=\"anal-decl\">");
        // doc comment
        if (self.dc) |d| {
            try util.writeEscaped(writer, d);
            try writer.writeByte('\n');
        }
        // payload
        try writer.writeAll("<pre><code class=\"zig\">");
        try writer.writeAll(self.pl);
        try writer.writeAll("</code></pre>");

        // TODO src loc
        if (self.md) |m| {
            try writer.writeAll("<div class=\"more-decls\">");
            for (m) |decl| {
                try decl.htmlStringify(writer);
            }
            try writer.writeAll("</div>");
        }
        try writer.writeAll("</div>");
    }
};

fn fatal(s: []const u8) noreturn {
    std.log.emerg("{s}\n", .{s});
    std.process.exit(1);
}

const Args = struct {
    fname: [:0]const u8,
    docs_url: ?[:0]const u8 = null,
    type: enum { json, html } = .json,
};

pub fn main() anyerror!void {
    var general_pa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = general_pa.deinit();

    const ally = &general_pa.allocator;

    const args = try std.process.argsAlloc(ally);
    defer ally.free(args);
    if (args.len < 2)
        fatal("the first argument needs to be the zig file to run zigdoc on");
    var opts: Args = .{ .fname = args[1] };
    if (args.len >= 3) {
        var i: usize = 2;
        while (i < args.len) : (i += 1) {
            const arg = args[i];
            if (std.mem.eql(u8, arg, "-json"))
                opts.type = .json
            else if (std.mem.eql(u8, arg, "-html"))
                opts.type = .html
            else if (std.mem.eql(u8, arg, "-url")) {
                if (i == args.len) fatal("need an argument after -url");
                opts.docs_url = args[i + 1];
                i += 1;
            }
        }
    }

    const zig_code = std.fs.cwd().readFileAlloc(ally, std.mem.spanZ(std.os.argv[1]), 2 * 1024 * 1024 * 1024) catch fatal("could not read file provided");
    defer ally.free(zig_code);

    tree = try std.zig.parse(ally, zig_code);
    defer tree.deinit(ally);
    const decls = tree.rootDecls();

    var anal_list = try recAnalListOfDecls(ally, decls);

    defer {
        for (anal_list) |*anal| {
            anal.deinit(ally);
        }
        ally.free(anal_list);
    }

    const stdout = std.io.getStdOut().writer();
    if (opts.type == .json)
        try std.json.stringify(anal_list, .{}, stdout)
    else {
        try stdout.writeAll(
            \\<style type="text/css" >
            \\ .more-decls {
            \\     padding-left: 50px;
            \\ }
            \\ .anal-decl {
            \\     background-color: #F7A41D77;
            \\ }
            \\ * {
            \\     background-color: #F7A41D22;
            \\ }
            \\</style>
        );
        try stdout.writeAll("<div class=\"more-decls\">");
        for (anal_list) |decl| {
            try decl.htmlStringify(stdout);
        }
        try stdout.writeAll("</div>");
    }
}

fn recAnalListOfDecls(
    ally: *std.mem.Allocator,
    list_d: []const ast.Node.Index,
) error{OutOfMemory}![]AnalysedDecl {
    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const token_starts = tree.tokens.items(.start);

    var list = std.ArrayList(AnalysedDecl).init(ally);

    for (list_d) |member| if (util.isNodePublic(tree, member)) {
        const tag = node_tags[member];

        // we know it has to be a vardecl now
        const decl_addr = member;
        var doc: ?[]const u8 = null;
        if (try util.getDocComments(ally, tree, decl_addr)) |dc| {
            doc = dc;
        }
        if (tag == .container_field or tag == .container_field_align or tag == .container_field_init) {
            const ftoken = tree.firstToken(member);
            const ltoken = tree.lastToken(member);
            const start = token_starts[ftoken];
            const end = token_starts[ltoken + 1];
            try list.append(.{
                .pl = try ally.dupe(u8, tree.source[start..end]),
                .dc = doc,
                .md = null,
                .src = blk: {
                    const src = std.zig.findLineColumn(tree.source, start);
                    break :blk .{ .line = src.line, .column = src.column };
                },
            });
            continue;
        } else if (tag == .fn_decl) {
            var d = try doFunction(ally, decl_addr);
            d.dc = doc;
            try list.append(d);
            continue;
        } else if (tag == .global_var_decl or
            tag == .local_var_decl or
            tag == .simple_var_decl or
            tag == .aligned_var_decl)
        {
            // handle if it is a vardecl
            const vardecl = util.varDecl(tree, decl_addr).?;

            const name_loc = vardecl.ast.mut_token + 1;
            const name = tree.tokenSlice(name_loc);

            const init = node_datas[decl_addr].rhs;
            const rhst = node_tags[init];

            // we find if the var is a container, we dont wanna display the full thing if it is
            // then we recurse over it
            var buf: [2]ast.Node.Index = undefined;
            var cd = getContainer(node_datas[decl_addr].rhs, &buf);
            if (cd) |container_decl| {
                const offset = if (container_decl.ast.enum_token != null)
                    if (rhst == .tagged_union_enum_tag or rhst == .tagged_union_enum_tag_trailing)
                        @as(u32, 7)
                    else
                        @as(u32, 4)
                else
                    @as(u32, 1);
                const more = try recAnalListOfDecls(ally, container_decl.ast.members);
                try list.append(.{
                    .pl = try ally.dupe(u8, tree.source[token_starts[tree.firstToken(member)]..token_starts[
                        main_tokens[init] + offset
                    ]]),
                    .dc = doc,
                    .md = more,
                    .src = blk: {
                        const src = std.zig.findLineColumn(tree.source, token_starts[tree.firstToken(decl_addr)]);
                        break :blk .{ .line = src.line, .column = src.column };
                    },
                });
                continue;
            } else {
                const sig = util.getVariableSignature(tree, vardecl);
                var ad: AnalysedDecl = .{
                    .pl = try ally.dupe(u8, sig),
                    .dc = doc,
                    .md = null,
                    .src = blk: {
                        const src = std.zig.findLineColumn(tree.source, token_starts[tree.firstToken(decl_addr)]);
                        break :blk .{ .line = src.line, .column = src.column };
                    },
                };
                try list.append(ad);
                continue;
            }
        } else if (tag == .fn_proto or
            tag == .fn_proto_multi or
            tag == .fn_proto_one or
            tag == .fn_proto_simple)
        {
            var params: [1]ast.Node.Index = undefined;
            const fn_proto = util.fnProto(
                tree,
                member,
                &params,
            ).?;

            var sig: []const u8 = undefined;
            {
                var start = util.tokenLocation(tree, fn_proto.extern_export_token.?);
                // return type can be 0 when user wrote incorrect fn signature
                // to ensure we don't break, just end the signature at end of fn token
                if (fn_proto.ast.return_type == 0) sig = tree.source[start.start..start.end];
                const end = util.tokenLocation(tree, tree.lastToken(fn_proto.ast.return_type)).end;
                sig = tree.source[start.start..end];
            }
            sig = try ally.dupe(u8, sig);
            var ad: AnalysedDecl = .{
                .pl = sig,
                .dc = doc,
                .md = null,
                .src = blk: {
                    const src = std.zig.findLineColumn(tree.source, token_starts[tree.firstToken(decl_addr)]);
                    break :blk .{ .line = src.line, .column = src.column };
                },
            };
            try list.append(ad);
            continue;
        } else {
            continue;
        }
        unreachable;
    };
    return list.toOwnedSlice();
}

fn doFunction(ally: *std.mem.Allocator, decl_addr: ast.Node.Index) !AnalysedDecl {
    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const token_starts = tree.tokens.items(.start);

    const full_source = tree.source[token_starts[tree.firstToken(decl_addr)] .. token_starts[tree.lastToken(decl_addr)] + 1];

    // TODO configure max
    if (nlGtMax(full_source, 5)) {
        // handle if it is a function and the number of lines is greater than max
        const proto = node_datas[decl_addr].lhs;
        const block = node_datas[decl_addr].rhs;
        var params: [1]ast.Node.Index = undefined;

        const fn_proto = util.fnProto(
            tree,
            proto,
            &params,
        ).?;

        const sig = util.getFunctionSignature(tree, fn_proto);

        var sub_cont_ty: ?[]const u8 = null;
        const md = if (util.isTypeFunction(tree, fn_proto)) blk: {
            const ret = util.findReturnStatement(tree, fn_proto, block) orelse break :blk null;
            if (node_datas[ret].lhs == 0) break :blk null;
            var buf: [2]ast.Node.Index = undefined;
            const container = getContainer(node_datas[ret].lhs, &buf) orelse break :blk null;

            const offset = if (container.ast.enum_token != null)
                if (node_tags[node_datas[ret].lhs] == .tagged_union_enum_tag or
                    node_tags[node_datas[ret].lhs] == .tagged_union_enum_tag_trailing)
                    @as(u32, 7)
                else
                    @as(u32, 4)
            else
                @as(u32, 1);

            sub_cont_ty = tree.source[token_starts[tree.firstToken(node_datas[ret].lhs)]..token_starts[
                main_tokens[node_datas[ret].lhs] + offset
            ]];

            break :blk try recAnalListOfDecls(ally, container.ast.members);
        } else null;
        return AnalysedDecl{
            .pl = try ally.dupe(u8, sig),
            // to be filled in later
            .dc = undefined,
            .md = md,
            .sub_cont_ty = sub_cont_ty,
            .src = blk: {
                const src = std.zig.findLineColumn(tree.source, token_starts[tree.firstToken(decl_addr)]);
                break :blk .{ .line = src.line, .column = src.column };
            },
        };
    } else {
        return AnalysedDecl{
            .pl = try removeNewLinesFromRest(ally, full_source),
            .dc = undefined,
            .md = null,
            .src = blk: {
                const src = std.zig.findLineColumn(tree.source, token_starts[tree.firstToken(decl_addr)]);
                break :blk .{ .line = src.line, .column = src.column };
            },
        };
    }
}

fn getContainer(decl_addr: ast.Node.Index, buf: *[2]ast.Node.Index) ?ast.full.ContainerDecl {
    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const token_starts = tree.tokens.items(.start);

    const rhst = node_tags[decl_addr];

    // we find if the var is a container, we dont wanna display the full thing if it is
    // then we recurse over it
    return if (rhst == .container_decl or rhst == .container_decl_trailing) tree.containerDecl(decl_addr) else if (rhst == .container_decl_arg or rhst == .container_decl_arg_trailing)
        tree.containerDeclArg(decl_addr)
    else if (rhst == .container_decl_two or rhst == .container_decl_two_trailing) blk: {
        break :blk tree.containerDeclTwo(buf, decl_addr);
    } else if (rhst == .tagged_union or rhst == .tagged_union_trailing)
        tree.taggedUnion(decl_addr)
    else if (rhst == .tagged_union_two or rhst == .tagged_union_two_trailing) blk: {
        break :blk tree.taggedUnionTwo(buf, decl_addr);
    } else if (rhst == .tagged_union_enum_tag or rhst == .tagged_union_enum_tag_trailing)
        tree.taggedUnionEnumTag(decl_addr)
    else
        null;
}

fn nlGtMax(str: []const u8, max: usize) bool {
    var n: usize = 0;
    for (str) |c| {
        if (c == '\n') n += 1;
        if (n > max) return true;
    }
    return false;
}

/// returns an owned slice
/// O(2n)
fn removeNewLinesFromRest(ally: *std.mem.Allocator, s: []const u8) ![]const u8 {
    var numspaces: u32 = 0;
    var pure = false;
    var on_first_line = true;
    for (s) |c, i| {
        if (on_first_line) {
            if (c == '\n') on_first_line = false else continue;
        }
        if (c == ' ') {
            if (pure) numspaces += 1;
        } else if (c == '\n') {
            if (!(i == s.len - 1))
                numspaces = 0;
            pure = true;
        } else pure = false;
    }
    on_first_line = true;
    pure = true;
    const num_on_last = numspaces;
    var z = std.ArrayList(u8).init(ally);
    for (s) |c| {
        if (on_first_line) {
            if (c == '\n') {
                pure = false;
                numspaces = 0;
                on_first_line = false;
            }
            try z.append(c);
            continue;
        }
        if (c == '\n') {
            numspaces = 0;
            try z.append('\n');
        } else numspaces += 1;
        if (!(numspaces <= num_on_last))
            try z.append(c);
    }
    return z.toOwnedSlice();
}
