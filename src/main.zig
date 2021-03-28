const std = @import("std");

const ast = std.zig.ast;

const util = @import("utils.zig");

const zig_code =
    \\/// Here is our a
    \\a: usize,
    \\
    \\pub extern fn thing() c_int;
    \\pub extern fn thing_largo(a: c_int, b: c_int, z: c_int) c_int;
    \\pub fn x() void {
    \\    return;
    \\}
    \\/// Z func
    \\pub fn Z() type {
    \\    return union(enum) {
    \\        a: u32,
    \\        b: usize,
    \\        d: u32,
    \\        pub fn bruh() nested {
    \\            return "bruh";
    \\        }
    \\        pub const HAZE = bruh();
    \\    };
    \\}
    \\pub const A = 1;
    \\const B = 2;
    \\
    \\/// Here is our z struct
    \\pub const D = union(enum) {
    \\    /// Here is the index of the rust code
    \\    rust: u32,
    \\    /// This performs the z function. big functions dont get inlined, but small ones do
    \\    pub fn z(self: @This()) u32 {
    \\
    \\
    \\
    \\
    \\
    \\
    \\
    \\
    \\
    \\
    \\
    \\
    \\
    \\
    \\
    \\        return 1;
    \\    }
    \\    /// WOW: even more
    \\    pub const EvenMoreInner = struct {
    \\        /// This function should get inlined because it is small
    \\        pub fn v() void {
    \\            return;
    \\        }
    \\    };
    \\
    \\};
    \\pub const V = union(enum(u32)) {
    \\    /// Our special u32 type. we ***need*** "distinct types"
    \\    pub const A = u32;
    \\};
;

var tree: ast.Tree = undefined;

const AnalysedDecl = struct {
    /// The doc comment of the decl
    /// Owned by this decl
    dc: ?[]const u8,

    pl: []const u8,

    sub_cont_ty: ?[]const u8 = null,

    md: ?[]AnalysedDecl = null,

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
        self.* = undefined;
    }
};

pub fn main() anyerror!void {
    var general_pa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 8 }){};
    defer _ = general_pa.deinit();

    const ally = &general_pa.allocator;

    const stdout = std.io.getStdOut().writer();

    try stdout.print("src:\n{s}\nparsed:\n", .{zig_code});

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

    try std.json.stringify(anal_list, .{ .whitespace = .{} }, stdout);
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
                .pl = tree.source[start..end],
                .dc = doc,
                .md = null,
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
            var cd = getContainer(node_datas[decl_addr].rhs);
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
                    .pl = tree.source[token_starts[tree.firstToken(member)]..token_starts[
                        main_tokens[init] + offset
                    ]],
                    .dc = doc,
                    .md = more,
                });
                continue;
            } else {
                const sig = util.getVariableSignature(tree, vardecl);
                var ad: AnalysedDecl = .{
                    .pl = sig,
                    .dc = doc,
                    .md = null,
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
            var ad: AnalysedDecl = .{
                .pl = sig,
                .dc = doc,
                .md = null,
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
            const container = getContainer(node_datas[ret].lhs) orelse break :blk null;

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
            .pl = sig,
            // to be filled in later
            .dc = undefined,
            .md = md,
            .sub_cont_ty = sub_cont_ty,
        };
    } else {
        return AnalysedDecl{
            .pl = full_source,
            .dc = undefined,
            .md = null,
        };
    }
}

fn getContainer(decl_addr: ast.Node.Index) ?ast.full.ContainerDecl {
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
        var buf: [2]ast.Node.Index = undefined;
        break :blk tree.containerDeclTwo(&buf, decl_addr);
    } else if (rhst == .tagged_union or rhst == .tagged_union_trailing)
        tree.taggedUnion(decl_addr)
    else if (rhst == .tagged_union_two or rhst == .tagged_union_two_trailing) blk: {
        var buf: [2]ast.Node.Index = undefined;
        break :blk tree.taggedUnionTwo(&buf, decl_addr);
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
