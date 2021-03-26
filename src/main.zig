const std = @import("std");

const ast = std.zig.ast;

const util = @import("utils.zig");

const zig_code =
    \\a: usize,
    \\pub fn x() void {
    \\    return;
    \\}
    \\pub const A = 1;
    \\const B = 2;
    \\/// Here is our z struct
    \\pub const D = union(enum) {
    \\    /// Here is the index of the rust code
    \\    rust: u32,
    \\    /// This preforms the z function
    \\    pub fn z(self: @This()) u32 {
    \\        return 1;
    \\    }
    \\    /// WOW: even more
    \\    pub const EvenMoreInner = struct {
    \\        pub fn v() void {}
    \\    };
    \\};
;

var tree: ast.Tree = undefined;

const AnalysedDecl = struct {
    /// The doc comment of the decl
    /// Owned by this decl
    doc_comment: ?[]const u8,

    more_decls: ?[]AnalysedDecl = null,

    payload: []const u8,

    fn deinit(self: *@This(), ally: *std.mem.Allocator) void {
        if (self.more_decls) |more| {
            for (more) |*item| {
                item.deinit(ally);
            }
            ally.free(more);
        }
        if (self.doc_comment) |dc| {
            ally.free(dc);
        }
        self.* = undefined;
    }

    pub fn format(
        self: AnalysedDecl,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.writeByte('{');
        // TODO escape strings
        try writer.print("payload:\"{s}\",", .{self.payload});
        if (self.doc_comment) |dc| {
            // TODO escape strings
            try writer.print("doccomment:\"{s}\",", .{dc});
        }
        if (self.more_decls) |more| {
            try writer.writeAll("more:[");
            for (more) |anal| {
                // TODO make no terminating commas
                try writer.print("{},", .{anal});
            }
            try writer.writeByte(']');
        }
        try writer.writeByte('}');
    }
};

pub fn main() anyerror!void {
    var general_pa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 8 }){};
    defer _ = general_pa.deinit();

    const ally = &general_pa.allocator;

    std.debug.print("src:\n{s}\nparsed:\n", .{zig_code});

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
    try renderListAnalDeclsToJsonArray(stdout, anal_list);
}

fn renderListAnalDeclsToJsonArray(writer: anytype, l: []const AnalysedDecl) !void {
    try writer.writeByte('[');
    for (l) |anal| {
        // TODO make no terminating comma
        try writer.print("{},", .{anal});
    }
    try writer.writeByte(']');
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
                .payload = tree.source[start..end],
                .doc_comment = doc,
                .more_decls = null,
            });
            continue;
        } else if (tag == .fn_decl) {
            // handle if it is a function
            const proto = node_datas[decl_addr].lhs;
            const block = node_datas[decl_addr].rhs;
            var params: [1]ast.Node.Index = undefined;
            const sig = util.getFunctionSignature(tree, util.fnProto(
                tree,
                proto,
                &params,
            ).?);
            var ad: AnalysedDecl = .{
                .payload = sig,
                .doc_comment = doc,
                // TODO fill in struct functions inside a function
                .more_decls = null,
            };
            try list.append(ad);
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
            var cd: ?ast.full.ContainerDecl = null;
            if (rhst == .container_decl or rhst == .container_decl_trailing) {
                cd = tree.containerDecl(init);
            }
            if (rhst == .container_decl_arg or rhst == .container_decl_arg_trailing) {
                cd = tree.containerDeclArg(init);
            }
            if (rhst == .container_decl_two or rhst == .container_decl_two_trailing) {
                var buf: [2]ast.Node.Index = undefined;
                cd = tree.containerDeclTwo(&buf, init);
            }
            if (rhst == .tagged_union or
                rhst == .tagged_union_trailing)
            {
                cd = tree.taggedUnion(init);
            }
            if (rhst == .tagged_union_two or
                rhst == .tagged_union_two_trailing)
            {
                var buf: [2]ast.Node.Index = undefined;
                cd = tree.taggedUnionTwo(&buf, init);
            }
            if (rhst == .tagged_union_enum_tag or
                rhst == .tagged_union_enum_tag_trailing)
            {
                cd = tree.taggedUnionEnumTag(init);
            }
            if (cd) |container_decl| {
                const more = try recAnalListOfDecls(ally, container_decl.ast.members);
                try list.append(.{
                    .payload = tree.source[token_starts[tree.firstToken(member)]..token_starts[
                        main_tokens[init] +
                            // TODO correctly handle tagged union(enum(u32))
                            if (container_decl.ast.enum_token != null) @as(u32, 4) else @as(u32, 1)
                    ]],
                    .doc_comment = doc,
                    .more_decls = more,
                });
                continue;
            } else {
                const sig = util.getVariableSignature(tree, vardecl);
                var ad: AnalysedDecl = .{
                    .payload = sig,
                    .doc_comment = doc,
                    .more_decls = null,
                };
                try list.append(ad);
                continue;
            }
        } else {
            std.debug.print("TODO: we need more stuff: {}", .{tag});
            continue;
        }
        unreachable;
    };
    return list.toOwnedSlice();
}
