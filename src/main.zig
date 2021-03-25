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
    \\pub const D = struct {
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

    type: union(enum) {
        /// The signature of the function (non-optional)
        /// Should have the lifetime of the src code input
        nocontainer: []const u8,
        // TODO add default value to field
        field: struct {
            name: []const u8,
            type: []const u8,
        },
        container: struct {
            name: []const u8,
            type: []const u8,
        },
    },

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
        try writer.writeAll("\n----------\n");
        try writer.writeAll(if (self.doc_comment) |dc| dc else "No Doc Comment");
        try writer.writeByte('\n');
        switch (self.type) {
            .nocontainer => |sig| try writer.writeAll(sig),
            .container => |nf| {
                try writer.print("const {s} = {s}\n", .{ nf.name, nf.type });
            },
            .field => |f| {
                try writer.print("{s}: {s}\n", .{ f.name, f.type });
            },
        }
        if (self.more_decls) |more| {
            for (more) |anal| {
                try anal.formatIndent(1, writer);
            }
        }
    }

    pub fn formatIndent(self: AnalysedDecl, indent_level: u32, writer: anytype) std.os.WriteError!void {
        try writer.writeAll("----------\n");
        const indentx4 = indent_level * 4;
        try writer.writeByteNTimes(' ', indentx4);
        try writer.writeAll(if (self.doc_comment) |dc| dc else "No Doc Comment");
        try writer.writeByte('\n');
        try writer.writeByteNTimes(' ', indentx4);
        switch (self.type) {
            .nocontainer => |sig| try writer.writeAll(sig),
            .container => |nf| {
                try writer.writeByteNTimes(' ', indentx4);
                try writer.print("const {s} = {s}", .{ nf.name, nf.type });
            },
            .field => |f| {
                try writer.writeByteNTimes(' ', indentx4);
                try writer.print("{s}: {s}", .{ f.name, f.type });
            },
        }
        try writer.writeByte('\n');
        if (self.more_decls) |more| {
            for (more) |anal| {
                try anal.formatIndent(indent_level + 1, writer);
            }
        }
    }
};

pub fn main() anyerror!void {
    var general_pa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 8 }){};
    defer _ = general_pa.deinit();

    const ally = &general_pa.allocator;

    std.debug.print("src:\n{s}\nparsed:", .{zig_code});

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

    for (anal_list) |anal| {
        std.debug.print("{}\n", .{anal});
    }
}

fn recAnalListOfDecls(
    ally: *std.mem.Allocator,
    list_d: []const ast.Node.Index,
) error{OutOfMemory}![]AnalysedDecl {
    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);

    var list = std.ArrayList(AnalysedDecl).init(ally);

    for (list_d) |member| if (util.isNodePublic(tree, member)) {
        const tag = node_tags[member];

        // we know it has to be a vardecl now
        const decl_addr = member;
        var doc: ?[]const u8 = null;
        var sig: ?[]const u8 = null;
        var more: ?[]AnalysedDecl = null;
        if (try util.getDocComments(ally, tree, decl_addr)) |dc| {
            doc = dc;
        }
        if (tag == .container_field or tag == .container_field_align or tag == .container_field_init) {
            try list.append(.{
                .type = .{ .field = .{ .name = tree.tokenSlice(main_tokens[member]), .type = tree.tokenSlice(main_tokens[member + 1]) } },
                .doc_comment = doc,
                .more_decls = null,
            });
            continue;
        } else if (tag == .fn_decl) {
            // handle if it is a function
            const proto = node_datas[decl_addr].lhs;
            const block = node_datas[decl_addr].rhs;
            var params: [1]ast.Node.Index = undefined;
            sig = util.getFunctionSignature(tree, util.fnProto(
                tree,
                proto,
                &params,
            ).?);
            var ad: AnalysedDecl = .{
                .type = .{ .nocontainer = sig.? },
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
            if (cd) |container_decl| {
                more = try recAnalListOfDecls(ally, container_decl.ast.members);
                try list.append(.{
                    .type = .{ .container = .{ .name = name, .type = tree.tokenSlice(main_tokens[init]) } },
                    .doc_comment = doc,
                    .more_decls = more,
                });
                continue;
            } else {
                sig = util.getVariableSignature(tree, vardecl);
                var ad: AnalysedDecl = .{
                    .type = .{ .nocontainer = sig.? },
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
