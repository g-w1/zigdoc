const std = @import("std");

const ast = std.zig.ast;

const util = @import("utils.zig");

const zig_code =
    \\/// Heres a function
    \\pub fn main() void {
    \\  bruh();
    \\}
    \\/// another function (not pub)
    \\fn brhu(aoen, aosiet ) vart {
    \\  return 2;
    \\}
    \\/// Heres a const
    \\pub var B = 0;
    \\/// Heres a vardecl
    \\pub const A = 0;
    \\/// Some doc comments
    \\/// Here
    \\/// For this struct
    \\pub const X = struct {
    \\  /// THIS IS A
    \\  /// DOC COMMENT PUNNY
    \\  a: u32,
    \\  b: usize,
    \\  c: f32,
    \\  /// Returns 1
    \\  pub fn x() u32 {
    \\    return 1;
    \\  }
    \\  /// LOLLOLOLO
    \\  pub const ARST = 1;
    \\};
    \\pub fn b() void {
    \\  return;
    \\}
;

var tree: ast.Tree = undefined;

pub fn main() anyerror!void {
    var general_pa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 8 }){};
    defer _ = general_pa.deinit();

    const ally = &general_pa.allocator;

    var anal_list = try analyzeFromSource(ally, zig_code);
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
        try writer.writeAll("\n----------\n");
        const indentx4 = indent_level * 4;
        try writer.writeByteNTimes(' ', indentx4);
        try writer.writeAll(if (self.doc_comment) |dc| dc else "No Doc Comment");
        try writer.writeByte('\n');
        try writer.writeByteNTimes(' ', indentx4);
        switch (self.type) {
            .nocontainer => |sig| try writer.writeAll(sig),
            .container => |nf| {
                try writer.writeByteNTimes(' ', indentx4);
                try writer.print("const {s} = {s}\n", .{ nf.name, nf.type });
            },
            .field => |f| {
                try writer.writeByteNTimes(' ', indentx4);
                try writer.print("{s}: {s}\n", .{ f.name, f.type });
            },
        }
        if (self.more_decls) |more| {
            for (more) |anal| {
                try anal.formatIndent(indent_level + 1, writer);
            }
        }
    }
};

/// The result must be freed
fn analyzeFromSource(ally: *std.mem.Allocator, src: []const u8) ![]AnalysedDecl {
    tree = try std.zig.parse(ally, zig_code);
    defer tree.deinit(ally);

    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);

    var list = std.ArrayList(AnalysedDecl).init(ally);

    for (tree.rootDecls()) |decl_addr| if (util.isNodePublic(tree, decl_addr)) {
        var doc: ?[]const u8 = null;
        var sig: ?[]const u8 = null;
        var more: ?[]AnalysedDecl = null;
        if (try util.getDocComments(ally, tree, decl_addr)) |dc| {
            doc = dc;
        }

        const tag = node_tags[decl_addr];

        if (tag == .fn_decl) {
            // handle if it is a function
            const proto = node_datas[decl_addr].lhs;
            const block = node_datas[decl_addr].rhs;
            var params: [1]ast.Node.Index = undefined;
            sig = util.getFunctionSignature(tree, util.fnProto(
                tree,
                proto,
                &params,
            ).?);
        } else if (tag == .global_var_decl or
            tag == .local_var_decl or
            tag == .simple_var_decl or
            tag == .aligned_var_decl)
        {
            // handle if it is a vardecl
            const vardecl = util.varDecl(tree, decl_addr).?;

            const init = node_datas[decl_addr].rhs;
            const rhst = node_tags[init];
            var cd: ?ast.full.ContainerDecl = null;
            if (rhst == .container_decl or rhst == .container_decl_trailing) {
                cd = tree.containerDecl(init);
            }
            if (rhst == .container_decl_arg or rhst == .container_decl_arg_trailing) {
                cd = tree.containerDeclArg(init);
            }
            if (cd) |container_decl| {
                more = try recAnalDecl(ally, container_decl);
            }
            sig = util.getVariableSignature(tree, vardecl);
        } else std.debug.panic("we need more stuff: {}", .{tag});

        var ad: AnalysedDecl = .{
            .type = .{ .nocontainer = sig.? },
            .doc_comment = doc,
            .more_decls = more,
        };
        try list.append(ad);
    };
    return list.toOwnedSlice();
}

fn recAnalDecl(ally: *std.mem.Allocator, container: ast.full.ContainerDecl) error{OutOfMemory}![]AnalysedDecl {
    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    var list = std.ArrayList(AnalysedDecl).init(ally);
    for (container.ast.members) |member| {
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

            const init = node_datas[decl_addr].lhs;
            const lhst = node_tags[init];
            var cd: ?ast.full.ContainerDecl = null;
            if (lhst == .container_decl or lhst == .container_decl_trailing) {
                cd = tree.containerDecl(init);
            }
            if (lhst == .container_decl_arg or lhst == .container_decl_arg_trailing) {
                cd = tree.containerDeclArg(init);
            }
            if (cd) |container_decl| {
                more = try recAnalDecl(ally, container_decl);
                var ad: AnalysedDecl = .{
                    .type = .{ .container = .{ .name = name, .type = "TODO" } },
                    .doc_comment = doc,
                    .more_decls = more,
                };
                try list.append(ad);
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
    }
    return list.toOwnedSlice();
}
