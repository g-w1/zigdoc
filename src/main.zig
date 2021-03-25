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
;

const AnalysedDecl = struct {
    /// The doc comment of the decl
    /// Owned by this decl
    doc_comment: ?[]const u8,
    /// The signature of the function (non-optional)
    /// Should have the lifetime of the src code input
    sig: []const u8,

    more: ?[]AnalysedDecl = null,

    fn deinit(self: *@This(), ally: *std.mem.Allocator) void {
        if (self.more) |more| {
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
        try writer.writeAll("----------\n");
        try writer.writeAll(if (self.doc_comment) |dc| dc else "No Doc Comment");
        try writer.writeByte('\n');
        try writer.print("pub {s}", .{self.sig});
    }
};

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

/// The result must be freed
fn analyzeFromSource(ally: *std.mem.Allocator, src: []const u8) ![]AnalysedDecl {
    var tree = try std.zig.parse(ally, zig_code);
    defer tree.deinit(ally);

    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);

    var list = std.ArrayList(AnalysedDecl).init(ally);

    for (tree.rootDecls()) |decl_addr| if (util.isNodePublic(tree, decl_addr)) {
        var doc: ?[]const u8 = null;
        var sig: ?[]const u8 = null;
        if (try util.getDocComments(ally, tree, decl_addr)) |dc| {
            doc = dc;
        }

        const tag = node_tags[decl_addr];

        if (tag == .fn_decl) {
            // handle if it is a function
            const proto = node_datas[decl_addr].lhs;
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
            sig = util.getVariableSignature(tree, vardecl);
        } else @panic("TODO: we need more stuff");

        var ad: AnalysedDecl = .{
            .sig = sig.?,
            .doc_comment = doc,
        };
        try list.append(ad);
    };
    return list.toOwnedSlice();
}
