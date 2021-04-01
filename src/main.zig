const std = @import("std");

const ast = std.zig.ast;

const util = @import("utils.zig");

var tree: ast.Tree = undefined;

const Md = struct {
    fields: std.ArrayList(AnalysedDecl),
    types: std.ArrayList(AnalysedDecl),
    funcs: std.ArrayList(AnalysedDecl),
    values: std.ArrayList(AnalysedDecl),

    pub fn init(ally: *std.mem.Allocator) !@This() {
        return @This(){
            .fields = std.ArrayList(AnalysedDecl).init(ally),
            .types = std.ArrayList(AnalysedDecl).init(ally),
            .funcs = std.ArrayList(AnalysedDecl).init(ally),
            .values = std.ArrayList(AnalysedDecl).init(ally),
        };
    }
    pub fn deinit(self: *const @This(), ally: *std.mem.Allocator) void {
        inline for (comptime std.meta.fieldNames(@This())) |n| {
            for (@field(self, n).items) |*anal| {
                anal.deinit(ally);
            }
            @field(self, n).deinit();
        }
    }
    pub fn jsonStringify(self: @This(), options: anytype, writer: anytype) !void {
        for (self.fields.items) |anal| {
            try anal.jsonStringify(options, writer);
        }
        for (self.types.items) |anal| {
            try anal.jsonStringify(options, writer);
        }
        for (self.funcs.items) |anal| {
            try anal.jsonStringify(options, writer);
        }
        for (self.values.items) |anal| {
            try anal.jsonStringify(options, writer);
        }
    }
};

const AnalysedDecl = struct {
    /// The doc comment of the decl
    /// Owned by this decl
    dc: ?[]const u8,

    /// Should be owned by this decl
    pl: []const u8,

    sub_cont_ty: ?[]const u8 = null,

    md: ?Md,

    // TODO: make a range
    src: usize,

    fn deinit(self: *const @This(), ally: *std.mem.Allocator) void {
        if (self.md) |*m|
            m.deinit(ally);
        ally.free(self.pl);
        if (self.dc) |d|
            ally.free(d);
        if (self.sub_cont_ty) |s|
            ally.free(s);
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
        try writer.writeAll("\"more_decls\":");
        try std.json.stringify(self.md, options, writer);
        try writer.writeAll("}");
    }

    pub fn htmlStringify(self: AnalysedDecl, writer: anytype) std.fs.File.WriteError!void {
        try writer.writeAll("<div class=\"anal-decl\">");
        // doc comment
        if (self.dc) |d| {
            try writer.writeAll("<b>");
            try util.writeEscaped(writer, d);
            try writer.writeByte('\n');
            try writer.writeAll("</b>");
        }
        // payload

        if (opts.docs_url) |url| {
            // TODO src loc
            try writer.print("<a href=\"{s}{s}#L{d}\">src</a>", .{ opts.docs_url, cur_file, self.src + 1 });
        }
        try util.highlightZigCode(self.pl, writer, true);
        if (self.md != null) {
            if (self.md.?.fields.items.len > 0) {
                try writer.writeAll("<details><summary>fields:</summary>");
                try writer.writeAll("<div class=\"md-fields more-decls\">");
                for (self.md.?.fields.items) |decl| {
                    try decl.htmlStringify(writer);
                }
                try writer.writeAll("</div>");
                try writer.writeAll("</details>");
            }
            if (self.md.?.types.items.len > 0) {
                try writer.writeAll("<details><summary>types:</summary>");
                try writer.writeAll("<div class=\"md-types more-decls\">");
                for (self.md.?.types.items) |decl| {
                    try decl.htmlStringify(writer);
                }
                try writer.writeAll("</div>");
                try writer.writeAll("</details>");
            }
            if (self.md.?.funcs.items.len > 0) {
                try writer.writeAll("<details><summary>funcs</summary>");
                try writer.writeAll("<div class=\"md-funcs more-decls\">");
                for (self.md.?.funcs.items) |decl| {
                    try decl.htmlStringify(writer);
                }
                try writer.writeAll("</div>");
                try writer.writeAll("</details>");
            }
            if (self.md.?.values.items.len > 0) {
                try writer.writeAll("<details><summary>values:</summary>");
                try writer.writeAll("<div class=\"md-vals more-decls\">");
                for (self.md.?.values.items) |decl| {
                    try decl.htmlStringify(writer);
                }
                try writer.writeAll("</div>");
                try writer.writeAll("</details>");
            }
        }
        try writer.writeAll("</div>");
    }
};

fn fatal(s: []const u8) noreturn {
    std.log.emerg("{s}\n", .{s});
    std.process.exit(1);
}

fn fatalArgs(comptime s: []const u8, args: anytype) noreturn {
    std.log.emerg(s, args);
    std.process.exit(1);
}

const Args = struct {
    dirname: []const u8,
    docs_url: ?[]const u8 = null,
    type: enum { json, html } = .html,
    output_dir: []const u8 = "docs",
};

var opts: Args = undefined;
var cur_file: []const u8 = undefined;

fn removeTrailingSlash(n: [:0]u8) []u8 {
    if (std.mem.endsWith(u8, n, "/"))
        return n[0 .. n.len - 1];
    return n;
}

pub fn main() (error{ OutOfMemory, Overflow, InvalidCmdLine, TimerUnsupported } || std.os.UnexpectedError || std.os.WriteError)!void {
    var general_pa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 8 }){};
    defer _ = general_pa.deinit();

    const ally = &general_pa.allocator;

    const args = try std.process.argsAlloc(ally);
    defer ally.free(args);
    if (args.len < 2)
        fatal("the first argument needs to be the directory to run zigdoc on");
    opts = .{ .dirname = removeTrailingSlash(args[1]) };
    if (args.len >= 3) {
        var i: usize = 2;
        while (i < args.len) : (i += 1) {
            const arg = args[i];
            if (std.mem.eql(u8, arg, "-json"))
                opts.type = .json
            else if (std.mem.eql(u8, arg, "-html"))
                opts.type = .html
            else if (std.mem.eql(u8, arg, "-o")) {
                if (i == args.len) fatal("need an argument after -o");
                opts.output_dir = args[i + 1];
                i += 1;
            } else if (std.mem.eql(u8, arg, "-url")) {
                if (i == args.len) fatal("need an argument after -url");
                var durl: [:0]u8 = args[i + 1];
                opts.docs_url = removeTrailingSlash(durl);
                i += 1;
            }
        }
    }

    var walker = std.fs.walkPath(ally, opts.dirname) catch |e| fatalArgs("could not read dir: {s}: {}", .{ opts.dirname, e });
    defer walker.deinit();

    var file_to_anal_map = std.StringHashMap(Md).init(ally);
    defer {
        var iter = file_to_anal_map.iterator();
        while (iter.next()) |entry| {
            entry.value.deinit(ally);
            ally.free(entry.key);
        }
        file_to_anal_map.deinit();
    }

    var progress: std.Progress = .{};
    var main_progress_node = try progress.start("", 0);
    main_progress_node.activate();
    defer main_progress_node.end();
    var analyse_node = main_progress_node.start("Analysis", 0);
    analyse_node.activate();
    var i: usize = 0;
    while (walker.next() catch |e| fatalArgs("could not read next directory walker item: {}", .{e})) |entry| {
        if (std.mem.endsWith(u8, entry.path, ".zig")) {
            const strings = compareStrings(entry.path, opts.dirname);
            const str = try ally.dupe(u8, strings);
            if (!(file_to_anal_map.contains(strings))) {
                i += 1;
                var node = analyse_node.start(strings, i + 1);
                node.activate();
                // screw thread safety!
                node.unprotected_completed_items = i;
                defer node.end();
                const list = try getAnalFromFile(ally, entry.path);
                const pogr = try file_to_anal_map.put(str, list);
            }
        }
    }
    analyse_node.end();

    var output_dir = std.fs.cwd().makeOpenPath(opts.output_dir, .{}) catch |e| switch (e) {
        error.PathAlreadyExists => std.fs.cwd().openDir(opts.output_dir, .{}) catch |er| fatalArgs("could not open docs folder: {}", .{er}),
        else => |er| fatalArgs("could not make a \"docs\" output dir: {}", .{er}),
    };
    defer output_dir.close();
    var iter = file_to_anal_map.iterator();
    if (opts.type == .html) {
        while (iter.next()) |entry| {
            cur_file = entry.key;
            const dname = std.fs.path.dirname(entry.key).?[1..]; // remove the first /
            var output_path = if (!std.mem.eql(u8, dname, ""))
                (output_dir.makeOpenPath(dname, .{}) catch |e| fatalArgs("could not make dir {s}: {}", .{ dname, e }))
            else
                (output_dir.openDir(".", .{}) catch |e| fatalArgs("could not open dir '.': {}", .{e}));
            defer output_path.close();
            const name_to_open = std.fs.path.basename(entry.key);
            const catted = try std.mem.concat(ally, u8, &.{ name_to_open, ".html" });
            defer ally.free(catted);
            const output_file = output_path.createFile(catted, .{}) catch |e| fatalArgs("could not create file {s}: {}", .{ catted, e });
            defer output_file.close();
            const w = output_file.writer();
            const anal_list = entry.value;

            try w.print(our_css, .{ .our_background = background_color });
            try w.writeAll(code_css);
            try w.writeAll("<html>");
            try w.print("<a href=\"{s}/{s}\"><h1>{s}</h1></a>", .{ opts.docs_url, cur_file, cur_file });
            inline for (comptime std.meta.fieldNames(Md)) |n| {
                if (@field(anal_list, n).items.len != 0)
                    try w.print("<h2 style=\"color: orange;\">{s}:</h2>", .{n});
                try w.writeAll("<div class=\"more-decls\">");
                for (@field(anal_list, n).items) |decl| {
                    try decl.htmlStringify(w);
                }
                try w.writeAll("</div>");
            }
            try w.writeAll("</html>");
        }
    } else {
        while (iter.next()) |entry| {
            const dname = std.fs.path.dirname(entry.key).?[1..]; // remove the first /
            var output_path = if (!std.mem.eql(u8, dname, ""))
                (output_dir.makeOpenPath(dname, .{}) catch |e| fatalArgs("could not make dir {s}: {}", .{ dname, e }))
            else
                (output_dir.openDir(".", .{}) catch |e| fatalArgs("could not open dir '.': {}", .{e}));
            defer output_path.close();
            const name_to_open = std.fs.path.basename(entry.key);
            const catted = try std.mem.concat(ally, u8, &.{ name_to_open, ".json" });
            defer ally.free(catted);
            const output_file = output_path.createFile(catted, .{}) catch |e| fatalArgs("could not create file {s}: {}", .{ catted, e });
            defer output_file.close();
            const w = output_file.writer();
            const anal_list = entry.value;

            try w.writeAll("[");
            try std.json.stringify(anal_list, .{}, w);
            try w.writeAll("]");
        }
    }
}

fn getAnalFromFile(
    ally: *std.mem.Allocator,
    fname: []const u8,
) error{OutOfMemory}!Md {
    const zig_code = std.fs.cwd().readFileAlloc(ally, fname, 2 * 1024 * 1024 * 1024) catch fatal("could not read file provided");
    defer ally.free(zig_code);

    tree = std.zig.parse(ally, zig_code) catch |e| {
        std.log.emerg("could not parse zig file {s}: {}", .{ fname, e });
        fatal("parsing failed");
    };
    defer tree.deinit(ally);
    const decls = tree.rootDecls();

    const anal_list = try recAnalListOfDecls(ally, decls);

    return anal_list;
}

fn recAnalListOfDecls(
    ally: *std.mem.Allocator,
    list_d: []const ast.Node.Index,
) error{OutOfMemory}!Md {
    const node_tags = tree.nodes.items(.tag);
    const node_datas = tree.nodes.items(.data);
    const main_tokens = tree.nodes.items(.main_token);
    const token_starts = tree.tokens.items(.start);

    var list = try Md.init(ally);

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
            try list.fields.append(.{
                .pl = try ally.dupe(u8, tree.source[start..end]),
                .dc = doc,
                .md = null,
                .src = std.zig.findLineColumn(tree.source, start).line,
            });
            continue;
        } else if (tag == .fn_decl) {
            var d = try doFunction(ally, decl_addr);
            d.dc = doc;
            try list.funcs.append(d);
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
                try list.types.append(.{
                    .pl = try ally.dupe(u8, tree.source[token_starts[tree.firstToken(member)]..token_starts[
                        main_tokens[init] + offset
                    ]]),
                    .dc = doc,
                    .md = more,
                    .src = std.zig.findLineColumn(tree.source, token_starts[tree.firstToken(decl_addr)]).line,
                });
                continue;
            } else {
                const sig = util.getVariableSignature(tree, vardecl);
                var ad: AnalysedDecl = .{
                    .pl = try ally.dupe(u8, sig),
                    .dc = doc,
                    .md = null,
                    .src = std.zig.findLineColumn(tree.source, token_starts[tree.firstToken(decl_addr)]).line,
                };
                try list.values.append(ad);
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
                .src = std.zig.findLineColumn(tree.source, token_starts[tree.firstToken(decl_addr)]).line,
            };
            try list.types.append(ad);
            continue;
        } else {
            continue;
        }
        unreachable;
    };
    return list;
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
            .pl = try removeNewLinesFromRest(ally, sig),
            // to be filled in later
            .dc = null,
            .md = md,
            .sub_cont_ty = if (sub_cont_ty) |sct| try ally.dupe(u8, sct) else null,
            .src = std.zig.findLineColumn(tree.source, token_starts[tree.firstToken(decl_addr)]).line,
        };
    } else {
        return AnalysedDecl{
            .pl = try removeNewLinesFromRest(ally, full_source),
            // filled in later
            .dc = null,
            .md = null,
            .src = std.zig.findLineColumn(tree.source, token_starts[tree.firstToken(decl_addr)]).line,
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
/// ```
/// pub fn x() {
///         a();
///     }
/// ```
/// ->
/// ```
/// pub fn x() {
///     a();
/// }
/// ```
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

/// returns the difference of two strings reversed
/// asserts b is in a
fn compareStrings(a: []const u8, b: []const u8) []const u8 {
    const diff = a.len - b.len;
    return a[b.len..];
}
const background_color = "#F7A41D77";
const our_css =
    \\<style type="text/css" >
    \\.more-decls {{
    \\    padding-left: 50px;
    \\}}
    \\.anal-decl {{
    \\ background-color: {[our_background]s};
    \\}}
    \\code {{
    \\ background-color: {[our_background]s};
    \\}}
    \\</style>
;
const code_css =
    \\<style type="text/css" >
    \\pre > code {
    \\  display: block;
    \\  overflow: auto;
    \\  padding: 0.5em;
    \\  color: black;
    \\}
    \\
    \\details {
    \\  margin-bottom: 0.5em;
    \\  -webkit-touch-callout: none; /* iOS Safari */
    \\    -webkit-user-select: none; /* Safari */
    \\     -khtml-user-select: none; /* Konqueror HTML */
    \\       -moz-user-select: none; /* Old versions of Firefox */
    \\        -ms-user-select: none; /* Internet Explorer/Edge */
    \\            user-select: none; /* Non-prefixed version, currently
    \\                                  supported by Chrome, Edge, Opera and Firefox */
    \\}
    \\
    \\.tok {
    \\  color: #333;
    \\  font-style: normal;
    \\}
    \\
    \\.code {
    \\  font-family: monospace;
    \\  font-size: 0.8em;
    \\}
    \\
    \\.tok-kw {
    \\  color: #333;
    \\  font-weight: bold;
    \\}
    \\
    \\.tok-str {
    \\  color: #d14;
    \\}
    \\
    \\.tok-builtin {
    \\  color: #0086b3;
    \\}
    \\
    \\code.zig {
    \\  color: #777;
    \\  font-style: italic;
    \\}
    \\
    \\.tok-fn {
    \\  color: #900;
    \\  font-weight: bold;
    \\}
    \\
    \\.tok-null {
    \\  color: #008080;
    \\}
    \\
    \\.tok-number {
    \\  color: #008080;
    \\}
    \\
    \\.tok-type {
    \\  color: #458;
    \\  font-weight: bold;
    \\}
    \\</style>
;
