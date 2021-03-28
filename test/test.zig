/// Here is our a
a: usize,

pub extern fn thing() c_int;
pub extern fn thing_largo(a: c_int, b: c_int, z: c_int) c_int;
pub fn x() void {
    return;
}
pub export fn thinggy() void {}
/// Z func
pub fn Z() type {
    return union(enum) {
        a: u32,
        b: usize,
        d: u32,
        pub fn bruh() nested {
            return "bruh";
        }
        pub const HAZE = bruh();
    };
}
pub const A = 1;
const B = 2;

/// Here is our z struct
pub const D = union(enum) {
    /// Here is the index of the rust code
    rust: u32,
    /// This performs the z function. big functions dont get inlined, but small ones do
    pub fn z(self: @This()) u32 {
        return 1;
    }
    /// WOW: even more
    pub const EvenMoreInner = struct {
        /// This function should get inlined because it is small
        pub fn v() void {
            return;
        }
    };
};
pub const V = union(enum(u32)) {
    /// Our special u32 type. we ***need*** "distinct types"
    pub const A = u32;
};
