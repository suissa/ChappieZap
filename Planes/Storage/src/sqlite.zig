const std = @import("std");

pub const c = @cImport({
    @cInclude("sqlite3.h");
});

pub const SqliteError = error{
    SqliteError,
    SqliteBusy,
    SqliteConstraint,
    SqliteMismatch,
    SqliteNotFound,
    SqliteCorrupt,
    SqliteCannotOpen,
};

pub fn checkRc(rc: c_int) !void {
    return switch (rc) {
        c.SQLITE_OK, c.SQLITE_DONE, c.SQLITE_ROW => {},
        c.SQLITE_BUSY => error.SqliteBusy,
        c.SQLITE_CONSTRAINT => error.SqliteConstraint,
        c.SQLITE_MISMATCH => error.SqliteMismatch,
        c.SQLITE_NOTFOUND => error.SqliteNotFound,
        c.SQLITE_CORRUPT => error.SqliteCorrupt,
        c.SQLITE_CANTOPEN => error.SqliteCannotOpen,
        else => error.SqliteError,
    };
}

pub const Db = struct {
    handle: ?*c.sqlite3,

    pub fn open(path: [:0]const u8) !Db {
        var db_ptr: ?*c.sqlite3 = null;
        const flags = c.SQLITE_OPEN_READWRITE | c.SQLITE_OPEN_CREATE | c.SQLITE_OPEN_FULLMUTEX;
        const rc = c.sqlite3_open_v2(path.ptr, &db_ptr, flags, null);
        try checkRc(rc);
        return Db{ .handle = db_ptr };
    }

    pub fn close(self: *Db) void {
        if (self.handle) |db| {
            _ = c.sqlite3_close_v2(db);
            self.handle = null;
        }
    }

    pub fn exec(self: Db, sql: [:0]const u8) !void {
        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.handle, sql.ptr, null, null, &err_msg);
        if (err_msg != null) {
            c.sqlite3_free(err_msg);
        }
        try checkRc(rc);
    }

    pub fn prepare(self: Db, sql: [:0]const u8) !Stmt {
        var stmt_ptr: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.handle, sql.ptr, @intCast(sql.len), &stmt_ptr, null);
        try checkRc(rc);
        return Stmt{ .handle = stmt_ptr };
    }
};

pub const Stmt = struct {
    handle: ?*c.sqlite3_stmt,

    pub fn finalize(self: *Stmt) void {
        if (self.handle) |stmt| {
            _ = c.sqlite3_finalize(stmt);
            self.handle = null;
        }
    }

    pub fn reset(self: Stmt) !void {
        try checkRc(c.sqlite3_reset(self.handle));
    }

    pub fn bindText(self: Stmt, col_1indexed: c_int, text: []const u8) !void {
        const rc = c.sqlite3_bind_text(self.handle, col_1indexed, text.ptr, @intCast(text.len), c.SQLITE_TRANSIENT);
        try checkRc(rc);
    }

    pub fn bindBlob(self: Stmt, col_1indexed: c_int, blob: []const u8) !void {
        const rc = c.sqlite3_bind_blob(self.handle, col_1indexed, blob.ptr, @intCast(blob.len), c.SQLITE_TRANSIENT);
        try checkRc(rc);
    }

    pub fn bindInt64(self: Stmt, col_1indexed: c_int, val: i64) !void {
        const rc = c.sqlite3_bind_int64(self.handle, col_1indexed, val);
        try checkRc(rc);
    }

    pub fn bindNull(self: Stmt, col_1indexed: c_int) !void {
        const rc = c.sqlite3_bind_null(self.handle, col_1indexed);
        try checkRc(rc);
    }

    pub fn step(self: Stmt) !bool {
        const rc = c.sqlite3_step(self.handle);
        if (rc == c.SQLITE_ROW) return true;
        if (rc == c.SQLITE_DONE) return false;
        try checkRc(rc);
        return false;
    }

    pub fn columnText(self: Stmt, col_0indexed: c_int) ?[]const u8 {
        const ptr = c.sqlite3_column_text(self.handle, col_0indexed);
        if (ptr == null) return null;
        const len = c.sqlite3_column_bytes(self.handle, col_0indexed);
        return ptr[0..@intCast(len)];
    }

    pub fn columnBlob(self: Stmt, col_0indexed: c_int) ?[]const u8 {
        const ptr = c.sqlite3_column_blob(self.handle, col_0indexed);
        if (ptr == null) return null;
        const len = c.sqlite3_column_bytes(self.handle, col_0indexed);
        const u8_ptr: [*]const u8 = @ptrCast(ptr);
        return u8_ptr[0..@intCast(len)];
    }

    pub fn columnInt64(self: Stmt, col_0indexed: c_int) i64 {
        return c.sqlite3_column_int64(self.handle, col_0indexed);
    }
};
