/* */
#ifdef _WIN32
__declspec(dllexport) void Init_rua(void);
#endif

#include <stddef.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <stdarg.h>
#include <math.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "iconv.h"

#include "ruby.h"

#ifndef RUBY_VM
#include "rubysig.h"
#else
#define TRAP_BEG
#define TRAP_END
#endif

#include "rua.h"

#ifndef RSTRING_PTR
#define RSTRING_PTR(s) (RSTRING(s)->ptr)
#endif

#ifndef RSTRING_LEN
#define RSTRING_LEN(s) (RSTRING(s)->len)
#endif

#ifndef RARRAY_PTR
#define RARRAY_PTR(s) (RARRAY(s)->ptr)
#endif

#ifndef RARRAY_LEN
#define RARRAY_LEN(s) (RARRAY(s)->len)
#endif

#ifndef RUBY_VM
#define rb_errinfo() ruby_errinfo
#endif

#define VERSION   "0.4.8"
#define REF_RBOBJ "self"

#define ICONV_JIS   "ISO-2022-JP"
#define ICONV_SJIS  "SJIS"
#define ICONV_EUC   "eucJP"
#define ICONV_UTF8  "UTF-8"

static const char *insecure_methods[] = {
  "__id__",
  "__send__",
  "ancestors",
  "autoload",
  "autoload?",
  "class",
  "class_eval",
  "class_variable_defined?",
  "class_variables",
  "const_defined?",
  "const_get",
  "const_missing",
  "const_set",
  "constants",
  "extend",
  "freeze",
  "id",
  "include?",
  "included_modules",
  "instance_eval",
  "instance_method",
  "instance_methods",
  "instance_variable_defined?",
  "instance_variable_get",
  "instance_variable_set",
  "instance_variables",
  "method",
  "method_defined?",
  "method_missing",
  "methods",
  "module_eval",
  "private_class_method",
  "private_instance_methods",
  "private_method_defined?",
  "private_methods",
  "protected_instance_methods",
  "protected_method_defined?",
  "protected_methods",
  "public_class_method",
  "public_instance_methods",
  "public_method_defined?",
  "public_methods",
  "respond_to?",
  "send",
  "singleton_methods",
  "taint",
  "to_ary",
  "to_hash",
  "to_int",
  "to_str",
  "type",
  "untaint"
};

static const int insecure_method_num = sizeof(insecure_methods) / sizeof(char*);
static VALUE Rua, RuaFunc, RuaThread, RuaError, RuaDebug;
static VALUE s_all, s_base, s_package, s_string, s_table, s_math, s_io, s_debug;
static VALUE m_method_unbound, m_methods_unbound;
static VALUE m_constants_unbound, m_const_get_unbound;

void Init_rua() {
  Rua = rb_define_class("Rua", rb_cObject);
  RuaFunc = rb_define_class("RuaFunc", rb_cObject);
  RuaThread = rb_define_class("RuaThread", rb_cObject);
  RuaError = rb_define_class("RuaError", rb_eStandardError);
  RuaDebug = rb_define_class("RuaDebug", rb_cObject);

  rb_define_alloc_func(Rua, rua_alloc);
  rb_define_const(Rua, "VERSION", rb_str_new2(VERSION));
  rb_define_const(Rua, "JIS", rb_str_new2(ICONV_JIS));
  rb_define_const(Rua, "SJIS", rb_str_new2(ICONV_SJIS));
  rb_define_const(Rua, "EUC", rb_str_new2(ICONV_EUC));
  //rb_define_const(Rua, "UTF8", rb_str_new2(ICONV_UTF8));
  rb_define_private_method(Rua, "initialize", rua_initialize, -1);
  rb_define_method(Rua, "openlibs", rua_openlibs, -1);
  rb_define_method(Rua, "eval", rua_eval, -1);
  rb_define_method(Rua, "[]", rua_get, 1);
  rb_define_method(Rua, "[]=", rua_set, 2);
  rb_define_method(Rua, "secure", rua_get_secure, 0);
  rb_define_method(Rua, "secure=", rua_set_secure, 1);
  rb_define_method(Rua, "abort_by_error", rua_get_abort_by_error, 0);
  rb_define_method(Rua, "abort_by_error=", rua_set_abort_by_error, 1);
  rb_define_method(Rua, "wrap_error", rua_get_wrap_error, 0);
  rb_define_method(Rua, "wrap_error=", rua_set_wrap_error, 1);
  rb_define_method(Rua, "external_charset", rua_get_external_charset, 0);
  rb_define_method(Rua, "external_charset=", rua_set_external_charset, 1);
  rb_define_method(Rua, "error_handler", rua_get_error_handler, 0);
  rb_define_method(Rua, "error_handler=", rua_set_error_handler, 1);
  rb_define_method(Rua, "method_missing", rua_method_missing, -1);
  rb_define_method(Rua, "accept_block", rua_get_accept_block, 0);
  rb_define_method(Rua, "accept_block=", rua_set_accept_block, 1);

  m_method_unbound = rb_funcall(rb_cObject, rb_intern("instance_method"), 1, ID2SYM(rb_intern("method")));
  m_methods_unbound = rb_funcall(rb_cObject, rb_intern("instance_method"), 1, ID2SYM(rb_intern("methods")));
  rb_define_class_variable(Rua, "@@m_method_unbound", m_method_unbound);
  rb_define_class_variable(Rua, "@@m_methods_unbound", m_methods_unbound);

  m_constants_unbound = rb_funcall(rb_cModule, rb_intern("instance_method"), 1, ID2SYM(rb_intern("constants")));
  m_const_get_unbound = rb_funcall(rb_cModule, rb_intern("instance_method"), 1, ID2SYM(rb_intern("const_get")));
  rb_define_class_variable(Rua, "@@m_constants_unbound", m_constants_unbound);
  rb_define_class_variable(Rua, "@@m_const_get_unbound", m_const_get_unbound);

  rb_define_alloc_func(RuaFunc, rua_ref_alloc);
  rb_define_private_method(RuaFunc, "initialize", rua_func_initialize, 0);
  rb_define_method(RuaFunc, "call", rua_func_call, -1);
  rb_define_method(RuaFunc, "info", rua_func_info, 0);

  rb_define_alloc_func(RuaThread, rua_ref_alloc);
  rb_define_private_method(RuaThread, "initialize", rua_thread_initialize, 0);
  rb_define_method(RuaThread, "resume", rua_thread_resume, -1);

  rb_define_alloc_func(RuaError, rua_error_alloc);
  rb_define_method(RuaError, "cause", rua_error_cause, 0);
  rb_define_method(RuaError, "info", rua_error_info, 0);

  rb_define_alloc_func(RuaDebug, rua_debug_alloc);
  rb_define_private_method(RuaDebug, "initialize", rua_debug_initialize, 0);
  rb_define_method(RuaDebug, "name", rua_debug_name, 0);
  rb_define_method(RuaDebug, "namewhat", rua_debug_namewhat, 0);
  rb_define_method(RuaDebug, "what", rua_debug_what, 0);
  rb_define_method(RuaDebug, "source", rua_debug_source, 0);
  rb_define_method(RuaDebug, "currentline", rua_debug_currentline, 0);
  rb_define_method(RuaDebug, "nups", rua_debug_nups, 0);
  rb_define_method(RuaDebug, "linedefined", rua_debug_linedefined, 0);
  rb_define_method(RuaDebug, "lastlinedefined",rua_debug_lastlinedefined, 0);
  rb_define_method(RuaDebug, "short_src", rua_debug_short_src, 0);
  rb_define_method(RuaDebug, "to_hash", rua_debug_to_hash, 0);

  s_all     = ID2SYM(rb_intern("all"));
  s_base    = ID2SYM(rb_intern("base"));
  s_package = ID2SYM(rb_intern("package"));
  s_string  = ID2SYM(rb_intern("string"));
  s_table   = ID2SYM(rb_intern("table"));
  s_math    = ID2SYM(rb_intern("math"));
  s_io      = ID2SYM(rb_intern("io"));
  s_debug   = ID2SYM(rb_intern("debug"));
}

// ------------------------------------------------------------------

static VALUE rua_alloc(VALUE klass) {
  struct rua *p = ALLOC(struct rua);

  p->R = ALLOC(struct rua_state);
  p->R->rua = Qnil;
  p->R->refs = Qnil;
  p->R->error_handler = Qnil;
  p->R->external_charset = Qnil;
  p->R->secure = 1;
  p->R->abort_by_error = 1;
  p->R->wrap_error = 1;
  return Data_Wrap_Struct(klass, rua_mark, rua_free, p);
}

static void rua_mark(struct rua *p) {
  rb_gc_mark(p->R->rua);
  rb_gc_mark(p->R->refs);
  rb_gc_mark(p->R->error_handler);
  rb_gc_mark(p->R->external_charset);
}

static void rua_free(struct rua *p) {
  if (p->L) {
    lua_close(p->L);
  }

  if (p->R) {
    xfree(p->R);
  }

  xfree(p);
}

/**
 * new Rua instance.
 */
static VALUE rua_initialize(int argc, VALUE *argv, VALUE self) {
  struct rua *p;

  Data_Get_Struct(self, struct rua, p);
  p->L = lua_open();
  p->R->rua = self;
  p->R->refs = rb_hash_new();
  p->R->error_handler = Qnil;
  p->R->external_charset = Qnil;
  p->R->secure = 1;
  p->R->abort_by_error = 1;
  p->R->wrap_error = 1;
  p->R->accept_block = 1;

  if (argc > 0) {
    rua_openlibs(argc, argv, self);
  }

  return Qnil;
}

/**
 * open libraries.
 * see http://www.lua.org/manual/5.1/manual.html#5.
 */
static VALUE rua_openlibs(int argc, VALUE *argv, VALUE self) {
  struct rua *p;
  VALUE arg;
  int i;

  if (argc < 1) {
    rb_raise(rb_eArgError, "wrong number of arguments (0 for 1)");
  }

  for (i = 0; i < argc; i++) {
    Check_Type(argv[i], T_SYMBOL);
  }

  Data_Get_Struct(self, struct rua, p);

  for (i = 0; i < argc; i++) {
    arg = argv[i];

    if (s_all == arg) {
      luaL_openlibs(p->L);
    } else if (s_base == arg) {
      lua_pushcfunction(p->L, luaopen_base);
      lua_call(p->L, 0, 0);
    } else if (s_package == arg) {
      lua_pushcfunction(p->L, luaopen_package);
      lua_call(p->L, 0, 0);
    } else if (s_string == arg) {
      lua_pushcfunction(p->L, luaopen_string);
      lua_call(p->L, 0, 0);
    } else if (s_table == arg) {
      lua_pushcfunction(p->L, luaopen_table);
      lua_call(p->L, 0, 0);
    } else if (s_math == arg) {
      lua_pushcfunction(p->L, luaopen_math);
      lua_call(p->L, 0, 0);
    } else if (s_io == arg) {
      lua_pushcfunction(p->L, luaopen_io);
      lua_call(p->L, 0, 0);
    } else if (s_debug == arg) {
      lua_pushcfunction(p->L, luaopen_debug);
      lua_call(p->L, 0, 0);
    } else {
      rb_raise(rb_eArgError, "unknown library '%s' (available: base, package, table, math, io, debug, all)", rua_to_sptr(arg));
    }
  }

  return Qnil;
}

/**
 * evaluates string.
 */
static VALUE rua_eval(int argc, VALUE *argv, VALUE self) {
  struct rua *p;
  VALUE str, script_name, errinfo;
  const char *errmsg = NULL;
  int pretop, loaded = -1, result = -1;

  rb_scan_args(argc, argv, "11", &str, &script_name);

  Check_Type(str, T_STRING);

  if (!NIL_P(script_name)) {
    Check_Type(script_name, T_STRING);
  }

  Data_Get_Struct(self, struct rua, p);

  if (!NIL_P(p->R->external_charset)) {
    str = rua_iconv(ICONV_UTF8, RSTRING_PTR(p->R->external_charset), str);
  }

  pretop = lua_gettop(p->L);

  if (NIL_P(script_name)) {
    loaded = luaL_loadstring(p->L, RSTRING_PTR(str));
  } else {
    loaded = luaL_loadbuffer(p->L, RSTRING_PTR(str), RSTRING_LEN(str), RSTRING_PTR(script_name));
  }

  if (loaded != 0) {
    int curtop = lua_gettop(p->L);

    if (!lua_isnil(p->L, -1)) {
      errmsg = lua_tostring(p->L, -1);
    }

    if (errmsg == NULL) {
      errmsg = "(error object is not a string)";
    }

    if (curtop - pretop > 0) {
      lua_pop(p->L, curtop - pretop);
    }

    rb_raise(RuaError, "%s", errmsg);
  }

  TRAP_BEG;
  result = lua_pcall(p->L, 0, LUA_MULTRET, 0);
  TRAP_END;

  if (result != 0) {
    if (lua_islightuserdata(p->L, -1)) {
      errinfo = (VALUE) lua_touserdata(p->L, -1);
      lua_pop(p->L, 1);
      rb_exc_raise(errinfo);
    } else if (lua_isstring(p->L, -1)){
      errmsg = lua_tostring(p->L, -1);
      lua_pop(p->L, 1);
      rb_raise(RuaError, "%s", errmsg);
    } else {
      lua_pop(p->L, 1);
      rb_raise(RuaError, "must not happen");
    }
  }

  return rua_tomultiretval(p->L, pretop, p->R);
}

/**
 * set global variable.
 */
static VALUE rua_get(VALUE self, VALUE key) {
  struct rua *p;
  VALUE retval;

  Data_Get_Struct(self, struct rua, p);
  lua_getglobal(p->L, rua_to_sptr(key));
  retval = rua_torbval(p->L, -1, p->R);
  lua_pop(p->L, 1);
  return retval;
}

/**
 * set global variable.
 */
static VALUE rua_set(VALUE self, VALUE key, VALUE val) {
  struct rua *p;

  Data_Get_Struct(self, struct rua, p);

  if (p->R->secure && (rb_equal(rb_cModule, val) || rb_equal(rb_cClass, val))) {
    rb_raise(RuaError, "set insecure value %s", rua_to_sptr(val));
  }

  rua_pushrbval(p->L, val, p->R);
  lua_setglobal(p->L, rua_to_sptr(key));
  return Qnil;
}

/**
 * get secure flag.
 */
static VALUE rua_get_secure(VALUE self) {
  struct rua *p;

  Data_Get_Struct(self, struct rua, p);
  return p->R->secure ? Qtrue : Qfalse;
}

/**
 * set secure flag.
 */
static VALUE rua_set_secure(VALUE self, VALUE secure) {
  struct rua *p;

  Data_Get_Struct(self, struct rua, p);

  switch (TYPE(secure)) {
  case T_TRUE:  p->R->secure = 1; break;
  case T_FALSE: p->R->secure = 0; break;
  default:
    rb_raise(rb_eTypeError, "wrong argument type %s (expected TrueClass or FalseClass)", rua_classname_ptr(secure));
    break;
  }

  return Qnil;
}

/**
 * get abort flag.
 */
static VALUE rua_get_abort_by_error(VALUE self) {
  struct rua *p;

  Data_Get_Struct(self, struct rua, p);
  return p->R->abort_by_error ? Qtrue : Qfalse;
}

/**
 * set abort flag.
 */
static VALUE rua_set_abort_by_error(VALUE self, VALUE abort_by_error) {
  struct rua *p;

  Data_Get_Struct(self, struct rua, p);

  switch (TYPE(abort_by_error)) {
  case T_TRUE:  p->R->abort_by_error = 1; break;
  case T_FALSE: p->R->abort_by_error = 0; break;
  default:
    rb_raise(rb_eTypeError, "wrong argument type %s (expected TrueClass or FalseClass)", rua_classname_ptr(abort_by_error));
    break;
  }

  return Qnil;
}

/**
 * get wrap error flag.
 */
static VALUE rua_get_wrap_error(VALUE self) {
  struct rua *p;

  Data_Get_Struct(self, struct rua, p);
  return p->R->wrap_error ? Qtrue : Qfalse;
}

/**
 * set wrap error flag.
 */
static VALUE rua_set_wrap_error(VALUE self, VALUE wrap_error) {
  struct rua *p;

  Data_Get_Struct(self, struct rua, p);

  switch (TYPE(wrap_error)) {
  case T_TRUE:  p->R->wrap_error = 1; break;
  case T_FALSE: p->R->wrap_error = 0; break;
  default:
    rb_raise(rb_eTypeError, "wrong argument type %s (expected TrueClass or FalseClass)", rua_classname_ptr(wrap_error));
    break;
  }

  return Qnil;
}

/**
 * get external character set.
 */
static VALUE rua_get_external_charset(VALUE self) {
  struct rua *p;

  Data_Get_Struct(self, struct rua, p);
  return p->R->external_charset;
}

/**
 * set external character set.
 */
static VALUE rua_set_external_charset(VALUE self, VALUE external_charset) {
  struct rua *p;

  Data_Get_Struct(self, struct rua, p);

  if (NIL_P(external_charset)) {
    p->R->external_charset = Qnil;
  } else {
    Check_Type(external_charset, T_STRING);
    p->R->external_charset = external_charset;
  }

  return Qnil;
}

/**
 * get error handler.
 */
static VALUE rua_get_error_handler(VALUE self) {
  struct rua *p;

  Data_Get_Struct(self, struct rua, p);
  return p->R->error_handler;
}

/**
 * set error handler.
 */
static VALUE rua_set_error_handler(VALUE self, VALUE error_handler) {
  struct rua *p;

  if (!NIL_P(error_handler) && !rua_obj_is_executable(error_handler)) {
    rb_raise(rb_eTypeError, "wrong argument type %s (expected Proc or Method)", rua_classname_ptr(error_handler));
  }

  Data_Get_Struct(self, struct rua, p);
  p->R->error_handler = error_handler;
  return Qnil;
}

/**
 * dispatch Rua#[], Rua#[]=.
 */
static VALUE rua_method_missing(int argc, VALUE *argv, VALUE self) {
  const char *name;
  size_t len;

  name = rb_id2name(rb_to_id(argv[0]));

  if (!name) {
    rb_raise(rb_eRuntimeError, "fail: unknown method or property");
  }

  len = strlen(name);

  if (argc == 2 && name[len - 1] == '=') {
    argv[0] = rb_str_new(name, (long) len - 1);
    return rua_set(self, argv[0], argv[1]);
  } else if(argc == 1) {
    return rua_get(self, argv[0]);
  } else {
    return rb_call_super(argc, argv);
  }
}

/**
 * get accept block flag.
 */
static VALUE rua_get_accept_block(VALUE self) {
  struct rua *p;

  Data_Get_Struct(self, struct rua, p);
  return p->R->accept_block ? Qtrue : Qfalse;
}

/**
 * set accept block flag.
 */
static VALUE rua_set_accept_block(VALUE self, VALUE accept_block) {
  struct rua *p;

  Data_Get_Struct(self, struct rua, p);

  switch (TYPE(accept_block)) {
  case T_TRUE:  p->R->accept_block = 1; break;
  case T_FALSE: p->R->accept_block = 0; break;
  default:
    rb_raise(rb_eTypeError, "wrong argument type %s (expected TrueClass or FalseClass)", rua_classname_ptr(accept_block));
    break;
  }

  return Qnil;
}

// ------------------------------------------------------------------

static VALUE rua_ref_alloc(VALUE klass) {
  struct rua_ref *p = ALLOC(struct rua_ref);
  p->is_ruby = 0;
  return Data_Wrap_Struct(klass, rua_ref_mark, rua_ref_free, p);
}

static void rua_ref_mark(struct rua_ref *p) {
  rb_gc_mark(p->R->rua);
  rb_gc_mark(p->R->refs);
  rb_gc_mark(p->R->error_handler);
  rb_gc_mark(p->R->external_charset);
}

static void rua_ref_free(struct rua_ref *p) {
  //luaL_unref(p->L, LUA_REGISTRYINDEX, p->ref);

  if (p->R) {
    xfree(p->R);
  }

  xfree(p);
}

static void rua_ref_set_ruby_flag(VALUE self, int is_ruby) {
  struct rua_ref *p;
  Data_Get_Struct(self, struct rua_ref, p);
  p->is_ruby = is_ruby;
}

static int rua_ref_get_ruby_flag(VALUE self) {
  struct rua_ref *p;
  Data_Get_Struct(self, struct rua_ref, p);
  return p->is_ruby;
}

// ------------------------------------------------------------------

/**
 * new RuaFunc instance.
 */
static VALUE rua_func_initialize(VALUE self) {
  return Qnil;
}

/**
 * call Lua function.
 */
static VALUE rua_func_call(int argc, VALUE *argv, VALUE self) {
  struct rua_ref *p;
  int pretop, i, result = -1;
  VALUE errinfo;
  const char *errmsg;

  Data_Get_Struct(self, struct rua_ref, p);
  pretop = lua_gettop(p->L);
  lua_rawgeti(p->L, LUA_REGISTRYINDEX, p->ref);

  for (i = 0; i < argc; i ++) {
    rua_pushrbval(p->L, argv[i], p->R);
  }

  TRAP_BEG;
  result = lua_pcall(p->L, argc, LUA_MULTRET, 0);
  TRAP_END;

  if (result != 0) {
    if (lua_islightuserdata(p->L, -1)) {
      errinfo = (VALUE) lua_touserdata(p->L, -1);
      lua_pop(p->L, 1);
      rb_exc_raise(errinfo);
    } else if (lua_isstring(p->L, -1)){
      errmsg = lua_tostring(p->L, -1);
      lua_pop(p->L, 1);
      rb_raise(RuaError, "%s", errmsg);
    } else {
      lua_pop(p->L, 1);
      rb_raise(RuaError, "must not happen");
    }
  }

  return rua_tomultiretval(p->L, pretop, p->R);
}

/**
 * get debug info.
 */
static VALUE rua_func_info(VALUE self) {
  struct rua_ref *p;
  VALUE ruadebug;
  lua_Debug ar;

  Data_Get_Struct(self, struct rua_ref, p);
  lua_rawgeti(p->L, LUA_REGISTRYINDEX, p->ref);

  if (lua_isfunction(p->L, -1) && lua_getinfo(p->L, ">nSlu", &ar)) {
    ruadebug = rua_toruadebug(&ar);
  } else {
    ruadebug = Qnil;
  }

  return ruadebug;
}

// ------------------------------------------------------------------

/**
 * new RuaThread instance.
 */
static VALUE rua_thread_initialize(VALUE self) {
  return Qnil;
}

/**
 * resume Lua coroutine.
 */
static VALUE rua_thread_resume(int argc, VALUE *argv, VALUE self) {
  struct rua_ref *p;
  VALUE retval, errinfo;
  int pretop, i, result = -1;
  const char *errmsg;

  Data_Get_Struct(self, struct rua_ref, p);
  lua_getglobal(p->L, "coroutine");
  pretop = lua_gettop(p->L);
  lua_pushstring(p->L, "resume");
  lua_rawget(p->L, pretop);
  lua_rawgeti(p->L, LUA_REGISTRYINDEX, p->ref);

  for (i = 0; i < argc; i ++) {
    rua_pushrbval(p->L, argv[i], p->R);
  }

  TRAP_BEG;
  result = lua_pcall(p->L, argc + 1, LUA_MULTRET, 0);
  TRAP_END;

  if (result != 0) {
    if (lua_islightuserdata(p->L, -1)) {
      errinfo = (VALUE) lua_touserdata(p->L, -1);
      lua_pop(p->L, 2);
      rb_exc_raise(errinfo);
    } else if (lua_isstring(p->L, -1)){
      errmsg = lua_tostring(p->L, -1);
      lua_pop(p->L, 2);
      rb_raise(RuaError, "%s", errmsg);
    } else {
      lua_pop(p->L, 2);
      rb_raise(RuaError, "must not happen");
    }
  }

  retval = rua_tomultiretval(p->L, pretop, p->R);
  lua_pop(p->L, 1);
  return retval;
}

// ------------------------------------------------------------------

static VALUE rua_debug_alloc(VALUE klass) {
  struct rua_debug *p = ALLOC(struct rua_debug);

  return Data_Wrap_Struct(klass, rua_debug_mark, -1, p);
}

static void rua_debug_mark(struct rua_debug *p) {
  rb_gc_mark(p->name);
  rb_gc_mark(p->namewhat);
  rb_gc_mark(p->what);
  rb_gc_mark(p->source);
  rb_gc_mark(p->currentline);
  rb_gc_mark(p->nups);
  rb_gc_mark(p->linedefined);
  rb_gc_mark(p->lastlinedefined);
  rb_gc_mark(p->short_src);
}

/**
 * new RuaDebug instance.
 * see http://www.lua.org/manual/5.1/manual.html#lua_Debug.
 */
static VALUE rua_debug_initialize(VALUE self) {
  return Qnil;
}

/**
 * get name.
 */
static VALUE rua_debug_name(VALUE self) {
  struct rua_debug *p;

  Data_Get_Struct(self, struct rua_debug, p);
  return p->name;
}

/**
 * get namewhat.
 */
static VALUE rua_debug_namewhat(VALUE self) {
  struct rua_debug *p;

  Data_Get_Struct(self, struct rua_debug, p);
  return p->namewhat;
}

/**
 * get what.
 */
static VALUE rua_debug_what(VALUE self) {
  struct rua_debug *p;

  Data_Get_Struct(self, struct rua_debug, p);
  return p->what;
}

/**
 * get source.
 */
static VALUE rua_debug_source(VALUE self) {
  struct rua_debug *p;

  Data_Get_Struct(self, struct rua_debug, p);
  return p->source;
}

/**
 * get currentline.
 */
static VALUE rua_debug_currentline(VALUE self) {
  struct rua_debug *p;

  Data_Get_Struct(self, struct rua_debug, p);
  return p->currentline;
}

/**
 * get nups.
 */
static VALUE rua_debug_nups(VALUE self) {
  struct rua_debug *p;

  Data_Get_Struct(self, struct rua_debug, p);
  return p->nups;
}

/**
 * get linedefined.
 */
static VALUE rua_debug_linedefined(VALUE self) {
  struct rua_debug *p;

  Data_Get_Struct(self, struct rua_debug, p);
  return p->linedefined;
}

/**
 * get lastlinedefined.
 */
static VALUE rua_debug_lastlinedefined(VALUE self) {
  struct rua_debug *p;

  Data_Get_Struct(self, struct rua_debug, p);
  return p->lastlinedefined;
}

/**
 * get short_src.
 */
static VALUE rua_debug_short_src(VALUE self) {
  struct rua_debug *p;

  Data_Get_Struct(self, struct rua_debug, p);
  return p->short_src;
}

/**
 * convert to hash.
 */
static VALUE rua_debug_to_hash(VALUE self) {
  struct rua_debug *p;
  VALUE hash;

  Data_Get_Struct(self, struct rua_debug, p);
  hash = rb_hash_new();
  rb_hash_aset(hash, ID2SYM(rb_intern("name"))           , p->name);
  rb_hash_aset(hash, ID2SYM(rb_intern("namewhat"))       , p->namewhat);
  rb_hash_aset(hash, ID2SYM(rb_intern("what"))           , p->what);
  rb_hash_aset(hash, ID2SYM(rb_intern("source"))         , p->source);
  rb_hash_aset(hash, ID2SYM(rb_intern("currentline"))    , p->currentline);
  rb_hash_aset(hash, ID2SYM(rb_intern("nups"))           , p->nups);
  rb_hash_aset(hash, ID2SYM(rb_intern("linedefined"))    , p->linedefined);
  rb_hash_aset(hash, ID2SYM(rb_intern("lastlinedefined")), p->lastlinedefined);
  rb_hash_aset(hash, ID2SYM(rb_intern("short_src"))      , p->short_src);
  return hash;
}

// ------------------------------------------------------------------

static VALUE rua_error_alloc(VALUE klass) {
  struct rua_error *p = ALLOC(struct rua_error);

  p->cause = Qnil;
  p->info = Qnil;
  return Data_Wrap_Struct(klass, rua_error_mark, -1, p);
}

static void rua_error_mark(struct rua_error *p) {
  rb_gc_mark(p->cause);
  rb_gc_mark(p->info);
}

/**
 * get cause error.
 */
static VALUE rua_error_cause(VALUE self) {
  struct rua_error *p;

  Data_Get_Struct(self, struct rua_error, p);
  return p->cause;
}

/**
 * get debug info.
 */
static VALUE rua_error_info(VALUE self) {
  struct rua_error *p;

  Data_Get_Struct(self, struct rua_error, p);
  return p->info;
}

// ------------------------------------------------------------------

static VALUE rua_tomultiretval(lua_State *L, int pretop, struct rua_state *R) {
  VALUE retval;
  int nresults, i;

  nresults = lua_gettop(L) - pretop;

  if (nresults == 0) {
    return Qnil;
  } else if (nresults == 1) {
    retval = rua_torbval(L, -1, R);
    lua_pop(L, 1);
    return retval;
  } else {
    retval = rb_ary_new();

    for (i = nresults; i > 0; i--) {
      rb_ary_push(retval, rua_torbval(L, -i, R));
    }

    lua_pop(L, nresults);
    return retval;
  }
}

static VALUE rua_torbval(lua_State *L, int idx, struct rua_state *R) {
  VALUE rbval = Qnil;

  switch (lua_type(L, idx)) {
  case LUA_TNUMBER:
    rbval = rua_torbnum(L, idx);
    break;

  case LUA_TBOOLEAN:
    rbval = lua_toboolean(L, idx) ? Qtrue : Qfalse;
    break;

  case LUA_TSTRING:
    rbval = rb_str_new2(lua_tostring(L, idx));

    if (!NIL_P(R->external_charset)) {
      rbval = rua_iconv(RSTRING_PTR(R->external_charset), ICONV_UTF8, rbval);
    }

    break;

  case LUA_TTABLE:
    if (rua_is_rbobj(L, idx)) {
      rbval = rua_torbobj(L, idx);
    } else {
      rbval = rua_tohash(L, idx, R);
    }

    break;

  case LUA_TFUNCTION:
    {
      int type_is_cfunction = lua_iscfunction(L, idx);
      rbval = rua_toruaobj(RuaFunc, L, idx, R);
      rua_ref_set_ruby_flag(rbval, type_is_cfunction);
    }
    break;

  case LUA_TTHREAD:
    rbval = rua_toruaobj(RuaThread, L, idx, R);
    break;

  case LUA_TLIGHTUSERDATA:
    rbval = (VALUE) lua_touserdata(L, idx);
    break;
  }

  return rbval;
}

static int rua_is_rbobj(lua_State *L, int idx) {
  int tblidx, is_rbobj;

  lua_pushvalue(L, idx);
  tblidx = lua_gettop(L);
  lua_pushstring(L, REF_RBOBJ);
  lua_gettable(L, tblidx);
  is_rbobj = lua_islightuserdata(L, -1);
  lua_pop(L, 2);
  return is_rbobj;
}

static VALUE rua_torbobj(lua_State *L, int idx) {
  VALUE rbobj;
  int tblidx;

  lua_pushvalue(L, idx);
  tblidx = lua_gettop(L);
  lua_pushstring(L, REF_RBOBJ);
  lua_gettable(L, tblidx);
  rbobj = (VALUE) lua_touserdata(L, -1);
  lua_pop(L, 2);
  return rbobj;
}

static VALUE rua_tohash(lua_State *L, int idx, struct rua_state *R) {
  VALUE hash, key, val;
  int tblidx;

  lua_pushvalue(L, idx);
  tblidx = lua_gettop(L);
  hash = rb_hash_new();
  lua_pushnil(L);

  while (lua_next(L, tblidx) != 0) {
    key = rua_torbval(L, -2, R);
    val = rua_torbval(L, -1, R);
    rb_hash_aset(hash, key, val);
    lua_pop(L, 1);
  }

  lua_pop(L, 1);
  return hash;
}

static void rua_pushrbval(lua_State *L, VALUE rbval, struct rua_state *R) {
  struct rua_ref *p;

  switch (TYPE(rbval)) {
  case T_NIL:
    lua_pushnil(L);
    break;

  case T_FLOAT:
  case T_FIXNUM:
  case T_BIGNUM:
    lua_pushnumber(L, rb_num2dbl(rbval));
    break;

  case T_STRING:
    if (!NIL_P(R->external_charset)) {
      rbval = rua_iconv(ICONV_UTF8, RSTRING_PTR(R->external_charset), rbval);
    }

    lua_pushstring(L, RSTRING_PTR(rbval));
    break;

  case T_TRUE:
    lua_pushboolean(L, 1);
    break;

  case T_FALSE:
    lua_pushboolean(L, 0);
    break;

  case T_ARRAY:
    rua_newtable_from_ary(L, rbval, R);
    break;

  case T_HASH:
    rua_newtable_from_hash(L, rbval, R);
    break;

  default:
    if (R->secure && (rb_equal(rb_cModule, rbval) || rb_equal(rb_cClass, rbval))) {
      rb_warn("warning: convert insecure value %s", rua_to_sptr(rbval));
      lua_pushnil(L);
    } else if (rb_obj_is_kind_of(rbval, RuaFunc)) {
      Data_Get_Struct(rbval, struct rua_ref, p);
      lua_rawgeti(L, LUA_REGISTRYINDEX, p->ref);
    } else if (rb_obj_is_kind_of(rbval, RuaThread)) {
      Data_Get_Struct(rbval, struct rua_ref, p);
      lua_rawgeti(L, LUA_REGISTRYINDEX, p->ref);
    } else if (rua_obj_is_executable(rbval)) {
      lua_pushlightuserdata(L, (void *) rbval);
      lua_pushlightuserdata(L, R);
      lua_pushcclosure(L, rua_proc_call, 2);
      rua_setmeta2(L, -1, "__gc", rua_finalize_rbobj, 2, rbval, R);
    } else {
      rua_newtable_from_obj(L, rbval, R);
    }

    break;
  }
}

static void rua_newtable_from_ary(lua_State *L, VALUE ary, struct rua_state *R) {
  VALUE entry;
  int i, tblidx;

  lua_newtable(L);
  tblidx = lua_gettop(L);

  for (i = 0; i < RARRAY_LEN(ary); i++) {
    entry = rb_ary_entry(ary, i);
    lua_pushnumber(L, i + 1);
    rua_pushrbval(L, entry, R);
    lua_rawset(L, tblidx);
  }
}

static void rua_newtable_from_hash(lua_State *L, VALUE hash, struct rua_state *R) {
  VALUE keys, key, val;
  int i, tblidx;

  lua_newtable(L);
  tblidx = lua_gettop(L);
  keys = rb_check_convert_type(hash, T_ARRAY, "Array", "keys");

  for (i = 0; i < RARRAY_LEN(keys); i++) {
    key = rb_ary_entry(keys, i);
    val = rb_hash_aref(hash, key);
    rua_pushrbval(L, key, R);
    rua_pushrbval(L, val, R);
    lua_rawset(L, tblidx);
  }
}

static void rua_newtable_from_obj(lua_State *L, VALUE obj, struct rua_state *R) {
  VALUE methods, name, method;
  VALUE m_method_bound, m_methods_bound;
  int i, tblidx, prxidx;

  lua_newtable(L);
  prxidx = lua_gettop(L);
  lua_newtable(L);
  tblidx = lua_gettop(L);

  m_method_bound = rb_funcall(m_method_unbound, rb_intern("bind"), 1, obj);
  m_methods_bound = rb_funcall(m_methods_unbound, rb_intern("bind"), 1, obj);
  methods = rb_check_convert_type(m_methods_bound, T_ARRAY, "Array", "call");

  lua_pushstring(L, REF_RBOBJ);
  lua_pushlightuserdata(L, (void *) obj);
  rua_setmeta2(L, -1, "__gc", rua_finalize_rbobj, 2, obj, R);
  lua_rawset(L, tblidx);
  rb_hash_aset(R->refs, obj, Qtrue);

  for (i = 0; i < RARRAY_LEN(methods); i++) {
    name = rb_ary_entry(methods, i);
    method = rb_funcall(m_method_bound, rb_intern("call"), 1, name);
    rb_hash_aset(R->refs, method, Qtrue);

    if (R->secure && rua_name_is_insecure_method(StringValuePtr(name))) {
      continue;
    }

    rua_pushrbval(L, name, R);
    rua_pushrbval(L, method, R);
    lua_rawset(L, tblidx);
  }

  if (rb_obj_is_kind_of(obj, rb_cModule)) {
    VALUE cnsts, cname, cnst;
    VALUE m_const_get_bound, m_constants_bound;
    m_const_get_bound = rb_funcall(m_const_get_unbound, rb_intern("bind"), 1, obj);
    m_constants_bound = rb_funcall(m_constants_unbound, rb_intern("bind"), 1, obj);
    cnsts = rb_check_convert_type(m_constants_bound, T_ARRAY, "Array", "call");

    for (i = 0; i < RARRAY_LEN(cnsts); i++) {
      cname = rb_ary_entry(cnsts, i);
      cnst = rb_funcall(m_const_get_bound, rb_intern("call"), 1, cname);
      rb_hash_aset(R->refs, cnst, Qtrue);
      rua_pushrbval(L, cname, R);
      rua_pushrbval(L, cnst, R);
      lua_rawset(L, tblidx);
    }
  }

  lua_pushvalue(L, -1);
  rua_setmeta(L, prxidx, "__index", rua_getobject_event, 1);
  rua_setmeta(L, prxidx, "__newindex", rua_setobject_event, 1);
}

static int rua_getobject_event(lua_State *L) {
  int tblidx;

  tblidx = lua_upvalueindex(1);
  lua_pushvalue(L, -1);
  lua_rawget(L, tblidx);

  if (lua_isnil(L, -1)) {
    lua_pop(L, 1);
    lua_pushstring(L, "[]");
    lua_rawget(L, tblidx);

    if (lua_isfunction(L, -1)) {
      lua_pushvalue(L, -2);
      lua_call(L, 1, 1);
    } else {
      lua_pop(L, 1);
      lua_pushnil(L);
    }
  }

  return 1;
}

static int rua_setobject_event(lua_State *L) {
  const char *key;
  size_t keylen;
  char *setter;
  int tblidx;

  tblidx = lua_upvalueindex(1);

  key = lua_tostring(L, -2);
  keylen = strlen(key);
  setter = alloca(keylen + 2);
  memcpy(setter, key, keylen);
  setter[keylen] = '=';
  setter[keylen + 1] = '\0';

  lua_pushstring(L, setter);
  lua_rawget(L, tblidx);

  if (lua_isfunction(L, -1)) {
    lua_pushvalue(L, -2);
    lua_call(L, 1, 0);
  } else {
    lua_pop(L, 1);
    lua_pushstring(L, "[]=");
    lua_rawget(L, tblidx);

    if (lua_isfunction(L, -1)) {
      lua_pushvalue(L, -3);
      lua_pushvalue(L, -3);
      lua_call(L, 2, 0);
    } else {
      lua_pop(L, 1);
      lua_rawset(L, tblidx);
    }
  }

  return 0;
}

static int rua_proc_call(lua_State *L) {
  struct rua_state *R;
  VALUE proc, args, last, retval, errargs, error;
  int i, n, status;
  lua_Debug ar;

  proc = (VALUE) lua_touserdata(L, lua_upvalueindex(1));
  R = (struct rua_state *) lua_touserdata(L, lua_upvalueindex(2));
  args = rb_ary_new();
  n = lua_gettop(L);

  for (i = 0; i < n; i++) {
    rb_ary_push(args, rua_torbval(L, i + 1, R));
  }

  last = rb_ary_entry(args, -1);
  rb_ary_push(args, proc);

  if (R->accept_block && rb_obj_is_kind_of(last, RuaFunc) && !rua_ref_get_ruby_flag(last)) {
    retval = rb_protect(_rua_proc_call_with_block, args, &status);
  } else {
    retval = rb_protect(_rua_proc_call, args, &status);
  }

  if (status != 0) {
    if (R->wrap_error) {
      if (lua_getstack(L, 1, &ar) && lua_getinfo(L, "nSlu", &ar)) {
        error = rua_toruaerror(rb_errinfo(), rua_toruadebug(&ar));
      } else {
        error = rua_toruaerror(rb_errinfo(), Qnil);
      }
    } else {
      error = rb_errinfo();
    }

    if (rua_obj_is_executable(R->error_handler)) {
      errargs = rb_ary_new();
      rb_ary_push(errargs, error);
      rb_ary_push(errargs, R->error_handler);
      retval = rb_protect(_rua_proc_call, errargs, &status);

      if (status != 0) {
        rb_warn("%s\n", rua_to_sptr(rb_errinfo()));
      }
    } else {
      retval = Qnil;
    }

    if (R->abort_by_error) {
      lua_pushlightuserdata(L, (void *) error);
      return lua_error(L);
    }
  }

  rua_pushrbval(L, retval, R);
  return 1;
}

static VALUE _rua_proc_call(VALUE args) {
  VALUE proc;

  proc = rb_ary_pop(args);
  return rb_funcall2(proc, rb_intern("call"), RARRAY_LEN(args), RARRAY_PTR(args));
}


static VALUE _rua_proc_call_with_block(VALUE args) {
  VALUE proc, block;

  proc = rb_ary_pop(args);
  block = rb_ary_pop(args);
  rb_ary_push(args, proc);
  return rb_iterate(_rua_proc_call, args, _rua_proc_call_as_block, block);
}

static VALUE _rua_proc_call_as_block(VALUE block_arg, VALUE block, VALUE self) {
  if (TYPE(block_arg) == T_ARRAY) {
    return rb_apply(block, rb_intern("call"), block_arg);
  } else {
    return rb_funcall(block, rb_intern("call"), 1, block_arg);
  }
}

static VALUE rua_toruaobj(VALUE klass, lua_State *L, int idx, struct rua_state *R) {
  struct rua_ref *p;
  VALUE ruaobj;

  ruaobj = rb_funcall(klass, rb_intern("new"), 0);
  Data_Get_Struct(ruaobj, struct rua_ref , p);
  p->L = L;
  p->R = R;
  lua_pushvalue(L, idx);
  p->ref = luaL_ref(L, LUA_REGISTRYINDEX);
  rb_hash_aset(p->R->refs, ruaobj, Qtrue);
  return ruaobj;
}

static VALUE rua_toruaerror(VALUE cause, VALUE ruadebug) {
  struct rua_error *p;
  VALUE errmsg, ruaerr;

  errmsg = rb_check_convert_type(cause, T_STRING, "String", "to_s");
  ruaerr = rb_funcall(RuaError, rb_intern("new"), 1, errmsg);
  Data_Get_Struct(ruaerr, struct rua_error, p);
  p->cause = cause;
  p->info = ruadebug;
  return ruaerr;
}

static VALUE rua_toruadebug(lua_Debug *ar) {
  struct rua_debug *p;
  VALUE ruadebug;

  ruadebug = rb_funcall(RuaDebug, rb_intern("new"), 0);
  Data_Get_Struct(ruadebug, struct rua_debug, p);
  p->name            = ar->name ? rb_str_new2(ar->name) : Qnil;
  p->namewhat        = ar->namewhat ? rb_str_new2(ar->namewhat) : Qnil;
  p->what            = ar->what ? rb_str_new2(ar->what) : Qnil;
  p->source          = ar->source ? rb_str_new2(ar->source) : Qnil;
  p->currentline     = INT2NUM(ar->currentline);
  p->nups            = INT2NUM(ar->nups);
  p->linedefined     = INT2NUM(ar->linedefined);
  p->lastlinedefined = INT2NUM(ar->lastlinedefined);
  p->short_src       = ar->short_src ? rb_str_new2(ar->short_src) : Qnil;
  return ruadebug;
}

static VALUE rua_obj_is_executable(VALUE obj) {
  return (rb_obj_is_kind_of(obj, rb_cProc) || rb_obj_is_kind_of(obj, rb_cMethod));
}

static int rua_name_is_insecure_method(const char *name) {
  int i;

  for (i = 0; i < insecure_method_num; i++) {
    if (strcmp(insecure_methods[i], name) == 0) {
      return 1;
    }
  }

  return 0;
}

static VALUE rua_to_s(VALUE v) {
  return rb_check_convert_type(v, T_STRING, "String", "to_s");
}

static const char *rua_to_sptr(VALUE v) {
  VALUE str = rua_to_s(v);

  return RSTRING_PTR(str);
}

static VALUE rua_classname(VALUE v) {
  VALUE klass = rb_obj_class(v);

  return rb_class_name(klass);
}

static const char *rua_classname_ptr(VALUE v) {
  VALUE klassname = rua_classname(v);

  return RSTRING_PTR(klassname);
}

static void rua_setmeta(lua_State *L, int idx, const char *key, lua_CFunction f, int n) {
  int basetop, objidx, tblidx, i;

  basetop = lua_gettop(L) - n;
  lua_pushvalue(L, idx);
  objidx = lua_gettop(L);

  if (!lua_getmetatable(L, objidx)) {
    lua_newtable(L);
    lua_setmetatable(L, objidx);
    lua_getmetatable(L, objidx);
  }

  tblidx = lua_gettop(L);
  lua_pushstring(L, key);

  for (i = 1; i <= n; i++) {
    lua_pushvalue(L, basetop + i);
  }

  if (n > 0) {
    lua_pushcclosure(L, f, n);
  } else {
    lua_pushcfunction(L, f);
  }

  lua_rawset(L, tblidx);
  lua_pop(L, lua_gettop(L) - basetop);
}

static void rua_setmeta2(lua_State *L, int idx, const char *key, lua_CFunction f, int n, ...) {
  va_list argp;
  int i;

  va_start(argp, n);

  for (i = 0; i < n; i++) {
    lua_pushlightuserdata(L, va_arg(argp, void*));
  }

  if (idx < 0) {
    idx -= n;
  }

  rua_setmeta(L, idx, key, f, n);
}

static int rua_finalize_rbobj(lua_State *L) {
  struct rua_state *R;
  VALUE rbobj;

  if (lua_gettop(L) > 0) {
    rbobj = (VALUE) lua_touserdata(L, lua_upvalueindex(1));  
    R = (struct rua_state *) lua_touserdata(L, lua_upvalueindex(2));

    if (rbobj) {
      rb_hash_delete(R->refs, rbobj);
    }
  }

  return 0;
}

static VALUE rua_iconv(const char *to, const char *from, VALUE in) {
  VALUE out;
  iconv_t cd;
  char *cin, *cout, *pcout;
  size_t cin_len, cout_len;

  cd = iconv_open(to, from);

  if ((int) cd == -1) {
    rb_warn("%s (%s, %s)", to, from, strerror(errno));
    return Qnil;
  }

  cin = RSTRING_PTR(in);
  cin_len = strlen(cin);
  cout_len = cin_len * 3 + 1;
  cout = pcout = alloca(sizeof(char) * cout_len);

  if (iconv(cd, &cin, &cin_len, &pcout, &cout_len) == -1) {
    rb_warn("%s (%s, %s)", to, from, strerror(errno));
    iconv_close(cd);
    return Qnil;
  }

  *pcout = '\0';
  out = rb_str_new2(cout);

  if (iconv_close(cd) != 0) {
    rb_warn("%s (%s, %s)", to, from, strerror(errno));
  }

  return out;
}

static VALUE rua_torbnum(lua_State *L, int idx) {
  double luanum = lua_tonumber(L, idx);
  double truncated = floor(luanum);

  if (luanum == truncated) {
    return INT2NUM(lua_tointeger(L, idx));
  } else {
    return rb_float_new(luanum);
  }
}
