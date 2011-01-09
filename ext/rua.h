#ifndef __RUA_H__
#define __RUA_H__

struct rua_state {
  VALUE rua;
  VALUE refs;
  VALUE error_handler;
  VALUE external_charset;
  int secure;
  int abort_by_error;
  int wrap_error;
  int accept_block;
};

struct rua {
  lua_State *L;
  struct rua_state *R;
};

struct rua_ref {
  lua_State *L;
  struct rua_state *R;
  int ref;
  int is_ruby;
};

struct rua_debug {
  VALUE name;  
  VALUE namewhat;
  VALUE what;
  VALUE source;
  VALUE currentline;
  VALUE nups;
  VALUE linedefined;
  VALUE lastlinedefined;
  VALUE short_src;
};

struct rua_error {
  VALUE cause;
  VALUE info;
};

void Init_rua();
static VALUE rua_alloc(VALUE klass);
static void rua_mark(struct rua *p);
static void rua_free(struct rua *p);
static VALUE rua_initialize(int argc, VALUE *argv, VALUE self);
static VALUE rua_openlibs(int argc, VALUE *argv, VALUE self);
static VALUE rua_eval(int argc, VALUE *argv, VALUE self);
static VALUE rua_get(VALUE self, VALUE key);
static VALUE rua_set(VALUE self, VALUE key, VALUE val);
static VALUE rua_get_secure(VALUE self);
static VALUE rua_set_secure(VALUE self, VALUE secure);
static VALUE rua_get_abort_by_error(VALUE self);
static VALUE rua_set_abort_by_error(VALUE self, VALUE abort_by_error);
static VALUE rua_get_wrap_error(VALUE self);
static VALUE rua_set_wrap_error(VALUE self, VALUE wrap_error);
static VALUE rua_get_external_charset(VALUE self);
static VALUE rua_set_external_charset(VALUE self, VALUE external_charset);
static VALUE rua_get_error_handler(VALUE self);
static VALUE rua_set_error_handler(VALUE self, VALUE error_handler);
static VALUE rua_method_missing(int argc, VALUE *argv, VALUE self);
static VALUE rua_get_accept_block(VALUE self);
static VALUE rua_set_accept_block(VALUE self, VALUE accept_block);

static VALUE rua_ref_alloc(VALUE klass);
static void rua_ref_mark(struct rua_ref *p);
static void rua_ref_free(struct rua_ref *p);
static void rua_ref_set_ruby_flag(VALUE self, int is_ruby);
static int rua_ref_get_ruby_flag(VALUE self);

static VALUE rua_func_initialize(VALUE self);
static VALUE rua_func_call(int argc, VALUE *argv, VALUE self);
static VALUE rua_func_info(VALUE self);

static VALUE rua_thread_initialize(VALUE self);
static VALUE rua_thread_resume(int argc, VALUE *argv, VALUE self);

static VALUE rua_error_alloc(VALUE klass);
static void rua_error_mark(struct rua_error *p);
static VALUE rua_error_cause(VALUE self);
static VALUE rua_error_info(VALUE self);

static VALUE rua_debug_alloc(VALUE klass);
static void rua_debug_mark(struct rua_debug *p);
static VALUE rua_debug_initialize(VALUE self);
static VALUE rua_debug_name(VALUE self);
static VALUE rua_debug_namewhat(VALUE self);
static VALUE rua_debug_what(VALUE self);
static VALUE rua_debug_source(VALUE self);
static VALUE rua_debug_currentline(VALUE self);
static VALUE rua_debug_nups(VALUE self);
static VALUE rua_debug_linedefined(VALUE self);
static VALUE rua_debug_lastlinedefined(VALUE self);
static VALUE rua_debug_short_src(VALUE self);
static VALUE rua_debug_to_hash(VALUE self);

static VALUE rua_tomultiretval(lua_State *L, int pretop, struct rua_state *R);
static VALUE rua_torbval(lua_State *L, int idx, struct rua_state *R);
static int rua_is_rbobj(lua_State *L, int idx);
static VALUE rua_torbobj(lua_State *L, int idx);
static VALUE rua_tohash(lua_State *L, int idx, struct rua_state *R);
static void rua_pushrbval(lua_State *L, VALUE rbval, struct rua_state *R);
static void rua_newtable_from_ary(lua_State *L, VALUE ary, struct rua_state *R);
static void rua_newtable_from_hash(lua_State *L, VALUE hash, struct rua_state *R);
static void rua_newtable_from_obj(lua_State *L, VALUE obj, struct rua_state *R);
static int rua_getobject_event(lua_State *L);
static int rua_setobject_event(lua_State *L);
static int rua_proc_call(lua_State *L);
static VALUE _rua_proc_call(VALUE args);
static VALUE _rua_proc_call_with_block(VALUE args);
static VALUE _rua_proc_call_as_block(VALUE block_arg, VALUE block, VALUE self);
static VALUE rua_toruaobj(VALUE klass, lua_State *L, int idx, struct rua_state *R);
static VALUE rua_toruaerror(VALUE cause, VALUE ruadebug);
static VALUE rua_toruadebug(lua_Debug *ar);
static VALUE rua_obj_is_executable(VALUE obj);
static int rua_name_is_insecure_method(const char *name);
static VALUE rua_to_s(VALUE v);
static const char *rua_to_sptr(VALUE v);
static VALUE rua_classname(VALUE v);
static const char *rua_classname_ptr(VALUE v);
static void rua_setmeta(lua_State *L, int idx, const char *key, lua_CFunction f, int n);
static void rua_setmeta2(lua_State *L, int idx, const char *key, lua_CFunction f, int n, ...);
static int rua_finalize_rbobj(lua_State *L);
static VALUE rua_iconv(const char *to, const char *from, VALUE in);
static VALUE rua_torbnum(lua_State *L, int idx);

#endif
