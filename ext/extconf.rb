require 'mkmf'

dir_config('lua', '/usr/include/lua5.1', '/usr/lib')
if have_header('lua.h') and have_header('lualib.h') and have_header('lauxlib.h') and (have_library('lua5.1') or have_library('lua')) and have_header('iconv.h') and have_header('errno.h')
  have_header('iconv')
  create_makefile('rua')
end
