= Rua

Copyright (c) 2007,2008 SUGAWARA Genki <sgwr_dts@yahoo.co.jp>

== Description

Rua is a library for using Lua under Ruby.

== Project Page

http://rubyforge.org/projects/rua

== Install

gem install rua

== Download

http://rubyforge.org/frs/?group_id=4845

== Example

    require 'rua'
    
    class MyClass
      CONST_FOO = 100
      def val=(v); @val = v; end
      def val; @val; end
      def [](k); "#{k}->#{@val}"; end
      def []=(k, v); @val = "#{k}:#{v}"; end
    end
    
    rua = Rua.new(:all)
    #rua.external_charset = Rua::SJIS
    #rua.openlibs(:base, :package, :string)
    #rua.secure = false
    rua.abort_by_error = false
    rua.error_handler = lambda do |e|
      p e
      p e.cause
      p e.info.to_hash
    end
    
    rua.str = 'xxx'
    rua.num = 100
    rua.range = 1..5
    rua.proc = lambda do
      puts 'proc called.'
    end
    rua.err = lambda do
      raise 'err called.'
    end
    rua.Time = Time
    rua.MyClass = MyClass
    
    puts rua.eval(<<-EOS)
      print('hello Rua!')
      print(str)
      print(num)
      range.each(function(i)
        print(i)
      end)
      proc()
      err()
      print(Time.new().to_s())
      my_obj = MyClass.new()
      my_obj.val = 'my_obj.val'
      print(my_obj.val())
      print(my_obj['foo'])
      my_obj['bar'] = 'zoo'
      print(my_obj.val())
      print(MyClass.CONST_FOO)
    
      f = function()
        print('f() called.')
      end
    
      return true
    EOS
    
    rua.f.call
    p rua.my_obj
    p rua.eval('return 1, 2, 3')
    
    co = rua.eval(<<-EOS)
      function foo (a)
        print('foo', a)
        return coroutine.yield(2 * a)
      end
    
      return coroutine.create(function (a, b)
        print('co-body', a, b)
        local r = foo(a + 1)
        print('co-body', r)
        local r, s = coroutine.yield(a + b, a - b)
        print('co-body', r, s)
        return b, 'end'
      end)
    EOS
    
    p co.resume(1, 10)
    p co.resume('r')
    p co.resume('x', 'y')
    p co.resume('x', 'y')
    
    p rua.f.info.to_hash

== Notice
This library uses Lua.

=== Lua
License for Lua 5.0 and later versions

Copyright (c) 1994-2007 Lua.org, PUC-Rio.
