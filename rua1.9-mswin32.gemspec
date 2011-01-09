Gem::Specification.new do |spec|
  spec.name              = 'rua1.9'
  spec.version           = '0.4.8'
  spec.platform          = 'mswin32'
  spec.summary           = 'Rua is a library for using Lua under Ruby.'
  spec.require_paths     = ['lib/i386-mswin32']
  spec.files             = ['README.txt', 'lib/i386-mswin32/rua.so']
  spec.author            = 'winebarrel'
  spec.email             = 'sgwr_dts@yahoo.co.jp'
  spec.homepage          = 'http://rua.rubyforge.org'
  spec.has_rdoc          = true
  spec.rdoc_options      << '--title' << 'Rua - library for using Lua under Ruby.'
  spec.extra_rdoc_files  = ['README.txt', 'ext/rua.c']
  spec.rubyforge_project = 'rua'
end
