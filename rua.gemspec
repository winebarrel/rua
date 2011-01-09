Gem::Specification.new do |spec|
  spec.name              = 'rua'
  spec.version           = '0.4.8'
  spec.summary           = 'Rua is a library for using Lua under Ruby.'
  spec.files             = ['README.txt', 'ext/rua.c', 'ext/rua.h', 'ext/extconf.rb']
  spec.author            = 'winebarrel'
  spec.email             = 'sgwr_dts@yahoo.co.jp'
  spec.homepage          = 'http://rua.rubyforge.org'
  spec.extensions        = 'ext/extconf.rb'
  spec.has_rdoc          = true
  spec.rdoc_options      << '--title' << 'Rua - library for using Lua under Ruby.'
  spec.extra_rdoc_files  = ['README.txt', 'ext/rua.c']
  spec.rubyforge_project = 'rua'
end
