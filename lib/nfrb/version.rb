# This file is part of the nfrb gem for Ruby.
#
# Copyright (C) 2011 Davide Guerri
# 
# This code is largely derived from nfreader.c of nfdump suite.

module NfRb
  module Version
    MAJOR = 0
    MINOR = 0
    PATCH = 1
    BUILD = 'alpha'

    STRING = [MAJOR, MINOR, PATCH, BUILD].compact.join('.')
  end
end
