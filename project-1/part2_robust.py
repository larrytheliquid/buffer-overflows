#!/usr/bin/python

# Assuming the relationship between foo and fp is constant, and that
# the third-and-higher order bytes of APTs fp are the same as ours, we
# can compute APTs fp by shifting our fp by the separation of his and
# our foo.  In other words, under the assumptions,
#
#   apts_fp = our_fp + (apts_fp  - our_fp)
#           = our_fp + (apts_foo - our_foo)

our_fp   = 0x00007fffffffdb80
our_foo  = 0xdb7c
apts_foo = 0xea4c
apts_fp  = our_fp + (apts_foo - our_foo)
print '%016x' % apts_fp
