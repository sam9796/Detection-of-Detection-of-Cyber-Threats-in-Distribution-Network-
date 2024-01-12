from scapy.all import *

# Converet string to integer 
def hextodec(ts):
    ans = int(ts, 16)
    return ans

#Read packet frim wireshark file
packets = rdpcap("DelayAttack.pcapng")
cnt=10
prev=0 

for pack in packets:
    s = raw(pack)
    s1 = str(s)
    hexstr = ""
    i = 2
    while (i < len(s1)-1):
        if (i < len(s1)-2):
            if (s1[i] == "\\" and s1[i+1] == 'x'):
                hexstr = hexstr+s1[i+2]+s1[i+3]
                i += 3
            elif (s1[i] == '\\' and s1[i+1] == 'n'):
                hexstr = hexstr+"0a"
                i += 1
            elif (s1[i] == '\\' and s1[i+1] == 'r'):
                hexstr = hexstr+"0d"
                i += 1
            elif (s1[i] == '\\' and s1[i+1] == 't'):
                hexstr = hexstr+"09"
                i += 1
            elif (s1[i] == '\\' and s1[i+1] == '\\'):
                hexstr = hexstr+"5c"
                i += 1
            elif (s1[i] == '\\' and s1[i+1] == '\''):
                hexstr = hexstr+"27"
                i += 1
            else:
                c = hex(ord(s1[i]))
                c1 = str(c)
                hexstr = hexstr+c1[2]+c1[3]
        else:
            c = hex(ord(s1[i]))
            c1 = str(c)
            hexstr = hexstr+c1[2]+c1[3]
        i += 1
    port=hextodec(hexstr[68:72]) # source port number is used to identify the protocol of packet read
    if(port==4732 or port==4752 or port==4782): #port numbers for synchrophasor packets
        if(len(hexstr)>=396):
            j = 154
            fos = hextodec(hexstr[j:j+6]) # Variable which is measure of time at which synchrophasor data is read
                    
            if(prev==0):
                    prev = fos

            if(fos-prev>17000 and cnt>0): 
                    cnt = cnt-1
                    print("Packet Delay",end=" ")
                    print(fos,prev,fos-prev)

            prev=fos
        
        if len(hexstr)==168 :
            print("Drop Attack is performed")