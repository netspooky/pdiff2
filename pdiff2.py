import pyshark
import argparse
from collections import Counter 
import string

parser = argparse.ArgumentParser(description='pDiff2')
parser.add_argument('-p', dest='inPcap', help='Pcap File to Analyze')
parser.add_argument('-t', dest='inText', help='Text File to Analyze')
parser.add_argument('-f', dest='pFilter', default="", help='Display Filter to use')
#parser.add_argument('-l', dest='dLayer', default="", help='Dissection Layer') # Unsupported as of now
parser.add_argument('--packet-offset', dest='pOffset', type=lambda x: int(x,0), default=0, help='Offset in packet to diff')
parser.add_argument('-v', dest='verbose', help='verbose output',action="store_true")
parser.add_argument('-c', dest='listCommonBytes', help='List common bytes per offset',action="store_true")
#parser.add_argument('-u', dest='unique', help='Highlight unique values in packet output',action="store_true")
parser.add_argument('-s', dest='stringStats', help='Show string stats',action="store_true")
args    = parser.parse_args()

CGREY7 = "\x1b[48;5;253;38;5;16m"
CGREY6 = "\x1b[48;5;251;38;5;16m"
CGREY5 = "\x1b[48;5;249;38;5;16m"
CGREY4 = "\x1b[48;5;247;38;5;16m"
CGREY3 = "\x1b[48;5;245;38;5;16m"
CGREY2 = "\x1b[48;5;243;38;5;231m"
CGREY1 = "\x1b[48;5;241;38;5;231m"
CGREY0 = "\x1b[48;5;239;38;5;231m"

COLOR0 = "\x1b[48;5;230;38;5;0m" # White
COLOR1 = "\x1b[48;5;227;38;5;0m" # Light Yellow
COLOR2 = "\x1b[48;5;220;38;5;0m" # Yellow Orange
COLOR3 = "\x1b[48;5;214;38;5;0m" # Light Orange
COLOR4 = "\x1b[48;5;208;38;5;231m" # Orange
COLOR5 = "\x1b[48;5;202;38;5;231m" # Dark Orange
COLOR6 = "\x1b[48;5;196;38;5;231m" # Red
COLOR7 = "\x1b[48;5;124;38;5;231m" # Dark Red
COLORN = "\x1b[0m"
COLORX = "\x1b[48;5;244;38;5;0m"
COLORAV = "\x1b[38;5;51m" # For average packet data color

class pDiff:
    def __init__(self, inFile, dataMode, pFilter="", pOffset=0, verbose=False):
        self.captureFile = inFile
        self.pFilter = pFilter
        self.verbose = verbose
        self.pOffset = pOffset
        self.dataMode = dataMode # There are two modes, pcap and text. text is just line by line input of a text file containing ascii hex
        if self.dataMode == "pcap":
            self.packets = pyshark.FileCapture(self.captureFile,use_json=True,include_raw=True,display_filter=self.pFilter)
        elif self.dataMode == "text":
            self.packets = self.getTextPackets()
        else:
            print("Unsupported input type!")
            return
        self.pBytes = {} # Dict full of each offset and the value of each packet that has a byte at that offset
        self.pStrings = {} # This is the structure that contains all of packet string data
        self.pLens = {} # Hacky for now, holds the lengths of all the packets for length analysis
        self.strUniques = [] # This contains unique strings
        self.initPackets() # Get it going
    def dHex(self,inBytes,baseAddr=0):
        offs = 0
        while offs < len(inBytes):
            bHex = ""
            bAsc = ""
            bChunk = inBytes[offs:offs+16]
            for b in bChunk:
                bAsc += chr(b) if chr(b).isprintable() and b < 0x7f else '.'
                bHex += "{:02x} ".format(b)
            sp = " "*(48-len(bHex))
            print("{:08x}: {}{} {}".format(baseAddr + offs, bHex, sp, bAsc))
            offs = offs + 16
    def getTextPackets(self):
        with open(self.captureFile, "r") as f:
            return f.readlines()
    def initPackets(self, showLayers=False, showDissection=False, showFrameInfo=False, printPacketHex=True, printPacketStrings=True):
        if self.dataMode == "pcap":
            print("Analyzing PCAP")
            for pkt in self.packets:
                rawPkt = pkt.get_raw_packet()
                rawPkt = rawPkt[self.pOffset:]
                pktStrings = self.getPacketStrings(rawPkt) # string actions
                self.pStrings[f"f{str(pkt.number)}"] = pktStrings # Put all the strings in the packet buffer
                self.pLens[f"f{str(pkt.number)}"] = len(rawPkt)
                if self.verbose:
                    print(f"Frame {pkt.number}")
                    if showFrameInfo:
                        print(pkt.frame_info) # This will show each packet's wireshark frame info
                    if showDissection:  # This will show each packet's full dissection
                        print(pkt.show()) # pretty_print seems to be the same as show
                    if showLayers:
                        print(pkt.layers) # This will show each packet's layers
                    if printPacketHex:
                        self.dHex(rawPkt,self.pOffset)
                    if printPacketStrings:
                        print(f"Strings in frame {pkt.number}")
                        for pktStr in pktStrings:
                            print(f"- {pktStr[0]:04x}: {repr(pktStr[1])}")
                currentByte = 0 # Byte number in given packet
                for pktByte in rawPkt:
                    if self.pBytes.get(str(currentByte)) is None:
                        self.pBytes[str(currentByte)] = {}
                        fNum = "f"+str(pkt.number) # The packet number
                        self.pBytes[str(currentByte)][fNum] = pktByte # The actual payload data
                        currentByte = currentByte + 1
                    else:
                        fNum = "f"+str(pkt.number) # The packet number
                        self.pBytes[str(currentByte)][fNum] = pktByte # The actual payload data
                        currentByte = currentByte + 1
        elif self.dataMode == "text":
            # Text has no packet metadata or filter support, but the parsing logic is very similar but we have to track the "packet" number manually
            pktNum = 0
            print("Analyzing Text File")
            for pkt in self.packets:
                rawPkt = bytes.fromhex(pkt)
                rawPkt = rawPkt[self.pOffset:]
                pktStrings = self.getPacketStrings(rawPkt)
                self.pStrings[f"f{str(pktNum)}"] = pktStrings # Put all the strings in the packet buffer
                self.pLens[f"f{str(pktNum)}"] = len(rawPkt) # Record the curent length
                if self.verbose:
                    print(f"Frame {pktNum}")
                    if printPacketHex:
                        self.dHex(rawPkt,self.pOffset)
                    if printPacketStrings:
                        print(f"Strings in frame {pktNum}")
                        for pktStr in pktStrings:
                            print(f"{pktStr[0]:04x}: {repr(pktStr[1])}")
                currentByte = 0 # Byte number in given packet
                for pktByte in rawPkt:
                    if self.pBytes.get(str(currentByte)) is None:
                        self.pBytes[str(currentByte)] = {}
                        fNum = "f"+str(pktNum) # The packet number
                        self.pBytes[str(currentByte)][fNum] = pktByte # The actual payload data
                        currentByte = currentByte + 1
                    else:
                        fNum = "f"+str(pktNum) # The packet number
                        self.pBytes[str(currentByte)][fNum] = pktByte # The actual payload data
                        currentByte = currentByte + 1
                pktNum = pktNum + 1
    def getUniquePacketLens(self):
        uniqueLens = []
        for pkt in self.pLens.items():
            if pkt[1] not in uniqueLens:
                uniqueLens.append(pkt[1])
        return uniqueLens
    def listCommonBytesPerOffset(self, asciiPrint=True, maxComp=10):
        # Call with -c argument
        for currentPkt in self.pBytes.keys():
          mostCommon = Counter(self.pBytes[currentPkt].values()).most_common(maxComp) # Get most common values
          if len(mostCommon) > 0:
            tBytes = len(self.pBytes[currentPkt])
            realOffset = int(currentPkt)+self.pOffset
            print(f"\033[1;33m[ Offset 0x{realOffset:02x} ] Total: {tBytes}")
            for commonValue in mostCommon:
                if asciiPrint: # This handles the printing of ascii characters next to the offset
                    if commonValue[0] < 127 and chr(commonValue[0]).isprintable():
                      charPrint = chr(commonValue[0])
                      print(f"  \033[38;5;219m0x{commonValue[0]:02x}\033[0m - {commonValue[1]}/{tBytes} ({round((commonValue[1]/tBytes)*100,2)}%)\t'{charPrint}'") 
                    else:
                      print(f"  \033[38;5;219m0x{commonValue[0]:02x}\033[0m - {commonValue[1]}/{tBytes} ({round((commonValue[1]/tBytes)*100,2)}%)") 
                else:
                    print(f"  \033[38;5;219m0x{commonValue[0]:02x}\033[0m - {commonValue[1]}/{tBytes} ({round((commonValue[1]/tBytes)*100,2)}%)") 
    def packetHeatmap(self):
        # This generates an average packet with a heat map. The more unique values a given byte has, the more intense the color becomes
        print(f"\nPacket Average (With Unique Value Heatmap)")
        print(f"-[{CGREY0}  1+ {CGREY1}  4+ {CGREY2}  8+ {CGREY3}  12+ {CGREY4}  16+ {CGREY5}  20+ {CGREY6}  24+ {CGREY7} 28+ {COLORN}]-")
        print(f"-[{COLOR0} 32+ {COLOR1} 64+ {COLOR2} 96+ {COLOR3} 128+ {COLOR4} 160+ {COLOR5} 192+ {COLOR6} 224+ {COLOR7} 256 {COLORN}]-")
        print()
        pktAverage = ""
        pktAscii = ""
        currentByteInRow = 0
        numRows = 0
        bSep = " "
        packetOffset = 0
        uniqueLens = self.getUniquePacketLens()
        for pktData in self.pBytes.keys(): # iterate over packets keys
            pSet = set(self.pBytes[pktData].values()) # This is the number of unique values for this offset
            pSetLen = len(pSet) # This is the length of this set of values
            if packetOffset in uniqueLens:
                bSep = "\x1b[38;5;213m]" # This puts a bracket to show where a previous packet ended
            if pSetLen == 1:
                r = int(list(self.pBytes[pktData].values())[0])
                pktAverage += f"{COLORAV}{r:02x} {COLORN}"
                pktAscii += f"{COLORAV}{chr(r)}{COLORN}" if chr(r).isprintable() and r < 0x7f else f'{COLORAV}.{COLORN}'
            else:
                COLORZ = ""
                COLORZ = CGREY0 if pSetLen > 0  else COLORZ
                COLORZ = CGREY1 if pSetLen >= 4 else COLORZ
                COLORZ = CGREY2 if pSetLen >= 8 else COLORZ
                COLORZ = CGREY3 if pSetLen >= 12 else COLORZ
                COLORZ = CGREY4 if pSetLen >= 16 else COLORZ
                COLORZ = CGREY5 if pSetLen >= 20 else COLORZ
                COLORZ = CGREY6 if pSetLen >= 24 else COLORZ
                COLORZ = CGREY7 if pSetLen >= 28 else COLORZ
                COLORZ = COLOR0 if pSetLen >= (32*1) else COLORZ
                COLORZ = COLOR1 if pSetLen >= (32*2) else COLORZ
                COLORZ = COLOR2 if pSetLen >= (32*3) else COLORZ
                COLORZ = COLOR3 if pSetLen >= (32*4) else COLORZ
                COLORZ = COLOR4 if pSetLen >= (32*5) else COLORZ
                COLORZ = COLOR5 if pSetLen >= (32*6) else COLORZ
                COLORZ = COLOR6 if pSetLen >= (32*7) else COLORZ
                COLORZ = COLOR7 if pSetLen >= (32*8) else COLORZ
                pktAverage += f"{COLORZ}  {COLORN}{bSep}"
                pktAscii += f"{COLORZ} {COLORN}"
            currentByteInRow = currentByteInRow + 1
            bSep = " "
            if currentByteInRow == 16:
                print(f"{self.pOffset+(numRows*16):04x}  {pktAverage}{'   '*(16-currentByteInRow)}  {pktAscii}")
                pktAverage = ""
                pktAscii = ""
                currentByteInRow = 0
                numRows = numRows + 1
            packetOffset = packetOffset + 1
        print(f"{self.pOffset+(numRows*16):04x}  {pktAverage}{'   '*(16-currentByteInRow)}  {pktAscii}")
    def getPacketStrings(self,packetPayload, strLenMin=4, strModeStrict=False):
        outString = ""
        strList = []
        offs = 0
        strlen = 0
        for pktChar in packetPayload.decode("latin-1"):
            offs = offs + 1 # counting the offset of the packet in total
            if pktChar in string.printable:
                if strModeStrict:
                    if pktChar in string.punctuation:
                        continue
                    if pktChar in string.whitespace:
                        continue
                outString += pktChar
                strlen = strlen + 1
                continue
            if len(outString) >= strLenMin:
                stroffs = offs - strlen - 1 # The -1 is to keep it consistent with the 0 index offset
                strList.append((stroffs,outString))
            outString = ""
            strlen = 0
        if len(outString) >= strLenMin:  # catch at end of packet buffer
            stroffs = offs - strlen # Double check that this one isn't off by one. Might need a special case if offs == 0
            strList.append((stroffs,outString))
        return strList
    def enumUniqueStrings(self):
        # Helper for stringStats
        strList = []
        for dFrame in self.pStrings:
            for packetString in self.pStrings[dFrame]:
                strList.append(packetString[1])
        for i, c in Counter(strList).most_common():
            if c == 1:
                self.strUniques.append(i)
    def stringStats(self, strShowFilter=True):
        # Call with -s argument
        stringList  = [] # List of all the strings
        offsetList  = [] # List of all the offsets
        lengthsList = [] # Most common lengths
        for pi in self.pStrings:
            lengthsList.append(self.pLens[pi])
            for ps in self.pStrings[pi]:
                offsetList.append(ps[0])
                stringList.append(ps[1])
        mcs = Counter(stringList)
        mco = Counter(offsetList)
        mcl = Counter(lengthsList)
        print("\nMost Common Strings:\nCount\tString")
        for s in mcs.most_common(10):
            print(f'  {s[1]}\t{repr(s[0])}',end="")
            if strShowFilter: # If you want the filter to be automatically shown
                print(f' \t frame contains {":".join("{:02x}".format(ord(c)) for c in s[0])}')
            else:
                print()
        print("\nMost Common String Offsets:\nCount\tOffset")
        for pktMostCommonOffset in mco.most_common(10):
            print(f'  {pktMostCommonOffset[1]}\t0x{pktMostCommonOffset[0]:04x}')
        print("\nMost Common Payload Lengths:\nCount\tLength")
        for pktMostCommonLen in mcl.most_common(10):
            print(f'  {pktMostCommonLen[1]}\t{pktMostCommonLen[0]}')
        self.enumUniqueStrings()
        if len(self.strUniques) > 0:
            print("\nUnique Strings:")
            for u in self.strUniques:
                print(f' {repr(u)}')
        else:
            print("\nNo Unique Strings Found!")

if __name__ == '__main__':
    if args.inPcap and args.inText:
        print("Only use one: pcap or text")
    if args.inPcap:
        myPkts = pDiff(args.inPcap,"pcap", pFilter=args.pFilter, verbose=args.verbose, pOffset=args.pOffset)
    if args.inText:
        myPkts = pDiff(args.inText,"text", verbose=args.verbose, pOffset=args.pOffset)
    myPkts.packetHeatmap()
    if args.listCommonBytes:
        myPkts.listCommonBytesPerOffset()
    if args.stringStats:
        myPkts.stringStats()
