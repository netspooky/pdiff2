# pdiff2

pDiff2 is a standalone tool and library for analyzing pcaps, as well as text files containing lines of hex data. It's a combination of several smaller scripts I had worked on previously, along with the core logic of the [original pDiff](https://github.com/netspooky/pdiff). I wanted to rename it because pdiff is super generic and it's confusing.

I switched to using the pyshark library as it's a wrapper for Wireshark/Tshark and gives access to much nicer dissections (and even custom dissectors if they're installed).

> This tool is under active development, many features may change!

Requirements
- pyshark

## Usage

You can use pDiff2 in 2 ways

### As a standalone tool

- To analyze a pcap, use the option `-p myPcap.pcap`
- To analyze a text file use the option `-t myTextFile.txt`

Command Line Options
```
python3 pdiff2.py -h
usage: pdiff2.py [-h] [-p INPCAP] [-t INTEXT] [-f PFILTER] [--packet-offset POFFSET] [-v] [-c] [-s]

pDiff2

options:
  -h, --help            show this help message and exit
  -p INPCAP             Pcap File to Analyze
  -t INTEXT             Text File to Analyze
  -f PFILTER            Display filter to use
  --packet-offset POFFSET
                        Offset in packet to diff
  -v                    verbose output
  -c                    List common bytes per offset
  -s                    Show string stats
```

### As a library

pDiff2 has class methods for performing packet analysis.

An example of creating a pDiff object is as follows:
```python
pDiff("./myPcap.pcap,"pcap", pFilter="some wireshark filter", verbose=True, pOffset=0x2a)
myPkts.packetHeatmap() # print a heatmap of all available packets
```

Text files containing lines of hex data are also supported. Each line is treated as a packet, and can be analyzed in the same way as pcaps. The main difference is that dissections and filters aren't possible (currently) with this format, but all of the other analysis remains the same.
```python
pDiff("./mydata.txt,"text", verbose=True)
myPkts.packetHeatmap() # print a heatmap of all available packets
```

## What's Next?

There are a few things I want to finish:

- [ ] Make the color scheming nicer - Currently it's gross but I did it to make it work
- [ ] Add nicer output in general - I was thinking of using that `rich` library instead of writing my own
- [ ] Add Yara Support - I had another script that did frame aware yara signature scans on a pcap and alerted when the signature matched inside of a frame. I want to rework this so it works on both pcaps and text input.
- [ ] Fix up the data structure that holds all the info. It's kind of messy.
- [ ] Add more analysis functions
- [ ] LiveDiff - Raw socket listener for diffing packets

Others:

- [ ] It would be nice to add a repl mode 
- [ ] Explore more pyshark features
