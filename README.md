# MalScan 

MalScan is a simple PE File Heuristics Scanners written in python that you can use to quickly analyze a PE file and find out whether anything suspicious exists. It is a simple tool so doesn't offers much fancy features. You are free to extend it or do whatever you want with it.

## Things Supported

- Information About file such as MD5, SHA1, Timestamp
- PEiD Signature Check
- Custom Yara Rules Integration
- Section, Imports, Exports, Resources and TLS Callbacks Overview
- Provides some custom heuristics :-)

## Installing

You need to have Python 2.7 installed on your machine. The additional requirement is yara-python.

```sh
git clone https://github.com/Ice3man543/MalScan.git .
cd MalScan
python malscan.py
```

## Usage 

Simply run with the name of file you want to check. 

![tool_in_action](https://raw.githubusercontent.com/Ice3man543/MalScan/master/usage_example.png)

### Development

Want to contribute? Great! 

You can add more featrues or recommend any changes to the existing ones. Any kind of help is appreciated.

License
----

BSD 2-Clause "Simplified" License


## Contact

Meet me on Twitter: [@Ice3man543](https://twitter.com/ice3man543)

## Credits
- The Awesome PEiD project
- Malware Analysts Cookbook
- Any other malware resource that this tool contains code from :-)
