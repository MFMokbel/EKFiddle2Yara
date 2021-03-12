# EKFiddle2Yara
EKFiddle2Yara is a tool that takes [EKFiddle](https://github.com/malwareinfosec/EKFiddle) rules and converts them into Yara rules. The tool provides a plethora of options to generate customized Yara rules.

EKFiddle [Master Regexes](https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Regexes/MasterRegexes.txt) file contains such rules, and follows a specific format for each of the rules types.

Each rule spans one line only. For example,

```
SourceCode	Web Skimmer (Google exfil)	'replace','IMG','CVV'	https://twitter.com/AffableKraut/status/1362429457932419078?s=20
URI	KaiXin EK	\/hfs\/(cookie_do\.swf|\w{6}\.jar|swfobject\.js|jquery\.js)$
```

Each of the elements of the rule is deimited by a tab '\t'. The rule consists of the following elements, in this specific order:

1. **type**: takes either of the values (SourceCode|URI|IP|Headers|Hash)
2. **name**: for example, "Web Skimmer (Google exfil)"
3. **logic**: detection logic (content match or a regex). For example, "'replace','IMG','CVV'"
5. **reference**: this is usually a url pointing to the source of the logic (this is optional). For example, https://twitter.com/AffableKraut/status/1362429457932419078?s=20

Note-1: Every line that starts with "##" in the [Master Regexes](https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Regexes/MasterRegexes.txt) file is a comment, and therefore is ignored.

# Yara rule format
Generated Yara rule has the following format:

```yara
rule ekf_<normalized name>_<random number> : <type>
{
meta:
	name      = "<name>"
	type      = "<type>"
	author    = "EKFiddle2Yara vx.y"
	date      = "<date the rule was generated>"
	reference = "<reference(url)>"

strings:
	$ekfl = /<logic>/

condition:
	$ekfl
}
```
* <*normalized name*> is the **name** parsed such that only alphanumeric characters are allowed, and all other characters are replaced with '_'
* <*random number*> is a random number that takes a value between 0 and 90000. This is to avoid collision with rules of the same name. Note that this value is different on every invocation.
* The rest is self explanatory

# EKFiddle2Yara Rule Generation Options

```
Usage:
  EKFiddle2Yara [OPTION...]

  -f, --file arg  EKFiddle master regexes file (default: )
  -u, --url arg   url to fetch EKFiddle master regexes from (default:
                  https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Regexes/MasterRegexes.txt)
  -i, --ip        use VirusTotal cuckoo Yara module for rules of ip type
  -q, --query     use VirusTotal cuckoo Yara module for rules of uri type
  -n, --nocase    add nocase modifier to the rules
  -w, --wide      add wide modifier to the rules
  -a, --ascii     add ascii modifier to the rules
  -m, --mrgx      massage regex to work with Yara (default: true)
  -s, --save arg  save Yara rule(s) to a file
  -p, --print     print Yara rules to the console (default: true)
  -h, --help      print usage
  ```
1. By default, the tool pulls the [Master Regexes](https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Regexes/MasterRegexes.txt) from the Github repo, parses it, and prints generated Yara rules to the console window. You can also read EKFiddle rules from a file on disk with the option "**-f/--file**".
2. For rules of the types IP and URI, you could use the options "**-i/--ip**" and "**-q/--query**" to generate Yara conditions that use Cuckoo's module syntax.
3. For rules of the type Hash, the tool generates Yara conditions that use the Hash module syntax. It doesn't make sense otherwise.
4. Starting with version 2.0, Yara uses its own regex engine, a limited one compared to PCRE and RE libraries it used to use in previous versions. The list of some of the regex features it doesn't support include: backreferences, positive/negative lookahead, positive/negative lookbehind, non-capturing groups, regex case-insensitive flags (?i) and (?-i), the mix of greedy and non-greedy quantifiers in the same regex string, atomic groups, possessive quantifiers.
   * When a regex/logic payload is found to contain a negative lookahead, a specific comment is added to the Yara rule meta section. There is no alternative for negative lookahead.
   * By default, the tool massages the regex such that it removes most of the non-allowed regex features. This behaviour could be overridden by setting the option to false "**--mrgx=false**"

# Third-party libraries used

- [cpr: for HTTP(S) communications](https://github.com/whoshuu/cpr)
- [cxxopts: for parsing command line arguments](https://github.com/jarro2783/cxxopts)
- [Color Console: for console coloring](https://github.com/imfl/color-console)
 
# Contributing

Open for pull requests and issues. Comments and suggestions are greatly appreciated.

# Author

Mohamad Mokbel ([@MFMokbel](https://twitter.com/MFMokbel))
