# EKFiddler2Yara
EKFiddle2Yara is a tool that takes [EKFiddle](https://github.com/malwareinfosec/EKFiddle) rules and converts them into Yara rules. The tool provides a plethora of options to generate customized Yara rules.

EKFiddle [Master Regexes](https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Regexes/MasterRegexes.txt) file contains such rules, and follows a specific format for each of the rules types.

Each rule spans one line only. For example,

> **SourceCode**	Web Skimmer (Google exfil)	'replace','IMG','CVV'	https://twitter.com/AffableKraut/status/1362429457932419078?s=20

Each of the elements of the rule is deimited by a tab '\t'. The rule consists of the following elements, in this specific order:

1. **type**: takes either of the values (SourceCode|URI|IP|Headers|Hash)
2. **name**: for example, "Web Skimmer (Google exfil)"
3. **logic**: detection logic (content match or a regex). For example, "'replace','IMG','CVV'"
5. **reference**: this is usually a url pointing to the source of the logic. For example, https://twitter.com/AffableKraut/status/1362429457932419078?s=20

Note: Every line that starts with "##" in the [Master Regexes](https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Regexes/MasterRegexes.txt) file is a comment, and therefore is ignored.

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



# Third-party libraries used

- [cpr: for HTTP(S) communications](https://github.com/whoshuu/cpr)
- [cxxopts: for parsing command line arguments](https://github.com/jarro2783/cxxopts)
- [Color Console: for console coloring](https://github.com/imfl/color-console)
 
# Contributing

Open for pull requests and issues. Comments and suggestions are greatly appreciated.

# Author

Mohamad Mokbel ([@MFMokbel](https://twitter.com/MFMokbel))
