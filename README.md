# EKFiddle2Yara
EKFiddle2Yara is a tool that takes [EKFiddle](https://github.com/malwareinfosec/EKFiddle) rules and converts them into Yara rules. The tool provides a plethora of options to generate customized Yara rules.

EKFiddle [Master Regexes](https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Regexes/MasterRegexes.txt) file contains such rules, and follows a specific format for each of the rules types.

Each rule spans one line only. For example,

```
SourceCode	Web Skimmer (Google exfil)	'replace','IMG','CVV'	https://twitter.com/AffableKraut/status/1362429457932419078?s=20
URI	KaiXin EK	\/hfs\/(cookie_do\.swf|\w{6}\.jar|swfobject\.js|jquery\.js)$
IP	Web Skimmer (jashkinagal)	83\.166\.244\.76
Headers	Malcdn Campaign	9d5e3=eyJ
Hash	TSS Browlock (audio)	0589be7715d2320e559eae6bd26f3528e97450c70293da2e1e8ce45f77f99ab1|fc59bbb18f923747b9cd3f3b23537ff09c5ad2fdfc1505a4800a3f269a234e65|d6e8aff6202436d3d2c56f686ad04680f2e5afd6ac0e1e0911772e28f2471ad2
```

Each of the elements of the rule is deimited by a tab '\t'. The rule consists of the following elements, in this specific order:

1. **type**: takes either of the values (SourceCode|URI|IP|Headers|Hash|Extract-Skimmer|Extract-Phone|Extract-CMS)
2. **name**: for example, "Web Skimmer (Google exfil)"
3. **logic**: detection logic (content match or a regex). For example, "'replace','IMG','CVV'". However, everything is treated as a regex.
5. **reference**: this is usually a url pointing to the source of the logic (this is optional). For example, https://twitter.com/AffableKraut/status/1362429457932419078?s=20

Note-1: Every line that starts with "##" in the [Master Regexes](https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Regexes/MasterRegexes.txt) file is a comment, and therefore is ignored.

Recently (sometime after May 2021), some of the rules have been updated such that they don't follow the aforementioned elements separation logic. These changes are specific to rules of the types, Extract-Skimmer (used to be under the SourceCode type) and Extract-Phone (new); these rules are stored in the [/Misc/ExtractionRules.txt](https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Misc/ExtractionRules.txt) file. These rules used to be stored in the [Master Regexes](https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Regexes/MasterRegexes.txt) file. The major difference is that the rule's type becomes the rule's name. The transpiler accounts for these changes, nonetheless.

The rule type Extract-CMS has a slightly different logic. For example, the rule shown below still honors the '\t' separation between every element, except that this rule contains a digit element in addition to the content match. This digit (ex., 10) represents the minimum number of occurrences of the content match/regex (ex., "\/wp-content\/") in the payload.

```
Extract-CMS	WordPress	\/wp-content\/	10
```

The converter accounts for this rule type by converting it as follows:

```yara
rule ekf_wordpress_10943 : extract_cms
{
meta:
	name      = "WordPress"
	type      = "extract-cms"
	author    = "EKFiddle2Yara v1.0"
	date      = "2021-10-06"
	reference = "none"

strings:
        $ekfl = /\/wp-content\//
condition:
        #ekfl >= 10
}
```

For reference, you can get the old **MasterRegexes.txt** file from this repo, since it is not longer available on the official EKFiddle repo.

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
* <*normalized name*> is the **name** parsed such that only alphanumeric characters are accepted, and all white-space and '-' characters are replaced with '_'.
* <*random number*> is a random number that takes a value between 0 and 90000. This is to avoid collision with rules of the same name. Note that this value is different on every invocation.
* The rest is self-explanatory

# EKFiddle2Yara Rule Generation Options

```
Usage:
  EKFiddle2Yara [OPTION...]

  -f, --file arg  EKFiddle master regexes file (default: )
  -u, --url arg   url to fetch EKFiddle master regexes from (default: https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Regexes/MasterRegexes.txt)
  -i, --ip        use VirusTotal cuckoo Yara module for rules of ip type
  -q, --query     use VirusTotal cuckoo Yara module for rules of uri type
  -n, --nocase    add nocase modifier to the rules
  -w, --wide      add wide modifier to the rules
  -a, --ascii     add ascii modifier to the rules
  -m, --mrgx      massage regex to work with Yara (default: true)
  -r, --rnla      remove negative lookahead assertion(s) from regex (default: true)
  -d, --da        discard start(^) and end($) of string anchors from regex (default: true)
  -s, --save arg  save Yara rule(s) to a file
  -p, --print     print Yara rules to the console (default: true)
  -h, --help      print usage
  ```
1. By default, the tool pulls the [Master Regexes](https://raw.githubusercontent.com/malwareinfosec/EKFiddle/master/Regexes/MasterRegexes.txt) from the Github repo, parses it, and prints generated Yara rules to the console window. You can also read EKFiddle rules from a file on disk with the option "**-f/--file**".
2. For rules of the types IP and URI, you could use the options "**-i/--ip**" and "**-q/--query**" to generate Yara conditions that use Cuckoo's module syntax.
3. For rules of the type Hash, the tool generates Yara conditions that use the Hash module syntax. It doesn't make sense otherwise.
4. Starting with version 2.0, Yara uses its own regex engine, a limited one compared to PCRE and RE libraries it used to use in previous versions. The list of some of the regex features it doesn't support include *backreferences, positive/negative lookahead, positive/negative lookbehind, non-capturing groups, regex case-insensitive flags (?i) and (?-i), the mix of greedy and non-greedy quantifiers in the same regex string, atomic groups, possessive quantifiers.*
   * By default, the tool massages the regex such that it removes most of the non-allowed regex features. This behaviour could be overridden by setting the option **--mrgx** to **false** "**--mrgx=false**"
   * When a regex/logic payload is found to contain a negative lookahead assertion, a specific comment is added to the Yara rule meta section, and the assertion is deleted from the regex. This behaviour could be overridden by setting the option **--rnla** to **false** "**--rnla=false**"

# Example

- To generate a Yara rule that uses Cuckoo module syntax for the **URI** rule shown above:

> *ekfiddle2yara.exe -q*

```yara
rule ekf_kaixin_ek_22637 : uri
{
meta:
	name      = "KaiXin EK"
	type      = "uri"
	author    = "EKFiddle2Yara v1.0"
	date      = "2021-03-12"
	reference = "none"

condition:
	cuckoo.network.http_request(/\/hfs\/(cookie_do\.swf|\w{6}\.jar|swfobject\.js|jquery\.js)$/)
}
```
- To generate a Yara rule that takes the ascii and nocase modifiers for the **SourceCode** rule shown above:

> *ekfiddle2yara.exe -n -a*

```yara
rule ekf_web_skimmer_google_exfil_32229 : sourcecode
{
meta:
	name      = "Web Skimmer (Google exfil)"
	type      = "sourcecode"
	author    = "EKFiddle2Yara v1.0"
	date      = "2021-03-12"
	reference = "https://twitter.com/AffableKraut/status/1362429457932419078?s=20"

strings:
	$ekfl = /'replace','IMG','CVV'/ nocase ascii
condition:
	$ekfl
}
```

# Third-party libraries used

- [cpr: for HTTP(S) communications](https://github.com/whoshuu/cpr)
- [cxxopts: for parsing command line arguments](https://github.com/jarro2783/cxxopts)
- [Color Console: for console coloring](https://github.com/imfl/color-console)
 
# Release

A 32-bit & a 64-bit binary releases are located under the **Releases** folder.

# Contributing

Open for pull requests and issues. Comments and suggestions are greatly appreciated.

# Author

Mohamad Mokbel ([@MFMokbel](https://twitter.com/MFMokbel))
