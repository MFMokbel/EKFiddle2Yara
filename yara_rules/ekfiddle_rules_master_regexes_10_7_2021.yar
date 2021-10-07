// Retrieved on 2021-10-07; 06:50:36 PM
// Total number of parsed rules: 26

import "cuckoo"

rule ekf_fakeupdates_hacked_site_9618 : sourcecode
{
meta:
		name      = "FakeUpdates (hacked site)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://blog.malwarebytes.com/threat-analysis/2018/04/fakeupdates-campaign-leverages-multiple-website-platforms/"

strings:
		$ekfl = /\("cmVmZXJyZXI="\)\]\|\|'';/
condition:
		$ekfl
}

rule ekf_fakeupdates_domain_shadowing_17671 : uri
{
meta:
		name      = "FakeUpdates (domain shadowing)"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://blog.malwarebytes.com/threat-analysis/2018/04/fakeupdates-campaign-leverages-multiple-website-platforms/"

condition:
		cuckoo.network.http_request(/(report\?r=dj\w+ZjaWQ9Mj)|(report\?r=Y2lkPTI(1|2)M)/)
}

rule ekf_fakecertificate_campaign_15792 : sourcecode
{
meta:
		name      = "FakeCertificate Campaign"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/MBThreatIntel/status/1439995792693944324?s=20"

strings:
		$ekfl = /\[0\]\.appendChild\(jspp22\);|\/\/chrome\.html\\">"\s\+\s"<\/frameset>";|IaNeUmeiuVNaming/
condition:
		$ekfl
}

rule ekf_gootloader_15625 : sourcecode
{
meta:
		name      = "Gootloader"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://news.sophos.com/en-us/2021/08/12/gootloaders-mothership-controls-malicious-content/"

strings:
		$ekfl = /j\$k([0-9]{1,10})j\$k/
condition:
		$ekfl
}

rule ekf_fake_jquery_campaign_30639 : sourcecode
{
meta:
		name      = "Fake jQuery Campaign"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://blog.sucuri.net/2017/04/wordpress-security-unwanted-redirects-via-infected-javascript-files.html"

strings:
		$ekfl = /\\x73\\x6A\\x2E\\x79\\x72\\x65\\x75\\x71\\x6A\\x2/
condition:
		$ekfl
}

rule ekf_lnkr_campaign_32670 : sourcecode
{
meta:
		name      = "LNKR Campaign"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/baberpervez2/status/1194090555468394496?s=20"

strings:
		$ekfl = /lat\?jsonp=__[a-z]{3}_cb_[0-9]{9}&(#|amp)|addons\/lnkr30_nt\.min\.js/
condition:
		$ekfl
}

rule ekf_magecart_qlogger_23135 : sourcecode
{
meta:
		name      = "Magecart (Q_logger)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/AffableKraut/status/1385030485676544001?s=20"

strings:
		$ekfl = /var\s\w=\{isOpen:!1,orientation:void\s0,detectInterval:null\}/
condition:
		$ekfl
}

rule ekf_magecart_google_loop_25570 : sourcecode
{
meta:
		name      = "Magecart (Google loop)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/AffableKraut/status/1261157021027622912?s=20"

strings:
		$ekfl = /l1l1<userID\.length;l1l1\+\+/
condition:
		$ekfl
}

rule ekf_magecart_coffemokko_26037 : sourcecode
{
meta:
		name      = "Magecart (CoffeMokko)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://blog.group-ib.com/coffemokko"

strings:
		$ekfl = /\w\[\w\]=\s\w\[\w\];\w\[\w\]=\s\w;\w=\s\(\w\+\s\w\)%\s\d{7}/
condition:
		$ekfl
}

rule ekf_magecart_fakeclicky_540 : sourcecode
{
meta:
		name      = "Magecart (FakeClicky)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/GroupIB_GIB/status/1185237251762069504?s=20"

strings:
		$ekfl = /=','script','Y2hlY2tvdXQ=',/
condition:
		$ekfl
}

rule ekf_magecart_radix_4212 : sourcecode
{
meta:
		name      = "Magecart (Radix)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://blog.sucuri.net/2019/03/more-on-dnsden-biz-swipers-and-radix-obfuscation.html"

strings:
		$ekfl = /0a(0w){12}/
condition:
		$ekfl
}

rule ekf_magecart_svg_7985 : sourcecode
{
meta:
		name      = "Magecart (svg)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://sansec.io/research/svg-malware"

strings:
		$ekfl = /[iI]d=?\(?"(facebook|google|twitter|instagram|youtube|pinterest)_full"(\sviewbox="0\s0|\);window\.q=e)/
condition:
		$ekfl
}

rule ekf_magecart_shell_22619 : sourcecode
{
meta:
		name      = "Magecart (shell)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://blog.malwarebytes.com/cybercrime/2021/05/newly-observed-php-based-skimmer-shows-ongoing-magecart-group-12-activity/"

strings:
		$ekfl = /\$AJegUupT=/
condition:
		$ekfl
}

rule ekf_magecart_magento_footer_1193 : sourcecode
{
meta:
		name      = "Magecart (Magento footer)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/injecting-magecart-into-magento-global-config/"

strings:
		$ekfl = /function\sFN2Z22\(\)\{var/
condition:
		$ekfl
}

rule ekf_magecart_grelos_8330 : sourcecode
{
meta:
		name      = "Magecart (grelos)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/killamjr/status/1209165822939279365?s=20"

strings:
		$ekfl = /var grelos_v=/
condition:
		$ekfl
}

rule ekf_magecart_bom_12791 : sourcecode
{
meta:
		name      = "Magecart (Bom)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://community.riskiq.com/article/743ea75b"

strings:
		$ekfl = /(,urll,true\))|(;urll=\s_0x)|(\];function\sboms\(\))|stats:btoa\(_0x/
condition:
		$ekfl
}

rule ekf_magecart_57_gateways_14389 : sourcecode
{
meta:
		name      = "Magecart (57 gateways)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://sansec.io/research/polymorphic-skimmer-57-payment-gateways"

strings:
		$ekfl = /'1f1612164c041c515b1509011f0d03',\s'13101206530e1946'/
condition:
		$ekfl
}

rule ekf_magecart_state_30941 : sourcecode
{
meta:
		name      = "Magecart (state)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /\w=\w\[\w\];return!\w\?\(\w\[/
condition:
		$ekfl
}

rule ekf_magecart_fake_slideshow_29672 : sourcecode
{
meta:
		name      = "Magecart (fake slideshow)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/AffableKraut/status/1445043970283905024?s=20"

strings:
		$ekfl = /\['105O110O112O117O116O','115O101O108O101O99O116O'/
condition:
		$ekfl
}

rule ekf_rig_ek_26156 : uri
{
meta:
		name      = "RIG EK"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/rig-exploit-kit-diving-deeper-into-the-infrastructure/"

condition:
		cuckoo.network.http_request(/https?:\/\/[^\x3f]+\/\x3f[^\x3f]+Q[cdM][_fPrv][bDfLPTWXjn][acdefYZVUb][abKLJ][^\n]+/)
}

rule ekf_purplefox_ek_21987 : uri
{
meta:
		name      = "PurpleFox EK"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://www.trendmicro.com/en_ca/research/20/i/purple-fox-ek-relies-on-cloudflare-for-stability.html"
		comment   = "the regex uses negative lookahead"

condition:
		cuckoo.network.http_request(/http(s|):\/\/[^.]([a-z0-9-]+\.){2}[a-z]{2,7}\/news/((crypto-js|zepto|aes|base64)\.min\.js|dl\.php\?key=[0-9])/)
}

rule ekf_spelevo_ek_8486 : sourcecode
{
meta:
		name      = "Spelevo EK"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://blog.talosintelligence.com/2019/06/spelevo-exploit-kit.html"

strings:
		$ekfl = /\s{5}\tvar p = '\w{50}/
condition:
		$ekfl
}

rule ekf_underminer_ek_26198 : uri
{
meta:
		name      = "Underminer EK"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://blog.malwarebytes.com/threat-analysis/2018/07/hidden-bee-miner-delivered-via-improved-drive-by-download-toolkit/"

condition:
		cuckoo.network.http_request(/http(s|):\/\/(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\/(views|js)\/[a-z0-9]{26}\.(html|swf|wav|jpg|js)/)
}

rule ekf_underminer_ek_32588 : sourcecode
{
meta:
		name      = "Underminer EK"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://www.trendmicro.com/en_ca/research/18/g/new-underminer-exploit-kit-delivers-bootkit-and-cryptocurrency-mining-malware-with-encrypted-tcp-tunnel.html"

strings:
		$ekfl = /src="\/js\/((.*\d){4})[a-z0-9]{26}\.js"><\/script>|TinyJSLibrary\.enc\.Hex\.parse\('[a-z0-9]{32}'\)\)\.toString\(TinyJSLibrary\.enc\.Utf8\)\);/
condition:
		$ekfl
}

rule ekf_magnitude_ek_8841 : uri
{
meta:
		name      = "Magnitude EK"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://malware.dontneedcoffee.com/2018/03/CVE-2018-4878.html"
		comment   = "the regex uses negative lookahead"

condition:
		cuckoo.network.http_request(/http:\/\/((.*\d){4})(.*[a-zA-Z])[0-9a-zA-Z!@#$%]{8,}\.[a-z]{6,7}\.[a-z]{3,15}\/$/)
}

rule ekf_cve_2021_40444_14186 : sourcecode
{
meta:
		name      = "CVE-2021-40444"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444"

strings:
		$ekfl = /(':\.'\+'\.\/'\+'\.{2}\/'\+'\.{2}'\+'\/\.'\+'\.\/\.{2}\/)|(\.cpl:(\.{2}/){5})/
condition:
		$ekfl
}
