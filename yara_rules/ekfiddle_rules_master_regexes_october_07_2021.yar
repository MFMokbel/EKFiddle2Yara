// Retrieved on 2021-10-07; 06:48:48 PM
// Total number of parsed rules: 127

import "hash"
import "cuckoo"

rule ekf_web_skimmer_angular_9265 : sourcecode
{
meta:
		name      = "Web Skimmer (Angular)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /\};Angular(\['|\.)ready('\])?\(\)|Angular\.algularToken|\}\}return null;\},'register':function\(_/
condition:
		$ekfl
}

rule ekf_web_skimmer_atmzow_3723 : sourcecode
{
meta:
		name      = "Web Skimmer (ATMZOW)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/AffableKraut/status/1174933081792188416?s=20"

strings:
		$ekfl = /function ATMZOW\(\)/
condition:
		$ekfl
}

rule ekf_web_skimmer_aws_s3_19774 : sourcecode
{
meta:
		name      = "Web Skimmer (AWS S3)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/killamjr/status/1184480414947139584?s=20"

strings:
		$ekfl = /','\\x55\\x32\\x46\\x32\\x5[aA]\\x56\\x42\\x68\\x63\\x6[dD]\\x46\\x74',/
condition:
		$ekfl
}

rule ekf_web_skimmer_br_5459 : sourcecode
{
meta:
		name      = "Web Skimmer (BR)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /\\x27\\x6E\\x75\\x6D\\x65\\x72\\x6F\\x5F\\x63\\x61\\x72\\x74\\x61\\x6F\\x27/
condition:
		$ekfl
}

rule ekf_web_skimmer_callback_30777 : sourcecode
{
meta:
		name      = "Web Skimmer (callback)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/AffableKraut/status/1225279882118209536?s=20"

strings:
		$ekfl = /\s{12}_script\("[0-9a-z]{74}"\),|_scriptCallback\s=\s"[0-9a-z]{1000}/
condition:
		$ekfl
}

rule ekf_web_skimmer_checkoutonepage_1799 : sourcecode
{
meta:
		name      = "Web Skimmer (checkoutonepage)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /'atob','(Y2hlY2tvdXQvb25lcGFnZQ|Y2hlY2tvdXQ)==?','getElement|\(window.atob\("Y2hlY2tvdXQvb25lcGFnZQ==/
condition:
		$ekfl
}

rule ekf_web_skimmer_checkout_base64_14670 : sourcecode
{
meta:
		name      = "Web Skimmer (checkout base64)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /'YXRvYg==','WTJobFkydHZkWFE9'/
condition:
		$ekfl
}

rule ekf_web_skimmer_cdn71_14035 : sourcecode
{
meta:
		name      = "Web Skimmer (cdn71)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /\\x63\\x64\\x6E\\x30\\x30\\x30\\x30\\x30\\x30\\x31/
condition:
		$ekfl
}

rule ekf_web_skimmer_coffemokko_12257 : sourcecode
{
meta:
		name      = "Web Skimmer (CoffeMokko)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/GroupIB_GIB/status/1185237251762069504?s=20"

strings:
		$ekfl = /if\(location\.href\.search\(atob\("ZmlyZWNoZWNrb3V0"\)\)!=-1/
condition:
		$ekfl
}

rule ekf_web_skimmer_fakeclicky_9171 : sourcecode
{
meta:
		name      = "Web Skimmer (FakeClicky)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/GroupIB_GIB/status/1185237251762069504?s=20"

strings:
		$ekfl = /=','script','Y2hlY2tvdXQ=',/
condition:
		$ekfl
}

rule ekf_web_skimmer_fake_getsitecontrol_20186 : sourcecode
{
meta:
		name      = "Web Skimmer (Fake GetSiteControl)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /break;\n\}(\n)?\}\)\(window, document, '_gscq/
condition:
		$ekfl
}

rule ekf_web_skimmer_fake_ga_mastercard_3228 : sourcecode
{
meta:
		name      = "Web Skimmer (Fake GA, mastercard)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://blog.malwarebytes.com/web-threats/2019/11/web-skimmer-phishes-credit-card-data-via-rogue-payment-service-platform/"

strings:
		$ekfl = /if\(JSON\.stringify\(SendFlag\)\s==\sJSON\.stringify\(vals\)\)\{/
condition:
		$ekfl
}

rule ekf_web_skimmer_fakesecurity_23685 : sourcecode
{
meta:
		name      = "Web Skimmer (FakeSecurity)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://www.group-ib.com/blog/fakesecurity_raccoon"

strings:
		$ekfl = /\)\)\s\('_'\);/
condition:
		$ekfl
}

rule ekf_web_skimmer_fbseo_16430 : sourcecode
{
meta:
		name      = "Web Skimmer (FBseo)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /\w\[\w\]=\s\w\[\w\];\w\[\w\]=\s\w;\w=\s\(\w\+\s\w\)%\s\d{7}/
condition:
		$ekfl
}

rule ekf_web_skimmer_wordpress_analytics_3641 : sourcecode
{
meta:
		name      = "Web Skimmer (wordpress-analytics)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /a\.id\s=\s"ecc1dbbb";/
condition:
		$ekfl
}

rule ekf_web_skimmer_cloudfare_8053 : sourcecode
{
meta:
		name      = "Web Skimmer (cloudfare)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /\(function\(\)\n\{\n\tfunction\sOx\$/
condition:
		$ekfl
}

rule ekf_web_skimmer_gate_1630 : sourcecode
{
meta:
		name      = "Web Skimmer (gate)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /'CVV':null,'Gate':/
condition:
		$ekfl
}

rule ekf_web_skimmer_gate_exfil_7097 : sourcecode
{
meta:
		name      = "Web Skimmer (gate exfil)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/killamjr/status/1210663057547882496?s=20"

strings:
		$ekfl = /0x19[a-z]'\),\r\n\s{4}'Gate':/
condition:
		$ekfl
}

rule ekf_web_skimmer_gmagea_28563 : sourcecode
{
meta:
		name      = "Web Skimmer (gmagea)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/killamjr/status/1185376383180136448"

strings:
		$ekfl = /function createZxCScript/
condition:
		$ekfl
}

rule ekf_web_skimmer_google_exfil_8628 : sourcecode
{
meta:
		name      = "Web Skimmer (Google exfil)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/AffableKraut/status/1362429457932419078?s=20"

strings:
		$ekfl = /'replace','IMG','CVV'/
condition:
		$ekfl
}

rule ekf_web_skimmer_google_loop_1529 : sourcecode
{
meta:
		name      = "Web Skimmer (Google loop)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/AffableKraut/status/1261157021027622912?s=20"

strings:
		$ekfl = /l1l1<userID\.length;l1l1\+\+/
condition:
		$ekfl
}

rule ekf_web_skimmer_grelos_7713 : sourcecode
{
meta:
		name      = "Web Skimmer (grelos)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/killamjr/status/1209165822939279365?s=20"

strings:
		$ekfl = /var grelos_v=/
condition:
		$ekfl
}

rule ekf_web_skimmer_hacked_site_exfil_10229 : sourcecode
{
meta:
		name      = "Web Skimmer (Hacked site exfil)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/unmaskparasites/status/1186745552358252544?s=20"

strings:
		$ekfl = /,urll,(false|true)\);/
condition:
		$ekfl
}

rule ekf_web_skimmer_hex_28675 : sourcecode
{
meta:
		name      = "Web Skimmer (Hex)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/killamjr/status/1207685407229526023?s=20"

strings:
		$ekfl = /(\\)?x62(\\)?x69(\\)?x6[cC](\\)?x6[cC](\\)?x69(\\)?x6[eE](\\)?x67/
condition:
		$ekfl
}

rule ekf_web_skimmer_image_4583 : sourcecode
{
meta:
		name      = "Web Skimmer (Image)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://blog.sucuri.net/2020/07/skimmers-in-images-github-repos.html"

strings:
		$ekfl = /let\sx\s=\sawait\sx92\.text\(\)/
condition:
		$ekfl
}

rule ekf_web_skimmer_inter_kit_32253 : sourcecode
{
meta:
		name      = "Web Skimmer (Inter kit)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /\$[sr]\.SaveAllFields\(\);\r?\n\n?\s{8}\$[sr]\.GetCCInfo\(\);/
condition:
		$ekfl
}

rule ekf_web_skimmer_jj_17572 : sourcecode
{
meta:
		name      = "Web Skimmer (_jj)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/unmaskparasites/status/1377382029709348864?s=20"

strings:
		$ekfl = /_jj\['c'\+'v'\+'v'/
condition:
		$ekfl
}

rule ekf_web_skimmer_magento_1x_3940 : sourcecode
{
meta:
		name      = "Web Skimmer (Magento 1.x)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://antoinevastel.com/fraud/2020/09/20/analyzing-magento-skimmer.html"

strings:
		$ekfl = /(\-text\/javascript">|<script>)var\sa0a=\[/
condition:
		$ekfl
}

rule ekf_web_skimmer_magento_footer_21687 : sourcecode
{
meta:
		name      = "Web Skimmer (Magento footer)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/injecting-magecart-into-magento-global-config/"

strings:
		$ekfl = /function\sFN2Z22\(\)\{var/
condition:
		$ekfl
}

rule ekf_web_skimmer_onestepcheckout_20218 : sourcecode
{
meta:
		name      = "Web Skimmer (onestepcheckout)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /window\.atob\("b25lc3RlcGNoZWNrb3V0"\)/
condition:
		$ekfl
}

rule ekf_web_skimmer_pipka_4274 : sourcecode
{
meta:
		name      = "Web Skimmer (Pipka)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://usa.visa.com/dam/VCOM/global/support-legal/documents/pfd-identifies-new-javascript-skimmer.pdf"

strings:
		$ekfl = /id=[0-9]&pipka="|'scriptId': '#script',/
condition:
		$ekfl
}

rule ekf_web_skimmer_radix_19571 : sourcecode
{
meta:
		name      = "Web Skimmer (Radix)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /0a(0w){12}/
condition:
		$ekfl
}

rule ekf_web_skimmer_social_media_7969 : sourcecode
{
meta:
		name      = "Web Skimmer (social media)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://sansec.io/research/svg-malware"

strings:
		$ekfl = /[iI]d=?\(?"(facebook|google|twitter|instagram|youtube|pinterest)_full"(\sviewbox="0\s0|\);window\.q=e)/
condition:
		$ekfl
}

rule ekf_web_skimmer_script_mage_15157 : sourcecode
{
meta:
		name      = "Web Skimmer (script mage)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /\\x22payment\[cc_exp_year\]/
condition:
		$ekfl
}

rule ekf_web_skimmer_stegano_30928 : sourcecode
{
meta:
		name      = "Web Skimmer (stegano)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/AffableKraut/status/1210298763417276416?s=20"

strings:
		$ekfl = /new\sFunction\s?\(this\.responseText\.slice\(-[0-9]{5}\)\)/
condition:
		$ekfl
}

rule ekf_web_skimmer_urllbtoa_24555 : sourcecode
{
meta:
		name      = "Web Skimmer (urllbtoa)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/killamjr/status/1212058181725114369?s=20"

strings:
		$ekfl = /url:urll,data:btoa/
condition:
		$ekfl
}

rule ekf_web_skimmer_ultrarank_2692 : sourcecode
{
meta:
		name      = "Web Skimmer (UltraRank)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://www.group-ib.com/blog/ultrarank"

strings:
		$ekfl = /var\sJ8X="M9/
condition:
		$ekfl
}

rule ekf_web_skimmer_websocket_27624 : sourcecode
{
meta:
		name      = "Web Skimmer (websocket)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /"w"\.concat\('ss', ":"\)\)/
condition:
		$ekfl
}

rule ekf_web_skimmer_generic_24931 : sourcecode
{
meta:
		name      = "Web Skimmer (generic)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /if ?\(new RegExp\(_0x[a-z0-9]{2,8}\('0x0'|gas\.src=location\.protocol\+'\/\/|L2dhdGUucGhw"\)\+"\?image_id=|\\x2C\\x62\\x75\\x74\\x74\\x6F\\x6E\\x2C\\x20\\x69\\x6E\\x70\\x75\\x74\\x2C\\x20\\x73\\x75\\x62\\x6D\\x69\\x74\\x2C/
condition:
		$ekfl
}

rule ekf_web_skimmer_gate_uri_15468 : uri
{
meta:
		name      = "Web Skimmer (gate URI)"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

condition:
		cuckoo.network.http_request(/=WyJ1cmwl/)
}

rule ekf_web_skimmer_jashkinagal_8083 : ip
{
meta:
		name      = "Web Skimmer (jashkinagal)"
		type      = "ip"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

condition:
		cuckoo.network.host(/83\.166\.244\.76/)
}

rule ekf_fakeupdates_redirection_25929 : uri
{
meta:
		name      = "FakeUpdates Redirection"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

condition:
		cuckoo.network.http_request(/\/jquery\?frm=script&se_referrer=/)
}

rule ekf_domen_soc_engineering_c2_8922 : uri
{
meta:
		name      = "Domen soc. engineering C2"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

condition:
		cuckoo.network.http_request(/\/admin\/target\?secret=\w{32}&token=\w{32}&(main|_)/)
}

rule ekf_baidu_redirect_27004 : sourcecode
{
meta:
		name      = "Baidu Redirect"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /;this\.removeEventListener\('click',arguments\.callee,false\)\}\)\}\};/
condition:
		$ekfl
}

rule ekf_compromised_site_ad_redirection_21834 : sourcecode
{
meta:
		name      = "Compromised site (ad redirection)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /script src="\/\/d3al52d8cojds7\.cloudfront\.net/
condition:
		$ekfl
}

rule ekf_compromised_wordpress_examhome_22959 : sourcecode
{
meta:
		name      = "Compromised WordPress (Examhome)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://blog.malwarebytes.com/threat-analysis/2018/09/mass-wordpress-compromises-tech-support-scams/"

strings:
		$ekfl = /eval\(String\.fromCharCode\(118,97,114,32,115,111,109,101,115,116|script src='https:\/\/(cdn.examhome\.net|ads\.voipnewswire\.net|cdn\.allyouwant\.online)/
condition:
		$ekfl
}

rule ekf_compromised_wordpress_saskmade_8254 : sourcecode
{
meta:
		name      = "Compromised WordPress (Saskmade)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /<script src='https:\/\/saskmade\.net\/head/
condition:
		$ekfl
}

rule ekf_compromised_site_crypper_4043 : sourcecode
{
meta:
		name      = "Compromised site (Crypper)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/david_jursa/status/1171030161128603649?s=20"

strings:
		$ekfl = /\|setAdsCookie\|/
condition:
		$ekfl
}

rule ekf_compromised_site_fakeupdates_31784 : sourcecode
{
meta:
		name      = "Compromised site (FakeUpdates)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/Ring0x0/status/976613052606046208"

strings:
		$ekfl = /\/jquery\?frm=script&se_referrer=/
condition:
		$ekfl
}

rule ekf_compromised_site_wp_plugins_14327 : sourcecode
{
meta:
		name      = "Compromised site (WP Plugins)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://www.wordfence.com/blog/2019/07/recent-wordpress-vulnerabilities-targeted-by-malvertising-campaign/"

strings:
		$ekfl = /105, 108, 100, 40, 115, 99, 114, 105, 112, 116, 41, 59\)\);<\/script>/
condition:
		$ekfl
}

rule ekf_fake_jquery_11274 : sourcecode
{
meta:
		name      = "Fake jquery"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/Placebo52510486/status/1141619924512792583"

strings:
		$ekfl = /src="https?:\/\/([12][26]js|1[26]lib|wp11|lib0)\.org\/jquery.js/
condition:
		$ekfl
}

rule ekf_flashoffer_6843 : sourcecode
{
meta:
		name      = "FlashOffer"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://traffic.moe/2018/03/15/index.html"

strings:
		$ekfl = /iframe src="http:\/\/'\+window\.location\.hostname\+'\/lp\/flash\/offer\.php/
condition:
		$ekfl
}

rule ekf_fobos_campaign_27032 : sourcecode
{
meta:
		name      = "Fobos Campaign"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /\+ '' \+  '(\?|&)'; ?dtw?.write\('<ifr?'\);/
condition:
		$ekfl
}

rule ekf_domen_soc_engineering_kit_31014 : sourcecode
{
meta:
		name      = "Domen soc. engineering kit"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/tkanalyst/status/1163084043832872961"

strings:
		$ekfl = /var url='\/\/'\+domen\+_0x|break;\}\}\}return\s_0x23d1ca/
condition:
		$ekfl
}

rule ekf_fake_jquery_campaign_12094 : sourcecode
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

rule ekf_lnkr_campaign_4895 : sourcecode
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

rule ekf_redirect_domen_kit_campaign_30640 : sourcecode
{
meta:
		name      = "Redirect Domen kit Campaign"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /!function\(w,d,u,n,t\)/
condition:
		$ekfl
}

rule ekf_tk_redirect_29007 : sourcecode
{
meta:
		name      = "TK Redirect"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/unmaskparasites/status/1041753812518617088"

strings:
		$ekfl = /var x = asdasq3hgvb\('pp0000011'\);|<meta http-equiv="refresh" content="0; URL=http:\/\/([a-z0-9]{2,25}\.){2}(info|stream)"> <\/p>/
condition:
		$ekfl
}

rule ekf_socialwarfare_campaign_18095 : sourcecode
{
meta:
		name      = "SocialWarfare Campaign"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://blog.sucuri.net/2019/03/zero-day-stored-xss-in-social-warfare.html"

strings:
		$ekfl = /"\\x73\\x6C\\x69\\x63\\x65","\\x30\\x30"/
condition:
		$ekfl
}

rule ekf_crypper_campaign_5955 : headers
{
meta:
		name      = "Crypper Campaign"
		type      = "headers"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /00831=%7B/
condition:
		$ekfl
}

rule ekf_malcdn_campaign_11549 : headers
{
meta:
		name      = "Malcdn Campaign"
		type      = "headers"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /9d5e3=eyJ/
condition:
		$ekfl
}

rule ekf_grandsoft_ek_10168 : uri
{
meta:
		name      = "GrandSoft EK"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/kafeine/status/958298409944920064"

condition:
		cuckoo.network.http_request(/\.(tk|xyz|info|space|website|site|host|fun)\/9\/[0-9]{5,7}$|getversoinpd\/1\/2\/3\/4$/)
}

rule ekf_kaixin_ek_19105 : uri
{
meta:
		name      = "KaiXin EK"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

condition:
		cuckoo.network.http_request(/\/hfs\/(cookie_do\.swf|\w{6}\.jar|swfobject\.js|jquery\.js)/)
}

rule ekf_magnigatemagnitude_ek_5166 : uri
{
meta:
		name      = "Magnigate/Magnitude EK"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://malware.dontneedcoffee.com/2018/03/CVE-2018-4878.html"
		comment   = "the regex uses negative lookahead"

condition:
		cuckoo.network.http_request(/http:\/\/((.*\d){4})(.*[a-zA-Z])[0-9a-zA-Z!@#$%]{8,}\.[a-z]{6,7}\.[a-z]{3,15}\/$/)
}

rule ekf_purple_fox_ek_8542 : uri
{
meta:
		name      = "Purple Fox EK"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"
		comment   = "the regex uses negative lookahead"

condition:
		cuckoo.network.http_request(/http(s|):\/\/[^.]([a-z0-9-]+\.){3}[a-z]{2,7}\/((crypto-js|zepto|aes|base64)\.min\.js|dl\.php\?key=[0-9])/)
}

rule ekf_purple_fox_ek_landing_31288 : uri
{
meta:
		name      = "Purple Fox EK (Landing)"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"
		comment   = "the regex uses negative lookahead"

condition:
		cuckoo.network.http_request(/http(s|):\/\/[^.]([a-z0-9-]+\.){3}[a-z]{2,7}\/(\?key=[0-9A-Z]{16}|base64\.min\.js|[0-9]\.jpg|[a-z]{3,5}\.swf)/)
}

rule ekf_purple_fox_ek_payload_29847 : uri
{
meta:
		name      = "Purple Fox EK (Payload)"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

condition:
		cuckoo.network.http_request(/(rawcdn\.githack\.cyou\/(up\.php\?key=[0-9]|M00[0-9]{2}\.cab)|\.club\/\?key=[0-9A-Z]{16})/)
}

rule ekf_rig_ek_9251 : uri
{
meta:
		name      = "RIG EK"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/baberpervez2"

condition:
		cuckoo.network.http_request(/https?:\/\/[^\x3f]+\/\x3f[^\x3f]+Q[cdM][_fPrv][bDfLPTWXjn][acdefYZVUb][abKLJ][^\n]+/)
}

rule ekf_router_ek_28977 : uri
{
meta:
		name      = "Router EK"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/david_jursa/status/1111311144642404352"

condition:
		cuckoo.network.http_request(/https?:\/\/((192\.168\.([0-9]|[0-9][0-9]|[0-2][0-5][0-9])\.([0-9]|[0-9][0-9]|[0-2][0-9][0-9])\/)|(172\.([1][6-9]|[2][0-9]|[3][0-1])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-9][0-9])\/)|(10\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-9][0-9])\/|127.0.0.1\/))((userRpm\/|cgi-bin\/prim|form2Wan|form2Dhcpd)|(\?cache=[0-9]{13}$))/)
}

rule ekf_spelevo_ek_4067 : uri
{
meta:
		name      = "Spelevo EK"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/kafeine/status/1103649040800145409"
		comment   = "the regex uses negative lookahead"

condition:
		cuckoo.network.http_request(/https?:\/\/[^.]([a-z0-9-]+\.){2}(xyz|top|icu|info|site|monster|guru)\/[0-9][a-z0-9]{12}\/\?[a-z0-9]+[a-z]/)
}

rule ekf_underminer_ek_5994 : uri
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

rule ekf_capesand_ek_redirection_13934 : sourcecode
{
meta:
		name      = "Capesand EK redirection"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/new-exploit-kit-capesand-reuses-old-and-new-public-exploits-and-tools-blockchain-ruse/"

strings:
		$ekfl = /%31%39%38%2E%31%39%39%2E%31%30%34%2E%38%2F%6C%61%6E%64%69%6E%67%2E%70%68%70%/
condition:
		$ekfl
}

rule ekf_capesand_ek_22347 : sourcecode
{
meta:
		name      = "Capesand EK"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /<!-- Have Fun -->\r\n<script type="text\/javascript">var \w{3} = ""; /
condition:
		$ekfl
}

rule ekf_fallout_ek_24298 : sourcecode
{
meta:
		name      = "Fallout EK"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /[Il1]{4,20}\['[Il1]{4,20}'\] = '@@'\['[Il1]{4,20}']\(\);|window(\["[Il1]{4,20}"\]){4}\("[a-z0-9]{32}"\);/
condition:
		$ekfl
}

rule ekf_grandsoft_ek_7577 : sourcecode
{
meta:
		name      = "GrandSoft EK"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/kafeine/status/958298409944920064"

strings:
		$ekfl = /(document\.write\("<iframe src='"\+srcOfScript\+"'><\/iframe>"\);<\/script>|trifix = zerofix & zerofix & zerofix)/
condition:
		$ekfl
}

rule ekf_kaixin_ek_25693 : sourcecode
{
meta:
		name      = "KaiXin EK"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /;[a-z]\s[a-zA-Z0-9]{1,2}=new\s[a-z]\["\\\\[a-z]\\\\[a-z]\\\\[a-z]\\\\[a-z]\\\\x79"\]/
condition:
		$ekfl
}

rule ekf_purple_fox_ek_15692 : sourcecode
{
meta:
		name      = "Purple Fox EK"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/purple-fox-fileless-malware-with-rookit-component-delivered-by-rig-exploit-kit-now-abuses-powershell/"

strings:
		$ekfl = /<embed\swidth=80\sheight=1\ssrc=image\.php\?key=\w{16}\s/
condition:
		$ekfl
}

rule ekf_radio_ek_18876 : sourcecode
{
meta:
		name      = "Radio EK"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://nao-sec.org/2019/07/weak-dbd-attack-with-radioek.html"

strings:
		$ekfl = /\[System\.IO\.Path\]::GetTempPath\(\)\+'[a-z]{3,20}\.exe';Start-Process \$local_path2"/
condition:
		$ekfl
}

rule ekf_novidade_ek_16864 : sourcecode
{
meta:
		name      = "Novidade EK"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /%31%39%32%2E%31%36%38%2E%30%2E%31%|MTkyLjE2OC4wLjE=|MTAuMC4wLjE=|Launch\("gerar\.php\?ip=/
condition:
		$ekfl
}

rule ekf_spelevo_ek_6028 : sourcecode
{
meta:
		name      = "Spelevo EK"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /\s{5}\tvar p = '\w{50}/
condition:
		$ekfl
}

rule ekf_underminer_ek_22770 : sourcecode
{
meta:
		name      = "Underminer EK"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /src="\/js\/((.*\d){4})[a-z0-9]{26}\.js"><\/script>|TinyJSLibrary\.enc\.Hex\.parse\('[a-z0-9]{32}'\)\)\.toString\(TinyJSLibrary\.enc\.Utf8\)\);/
condition:
		$ekfl
}

rule ekf_greenflash_sundown_ek_6001 : headers
{
meta:
		name      = "GreenFlash Sundown EK"
		type      = "headers"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /ETag: "5a0c76d6-117"/
condition:
		$ekfl
}

rule ekf_fallout_ek_13836 : headers
{
meta:
		name      = "Fallout EK"
		type      = "headers"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /User-Agent: \b(.*[0-9])(.*[A-Z])\w{16}\r\n/
condition:
		$ekfl
}

rule ekf_cve_2018_4878_artifact_25957 : uri
{
meta:
		name      = "CVE-2018-4878 Artifact"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

condition:
		cuckoo.network.http_request(/individualization\.adobe\.com\/(crossdomain\.xml|flashaccess\/i15n\/v5)/)
}

rule ekf_cve_2014_6332_10637 : sourcecode
{
meta:
		name      = "CVE-2014-6332"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /myarray%3D%20%20%20%20%20%20%20%20chrw%2801%29%26chrw%282176%/
condition:
		$ekfl
}

rule ekf_cve_2016_0189_19305 : sourcecode
{
meta:
		name      = "CVE-2016-0189"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://github.com/theori-io/cve-2016-0189"

strings:
		$ekfl = /return String\.fromCharCode\(x & 0xffff\) \+ String\.fromCharCode\(x >> 16\);/
condition:
		$ekfl
}

rule ekf_cve_2018_8174_11277 : sourcecode
{
meta:
		name      = "CVE-2018-8174"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://www.exploit-db.com/exploits/44741/"

strings:
		$ekfl = /Dim (IIIlI|arr1)\(6\),(IllII|arr2)\(6\)|\(\w+\+&h174\) = temp\(0\)/
condition:
		$ekfl
}

rule ekf_cve_2018_8373_17384 : sourcecode
{
meta:
		name      = "CVE-2018-8373"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /ReDim Preserve array\(100000\)|\(index_vul\)\(index_a,0\)="AAAA"|VirtualProtectAddrFake%3DGetMemValue%28%29\+69596/
condition:
		$ekfl
}

rule ekf_fakecertificate_redirect_27059 : uri
{
meta:
		name      = "FakeCertificate Redirect"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://securelist.com/mokes-and-buerak-distributed-under-the-guise-of-security-certificates/96324/"

condition:
		cuckoo.network.http_request(/M2&ts=MTU/)
}

rule ekf_fakeupdates_redirection_8240 : uri
{
meta:
		name      = "FakeUpdates (Redirection)"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "http://www.broadanalysis.com/2018/03/03/fake-flash-and-chrome-updates-lead-to-ramnit-trojan/"

condition:
		cuckoo.network.http_request(/\/([a-z0-9]{70}|s_code\.js)\?cid=[0-9]{3}&(session=[a-z0-9]{32}|v=[a-z0-9]{20})/)
}

rule ekf_fakeupdates_template_30029 : uri
{
meta:
		name      = "FakeUpdates (Template)"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"
		comment   = "the regex uses negative lookahead"

condition:
		cuckoo.network.http_request(/http:\/\/[^.]([a-z0-9-]+\.){2}[a-z]{2,7}\/(browserfiles\/((css.css$)|(img|logo|fonts|favicon)\/)|topics\/index\.php\?n=[0-9]{6}&o=)/)
}

rule ekf_flashoffer_31656 : uri
{
meta:
		name      = "FlashOffer"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://traffic.moe/2018/03/15/index.html"

condition:
		cuckoo.network.http_request(/\/lp\/flash\/offer\.php/)
}

rule ekf_fakeadobeflash_18740 : uri
{
meta:
		name      = "FakeAdobeFlash"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/baberpervez2"

condition:
		cuckoo.network.http_request(/https?:\/\/[^\x3f]+\/(\x3f(dfgh=|pcl=|51tga=)|(zzz\x3f))[^\x3f]+(&cid=|&sid=)[^\n]+$|\x3f[^\x3f]+(..&cid=)?[^\x3f]+(&(sid|SUB_ID|sub|payout)=)[^\x3f]+(&v_id=)[^\x3f]+$/)
}

rule ekf_fakebrowserupdate_10661 : uri
{
meta:
		name      = "FakeBrowserUpdate"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://blog.sucuri.net/2019/02/fake-browser-updates-push-ransomware-and-bank-malware.html"

condition:
		cuckoo.network.http_request(/wibeee\.com\.ua|kompleks-ohoroni\.kiev\.ua|quoidevert\.com/)
}

rule ekf_tss_browlock_gen_11328 : uri
{
meta:
		name      = "TSS (Browlock gen)"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

condition:
		cuckoo.network.http_request(/\/((\?number=|(AT-|)TollFree(-|))((1-)?8[0-9]{2}-[0-9]{3}-[0-9]{4}|([0-9]{2}-){4}[0-9]{2}&)|\?a=[0-9]{4}&source=[0-9]{5}_[0-9]{5})/)
}

rule ekf_tss_forced_login_31510 : uri
{
meta:
		name      = "TSS (forced login)"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

condition:
		cuckoo.network.http_request(/\.club\/newauth\/\w+\/auth\.php/)
}

rule ekf_tss_woof_browlock_848 : uri
{
meta:
		name      = "TSS (WOOF browlock)"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

condition:
		cuckoo.network.http_request(/\/en\/\?search=\w?(%[\w_\-~\.]{1,4}){10,20}&list=([0-9]00000|null)$|api\.imagecloudsedo\.com/)
}

rule ekf_fakecertificate_campaign_25180 : sourcecode
{
meta:
		name      = "FakeCertificate Campaign"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /\[0\].appendChild\(jspp22\);|\/\/chrome\.html\\">"\s\+\s"<\/frameset>";|IaNeUmeiuVNaming/
condition:
		$ekfl
}

rule ekf_fakeflash_7229 : sourcecode
{
meta:
		name      = "FakeFlash"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /alert\("WARNING! Your Flash Player is out of date\. |src="http:\/\/byte\.wo\.tc\/js\/lib\/js\.js">/
condition:
		$ekfl
}

rule ekf_fakenotification_28418 : sourcecode
{
meta:
		name      = "FakeNotification"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/benkow_/status/1265254805422788609"

strings:
		$ekfl = /\s{4}showpopup\(exelink,\s[0-9]000,\s[0-9]000,\s[0-9]000\)/
condition:
		$ekfl
}

rule ekf_fakeupdates_campaign_hacked_site_9512 : sourcecode
{
meta:
		name      = "FakeUpdates Campaign (Hacked Site)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://blog.malwarebytes.com/threat-analysis/2018/04/fakeupdates-campaign-leverages-multiple-website-platforms/"

strings:
		$ekfl = /;\(function\(\)\{var [a-z]=navigator\[[a-z]\("/
condition:
		$ekfl
}

rule ekf_fakeupdates_js_download_10304 : sourcecode
{
meta:
		name      = "FakeUpdates (JS download)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /var filename = 'Chrome\.Update\./
condition:
		$ekfl
}

rule ekf_fakeupdates_possible_variant_23436 : sourcecode
{
meta:
		name      = "FakeUpdates (possible variant)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/baberpervez2"

strings:
		$ekfl = /src(\x3d)[ep](\x28)(\x27).+(\x3f).+(\x27)(\x29)/
condition:
		$ekfl
}

rule ekf_tss_browlock_gen_17503 : sourcecode
{
meta:
		name      = "TSS (Browlock gen)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /\\nRDN\/YahLover|.\\n\\nToll Free:" \+ phone|function bomb_ch() \{/
condition:
		$ekfl
}

rule ekf_tk_redirection_6259 : sourcecode
{
meta:
		name      = "TK (redirection)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /(<script>window\.location\.replace\("|u=)http:\/\/[a-z-]{3,20}\.tk\/index\/\?[0-9]{13}|function createCookie13123213\(e,o,r\)/
condition:
		$ekfl
}

rule ekf_tss_forced_login_27773 : sourcecode
{
meta:
		name      = "TSS (forced login)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /<iframe height="1" src="login\.php|ifr\.src = 'https?:\/\/\w+\.club\/newauth\/\w+\/auth\.php/
condition:
		$ekfl
}

rule ekf_tss_tfn_19392 : sourcecode
{
meta:
		name      = "TSS (TFN)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /(\+1)?(-[0-9]{3}){2}-[0-9]{4}(\\n){30}/
condition:
		$ekfl
}

rule ekf_tss_audio_30535 : sourcecode
{
meta:
		name      = "TSS (audio)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /\.mp3" allow="autoplay" style="display:none;"/
condition:
		$ekfl
}

rule ekf_tss_dynumber_18034 : sourcecode
{
meta:
		name      = "TSS (dynumber)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /class="lokacioni3"/
condition:
		$ekfl
}

rule ekf_tss_evil_cursor_6813 : sourcecode
{
meta:
		name      = "TSS (evil cursor)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /\) 128 128, crosshair;/
condition:
		$ekfl
}

rule ekf_tss_stroka_template_29766 : sourcecode
{
meta:
		name      = "TSS (stroka template)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /var stroka = "<tr><td valign/
condition:
		$ekfl
}

rule ekf_tss_fake_dialog_21311 : sourcecode
{
meta:
		name      = "TSS (fake dialog)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /Prevent additional dialogues\.<\/label>/
condition:
		$ekfl
}

rule ekf_tss_woof_browlock_26406 : sourcecode
{
meta:
		name      = "TSS (WOOF browlock)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /unescape\(_OIEq|function _WOOf/
condition:
		$ekfl
}

rule ekf_tss_browlock_audio_31472 : hash
{
meta:
		name      = "TSS Browlock (audio)"
		type      = "hash"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

condition:
		hash.sha256(0, filesize) == "0589be7715d2320e559eae6bd26f3528e97450c70293da2e1e8ce45f77f99ab1" or
		hash.sha256(0, filesize) == "fc59bbb18f923747b9cd3f3b23537ff09c5ad2fdfc1505a4800a3f269a234e65" or
		hash.sha256(0, filesize) == "d6e8aff6202436d3d2c56f686ad04680f2e5afd6ac0e1e0911772e28f2471ad2"
}

rule ekf_chalbhai_phish_27455 : sourcecode
{
meta:
		name      = "Chalbhai Phish"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /name=chalbhai id=chalbhai method=post/
condition:
		$ekfl
}

rule ekf_baldr_c2_2235 : uri
{
meta:
		name      = "Baldr C2"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

condition:
		cuckoo.network.http_request(/\/baldr\/gate\.php\?hwid=/)
}

rule ekf_fakeupdates_c2_callback_and_payload_20672 : uri
{
meta:
		name      = "FakeUpdates C2 (Callback and payload)"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

condition:
		cuckoo.network.http_request(/\w{8}\.user3\.altcoinfan\.com\/1x1\.gif/)
}

rule ekf_raccoonstealer_c2_5170 : uri
{
meta:
		name      = "RaccoonStealer C2"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

condition:
		cuckoo.network.http_request(/http(s|):\/\/(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\/(gate\/(log\.php|sqlite3.dll|libs.zip)$|file_handler\/file\.php\?hash=)/)
}

rule ekf_icedid_c2_16523 : uri
{
meta:
		name      = "IcedID C2"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

condition:
		cuckoo.network.http_request(/index.php\?z=JmE9MjA0NDA|\/photo.png\?id=[A-Z0-9]{38}|\/data3.php\?[A-Z0-9]{16}/)
}

rule ekf_predator_the_thief_c2_15333 : uri
{
meta:
		name      = "Predator the Thief C2"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://fumik0.com/2018/10/15/predator-the-thief-in-depth-analysis-v2-3-5/"

condition:
		cuckoo.network.http_request(/\/gate\.get\?p1=[0-9](&p[0-9]=[0-9]{1,2}){8}/)
}

rule ekf_zloader_c2_23385 : ip
{
meta:
		name      = "Zloader C2"
		type      = "ip"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

condition:
		cuckoo.network.host(/45\.72\.3\.132/)
}

rule ekf_kpot_stealer_c2_20584 : uri
{
meta:
		name      = "KPOT Stealer C2"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

condition:
		cuckoo.network.http_request(/\/(.*[A-Z])(.*[a-z])(.*[0-9]).{16}\/conf\.php/)
}

rule ekf_gootkit_template_7974 : sourcecode
{
meta:
		name      = "Gootkit (template)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "https://twitter.com/ffforward/status/1331371583890485257?s=20"

strings:
		$ekfl = /else\s\{\sremove\(document\.all\[i\]\);\}\s\}\sdocument\.body\.innerHTML\s=\s'<html><head><title>/
condition:
		$ekfl
}

rule ekf_vidar_library_28826 : uri
{
meta:
		name      = "Vidar Library"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

condition:
		cuckoo.network.http_request(/(\.ac)?\.ug\/\w+\.dll($|\?ddosprotected)/)
}

rule ekf_vidar_profile_11491 : sourcecode
{
meta:
		name      = "Vidar Profile"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

strings:
		$ekfl = /(1|0|,){20}250,(Default|Desktop);%DESKTOP%\\;\*\.txt/
condition:
		$ekfl
}

rule ekf_network_fingerprinting_26891 : uri
{
meta:
		name      = "Network fingerprinting"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

condition:
		cuckoo.network.http_request(/ip-api\.com\/|iplogger\.(org|com)\/|extreme-ip-lookup\.com/)
}

rule ekf_local_ip_6328 : uri
{
meta:
		name      = "Local IP"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2021-10-07"
		reference = "none"

condition:
		cuckoo.network.http_request(/https?:\/\/((192\.168\.([0-9]|[0-9][0-9]|[0-2][0-5][0-9])\.([0-9]|[0-9][0-9]|[0-2][0-9][0-9])\/)|(172\.([1][6-9]|[2][0-9]|[3][0-1])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-9][0-9])\/)|(10\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-5][0-5])\.([0-9]|[0-9][0-9]|[0-2][0-9][0-9])\/|127.0.0.1\/))/)
}

