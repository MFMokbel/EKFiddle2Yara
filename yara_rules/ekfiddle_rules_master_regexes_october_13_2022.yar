// Retrieved on 2022-10-13; 06:01:37 PM
// Total number of parsed rules: 75

import "hash"

rule ekf_fakeupdatessocgholish_hacked_site_15211 : sourcecode
{
meta:
		name      = "FakeUpdates/SocGholish (hacked site)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://blog.malwarebytes.com/threat-analysis/2018/04/fakeupdates-campaign-leverages-multiple-website-platforms/"

strings:
		$ekfl = /src=\w{2}\('\w{11}\:\w\/\w\//
condition:
		$ekfl
}

rule ekf_fakeupdatessocgholish_domain_shadowing_4878 : uri
{
meta:
		name      = "FakeUpdates/SocGholish (domain shadowing)"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://blog.malwarebytes.com/threat-analysis/2018/04/fakeupdates-campaign-leverages-multiple-website-platforms/"

strings:
		$ekfl = /report\?r=dj\w+ZjaWQ9Mj|report\?r=Y2lkPTI(1|2)(M|O)/
condition:
		$ekfl
}

rule ekf_fakeupdatessocgholish_theme_15856 : uri
{
meta:
		name      = "FakeUpdates/SocGholish (theme)"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"
		comment   = "the regex uses negative lookahead"

strings:
		$ekfl = /http(s|):\/\/[^.]([a-z0-9]+\.){2}[a-z]{2,7}\/updateassets\//
condition:
		$ekfl
}

rule ekf_gootloader_hacked_site_29204 : sourcecode
{
meta:
		name      = "Gootloader (hacked site)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://news.sophos.com/en-us/2021/08/12/gootloaders-mothership-controls-malicious-content/"

strings:
		$ekfl = /document\[\w{3,15}\[3\]\]=document\[\w{3,15}\[6\]\]\(\w{3,15}\[13\]\);/
condition:
		$ekfl
}

rule ekf_gootloader_payload_6333 : uri
{
meta:
		name      = "GootLoader (payload)"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /\/forum\.php\?[a-z]{3,15}=[a-z]{3,15}&[a-z]{3,20}=(.*[0-9])\w{50,200}&/
condition:
		$ekfl
}

rule ekf_fakecloudflare_30521 : sourcecode
{
meta:
		name      = "FakeCloudFlare"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://blog.sucuri.net/2022/08/fake-ddos-pages-on-wordpress-lead-to-drive-by-downloads.html"

strings:
		$ekfl = /domnamer\+add_knileds|location.replace\(zliker\)/
condition:
		$ekfl
}

rule ekf_parrot_tds_ndsw_20817 : sourcecode
{
meta:
		name      = "Parrot TDS (NDSW)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://blog.sucuri.net/2022/06/analysis-massive-ndsw-ndsx-malware-campaign.html"

strings:
		$ekfl = /\(nds(w|j)===undefined\)/
condition:
		$ekfl
}

rule ekf_fake_jquery_campaign_23442 : sourcecode
{
meta:
		name      = "Fake jQuery Campaign"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://blog.sucuri.net/2017/04/wordpress-security-unwanted-redirects-via-infected-javascript-files.html"

strings:
		$ekfl = /\\x73\\x6A\\x2E\\x79\\x72\\x65\\x75\\x71\\x6A\\x2/
condition:
		$ekfl
}

rule ekf_lnkr_campaign_18337 : sourcecode
{
meta:
		name      = "LNKR Campaign"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/baberpervez2/status/1194090555468394496?s=20"

strings:
		$ekfl = /lat\?jsonp=__[a-z]{3}_cb_[0-9]{9}&(#|amp)|addons\/lnkr30_nt\.min\.js/
condition:
		$ekfl
}

rule ekf_tss_9650 : sourcecode
{
meta:
		name      = "(TSS)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /getElementById\("warning"\)\.play\(\);\},10\);/
condition:
		$ekfl
}

rule ekf_tss_doubleclick_7350 : uri
{
meta:
		name      = "TSS (DoubleClick)"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /\/erxczzx/
condition:
		$ekfl
}

rule ekf_magecart_qlogger_23601 : sourcecode
{
meta:
		name      = "Magecart (Q_logger)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/AffableKraut/status/1385030485676544001?s=20"

strings:
		$ekfl = /var\s\w=\{isOpen:!1,orientation:void\s0,detectInterval:null\}/
condition:
		$ekfl
}

rule ekf_magecart_google_loop_26522 : sourcecode
{
meta:
		name      = "Magecart (Google loop)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/AffableKraut/status/1261157021027622912?s=20"

strings:
		$ekfl = /l1l1<userID\.length;l1l1\+\+/
condition:
		$ekfl
}

rule ekf_magecart_coffemokkogroup8_385 : sourcecode
{
meta:
		name      = "Magecart (CoffeMokko/Group8)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://blog.group-ib.com/coffemokko"

strings:
		$ekfl = /lmcScr\("screen-obj"|lmcScr\(_\$_|\/a\/g,_\$_\w{4}\[\d{2}\]\);(_0x\w{3,6}=\s_0x\w{3,6}|\w=\s?\w)\[_\$_\w{4}\[\d{2}\]\]\(\/h\/g,_\$_/
condition:
		$ekfl
}

rule ekf_magecart_fakeclicky_29275 : sourcecode
{
meta:
		name      = "Magecart (FakeClicky)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/GroupIB_GIB/status/1185237251762069504?s=20"

strings:
		$ekfl = /=','script','Y2hlY2tvdXQ=',/
condition:
		$ekfl
}

rule ekf_magecart_radix_19277 : sourcecode
{
meta:
		name      = "Magecart (Radix)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://blog.sucuri.net/2019/03/more-on-dnsden-biz-swipers-and-radix-obfuscation.html"

strings:
		$ekfl = /0a(0w){12}/
condition:
		$ekfl
}

rule ekf_magecart_svg_18534 : sourcecode
{
meta:
		name      = "Magecart (svg)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://sansec.io/research/svg-malware"

strings:
		$ekfl = /[iI]d=?\(?"(facebook|google|twitter|instagram|youtube|pinterest)_full"(\sviewbox="0\s0|\);window\.q=e)/
condition:
		$ekfl
}

rule ekf_magecart_shell_23034 : sourcecode
{
meta:
		name      = "Magecart (shell)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://blog.malwarebytes.com/cybercrime/2021/05/newly-observed-php-based-skimmer-shows-ongoing-magecart-group-12-activity/"

strings:
		$ekfl = /\$AJegUupT=/
condition:
		$ekfl
}

rule ekf_magecart_magento_footer_26769 : sourcecode
{
meta:
		name      = "Magecart (Magento footer)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/injecting-magecart-into-magento-global-config/"

strings:
		$ekfl = /function\sFN2Z22\(\)\{var/
condition:
		$ekfl
}

rule ekf_magecart_grelos_6401 : sourcecode
{
meta:
		name      = "Magecart (grelos)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/killamjr/status/1209165822939279365?s=20"

strings:
		$ekfl = /var grelos_v=/
condition:
		$ekfl
}

rule ekf_magecart_bom_16516 : sourcecode
{
meta:
		name      = "Magecart (Bom)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://community.riskiq.com/article/743ea75b"

strings:
		$ekfl = /,urll,true\)|;urll=\s_0x|\];function\sboms?\(\)|stats:btoa\(_0x|\]\](\(|=\s)_0x\w{1,8}(\[\d{1,2}\]|\))\}\}\}setInterval\(/
condition:
		$ekfl
}

rule ekf_magecart_bom_hacked_sited_30517 : sourcecode
{
meta:
		name      = "Magecart (Bom hacked sited)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /\/js\/prototype\/form\.js"><\/script><\/head>/
condition:
		$ekfl
}

rule ekf_magecart_57_gateways_1124 : sourcecode
{
meta:
		name      = "Magecart (57 gateways)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://sansec.io/research/polymorphic-skimmer-57-payment-gateways"

strings:
		$ekfl = /'1f1612164c041c515b1509011f0d03',\s'13101206530e1946'/
condition:
		$ekfl
}

rule ekf_magecart_fake_slideshow_24125 : sourcecode
{
meta:
		name      = "Magecart (fake slideshow)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/AffableKraut/status/1445043970283905024?s=20"

strings:
		$ekfl = /\['105O110O112O117O116O','115O101O108O101O99O116O'/
condition:
		$ekfl
}

rule ekf_magecart_recaptcha_19700 : sourcecode
{
meta:
		name      = "Magecart (recaptcha)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/sansecio/status/1445747878404583430?s=20"

strings:
		$ekfl = /window\["JSON"\]\["parse"\]\(window\["atob"\]\(\w{3,8}\.\w{3,8}\)\);/
condition:
		$ekfl
}

rule ekf_magecart_jquers_19135 : sourcecode
{
meta:
		name      = "Magecart (jquers)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/jeromesegura/status/1137087208630833152?s=20"

strings:
		$ekfl = /localStorage.removeItem\('__'\+s1\+'123'\)/
condition:
		$ekfl
}

rule ekf_magecart_magento_1x_30588 : sourcecode
{
meta:
		name      = "Magecart (Magento 1.x)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://antoinevastel.com/fraud/2020/09/20/analyzing-magento-skimmer.html"

strings:
		$ekfl = /(\-text\/javascript">|<script>)var\sa0a=\[/
condition:
		$ekfl
}

rule ekf_magecart_infowars_13080 : sourcecode
{
meta:
		name      = "Magecart (infowars)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://gist.github.com/gwillem/ddaa24b0987401d5a8d9cdcf6c5c30a2"

strings:
		$ekfl = /var\sKKbVWE/
condition:
		$ekfl
}

rule ekf_magecart_inter_kit_24126 : sourcecode
{
meta:
		name      = "Magecart (Inter kit)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://community.riskiq.com/article/30f22a00"

strings:
		$ekfl = /GetCCInfo:(\s|)function\(\)/
condition:
		$ekfl
}

rule ekf_magecart_img_6287 : sourcecode
{
meta:
		name      = "Magecart (img)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://blog.sucuri.net/2017/01/database-and-image-tricks-in-magento-malware.html"

strings:
		$ekfl = /http\.send\("data="\+snd\+"&asd="\+asd\);/
condition:
		$ekfl
}

rule ekf_magecart_group3_30017 : sourcecode
{
meta:
		name      = "Magecart (Group3)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://community.riskiq.com/projects/48b09759-49f9-c1a9-d1bb-dee04ae6155e"

strings:
		$ekfl = /\\x73\\x65\\x74\\x69\\x64\\x64/
condition:
		$ekfl
}

rule ekf_magecart_mrsniffa_16231 : sourcecode
{
meta:
		name      = "Magecart (mr.Sniffa)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/MBThreatIntel/status/1268982125543387136?s=20"

strings:
		$ekfl = /var\seventsListenerPool\s=\sdocument.createElement\('script'\);/
condition:
		$ekfl
}

rule ekf_magecart_heroku_30389 : sourcecode
{
meta:
		name      = "Magecart (Heroku)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://blog.malwarebytes.com/web-threats/2019/12/theres-an-app-for-that-web-skimmers-found-on-paas-heroku/"

strings:
		$ekfl = /!function\(e,n,i\)\{function\st/
condition:
		$ekfl
}

rule ekf_magecart_shoplift_11324 : sourcecode
{
meta:
		name      = "Magecart (shoplift)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://www.foregenix.com/blog/credit-card-hijack-magento-javascript-alert"

strings:
		$ekfl = /\+inp\[i\]\.value\+['"]&['"]/
condition:
		$ekfl
}

rule ekf_magecart_magentocore_25411 : sourcecode
{
meta:
		name      = "Magecart (magentocore)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://sansec.io/research/magentocore.net-skimmer-most-aggressive-to-date"

strings:
		$ekfl = /check_check_lol\(\)/
condition:
		$ekfl
}

rule ekf_magecart_clcl_14734 : sourcecode
{
meta:
		name      = "Magecart (clcl)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/rootprivilege/status/1326231381169512450?s=20"

strings:
		$ekfl = /onchange","clcl\(\)"\);/
condition:
		$ekfl
}

rule ekf_magecart_lilskimmer_32253 : sourcecode
{
meta:
		name      = "Magecart (lilskimmer)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://blog.malwarebytes.com/threat-intelligence/2021/06/lil-skimmer-the-magecart-impersonator/"

strings:
		$ekfl = /=\s\["change",\s"\[name=cc_cvv2\]",/
condition:
		$ekfl
}

rule ekf_magecart_save_img_28269 : sourcecode
{
meta:
		name      = "Magecart (save img)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /dG9rZW58c2VhcmNofGNzZnJ8a2V5d29yZHxidXR0b24/
condition:
		$ekfl
}

rule ekf_magecart_ccnumber_26840 : sourcecode
{
meta:
		name      = "Magecart (cc_number)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /(\\)?x63(\\)?x63(\\)?x5[fF](\\)?x6E(\\)?x75(\\)?x6[dD](\\)?x62(\\)?x65(\\)?x72/
condition:
		$ekfl
}

rule ekf_magecart_ctrlshifti_18326 : sourcecode
{
meta:
		name      = "Magecart (ctrlshifti)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /ctrlu=!\[\],ctrlshifti=!\[\]/
condition:
		$ekfl
}

rule ekf_magecart_showmy_28107 : sourcecode
{
meta:
		name      = "Magecart (showmy)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /var\ssf_gate='aHR0/
condition:
		$ekfl
}

rule ekf_magecart_cvv_28304 : sourcecode
{
meta:
		name      = "Magecart (cvv)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /Cvv:jQuery\(document\[_\$_/
condition:
		$ekfl
}

rule ekf_magecart_obj31337_8711 : sourcecode
{
meta:
		name      = "Magecart (obj_31337)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://lukeleal.com/research/posts/magento2-payprocess-obj_31337-skimmer/"

strings:
		$ekfl = /obj_31337\['dbg_addr'\]|function\scalled_outside_ready/
condition:
		$ekfl
}

rule ekf_magecart_woocommerce_fake_form_30336 : sourcecode
{
meta:
		name      = "Magecart (WooCommerce fake form)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://blog.sucuri.net/2021/11/woocommerce-skimmer-spoofs-checkout-page.html"

strings:
		$ekfl = /_dc_gtm_UA-180-9/
condition:
		$ekfl
}

rule ekf_magecart_fake_hotjarfirebase_loader_15340 : sourcecode
{
meta:
		name      = "Magecart (fake hotjar/firebase loader)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/unmaskparasites/status/1457896674374815750?s=20"

strings:
		$ekfl = /includes\(atob\([a-z]\._hj\.svhj\)\);/
condition:
		$ekfl
}

rule ekf_magecart_tagmanager_13519 : sourcecode
{
meta:
		name      = "Magecart (tagmanager)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://geminiadvisory.io/magecart-google-tag-manager/"

strings:
		$ekfl = /(typeof\s\$s!==a0_0x\w{6}\((0x\w{1,5},){3}0x\w{1,5}\)&&\(\$s\[a0_0x)|(window\[a0_0x\w{3,12}\((0x\w{2,6},){3}(0x\w{2,6})\)\]\)\)new\sself)/
condition:
		$ekfl
}

rule ekf_magecart_tagmanager_source_31140 : sourcecode
{
meta:
		name      = "Magecart (tagmanager source)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /\\"\smethod\\\\x3d\\"POST\\"/
condition:
		$ekfl
}

rule ekf_magecart_webtemplatedelivr_15321 : sourcecode
{
meta:
		name      = "Magecart (webtemplatedelivr)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /=\["\\x77\\x74\\x66"/
condition:
		$ekfl
}

rule ekf_magecart_obfu_9609 : sourcecode
{
meta:
		name      = "Magecart (obfu)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/MBThreatIntel/status/1489007692240752641?s=20&t=TuI6YgI7A-PhCFlkKYYBsQ"

strings:
		$ekfl = /\\x20Card\\x20Nu'\+/
condition:
		$ekfl
}

rule ekf_magecart_woff_28735 : sourcecode
{
meta:
		name      = "Magecart (woff)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://blog.sucuri.net/2022/02/woocommerce-skimmer-uses-fake-fonts-and-favicon-to-steal-cc-details.html"

strings:
		$ekfl = /g0\.ok/
condition:
		$ekfl
}

rule ekf_magecart_css_28349 : sourcecode
{
meta:
		name      = "Magecart (css)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/AvastThreatLabs/status/1496428689944371202"

strings:
		$ekfl = /\}(\t){3}\n(\t){2}\s(\t){2}(\n){2}\t\n\t/
condition:
		$ekfl
}

rule ekf_magecart_css_site_13711 : sourcecode
{
meta:
		name      = "Magecart (css site)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /'POST',decodeURIComponent\(escape\(\w{2,8}\)\),!0\);\w{2,8}\.send\(null\);\}/
condition:
		$ekfl
}

rule ekf_magecart_wss_16297 : sourcecode
{
meta:
		name      = "Magecart (wss)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/unmaskparasites/status/1519784855730499585?s=20&t=ieMMJelaM8_chtNakBeD0g"

strings:
		$ekfl = /_g0\[_cs/
condition:
		$ekfl
}

rule ekf_magecart_caramelcorp_21851 : sourcecode
{
meta:
		name      = "Magecart (CaramelCorp)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://www.domaintools.com/resources/blog/a-sticky-situation-part-1-the-pervasive-nature-of-credit-card-skimmers#"

strings:
		$ekfl = /\{mathBA\(\),mathCC\(\);/
condition:
		$ekfl
}

rule ekf_magecart_devtoolshex_18741 : sourcecode
{
meta:
		name      = "Magecart (devtoolshex)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /\\x64\\x65\\x76\\x74\\x6F\\x6F\\x6C\\x73\\x63\\x68\\x61\\x6E\\x67\\x65/
condition:
		$ekfl
}

rule ekf_magecart_xcart_7171 : sourcecode
{
meta:
		name      = "Magecart (xcart)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://blog.sucuri.net/2022/05/x-cart-skimmer-with-dom-based-obfuscation.html"

strings:
		$ekfl = /function\(s,m,e\)\{m=atob\(m\)\.split/
condition:
		$ekfl
}

rule ekf_magecart_anti_sandbox_28919 : sourcecode
{
meta:
		name      = "Magecart (anti sandbox)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://blog.malwarebytes.com/threat-intelligence/2022/06/client-side-magecart-attacks-still-around-but-more-covert/"

strings:
		$ekfl = /;var\so1,o2,o3,o4|var\sccn,nb_dd,nm_dd|atob\(dm_insight_ids\)|new\sself.Function\(atob\(/
condition:
		$ekfl
}

rule ekf_magecart_greatz_skimmerz_16562 : sourcecode
{
meta:
		name      = "Magecart (greatz skimmerz)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/unmaskparasites/status/1542237945779826688?s=20&t=Osp97NqF0O5rWa9bp4u-GQ"

strings:
		$ekfl = /retroslaver\(good_guys\)/
condition:
		$ekfl
}

rule ekf_magecart_magneto_431 : sourcecode
{
meta:
		name      = "Magecart (Magneto)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/MBThreatIntel/status/1171817639728934912"

strings:
		$ekfl = /xmlhttp\[_0x\w{4}\[[0-9]{2}\]\]\(_0x\w{6}\)\}\}\)\(\)\}|drt_script.parentNode.insertBefore/
condition:
		$ekfl
}

rule ekf_magecart_cloud_6751 : sourcecode
{
meta:
		name      = "Magecart (cloud)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/sansecio/status/1545097814945845248"

strings:
		$ekfl = /w\['AULGEE0'\]\s=\s1/
condition:
		$ekfl
}

rule ekf_magecart_wholeinter_14534 : sourcecode
{
meta:
		name      = "Magecart (whole_inter)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/sansecio/status/1545159974254362626"

strings:
		$ekfl = /clearInterval\(whole_inter\)/
condition:
		$ekfl
}

rule ekf_magecart_magcache_29148 : sourcecode
{
meta:
		name      = "Magecart (Mag_cache)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/MBThreatIntel/status/1578483645568147456"

strings:
		$ekfl = /send_data\)\);\}\}\}setInterval\(Mag_cache/
condition:
		$ekfl
}

rule ekf_magecart_gtmwss_24749 : ip
{
meta:
		name      = "Magecart (GTM,WSS)"
		type      = "ip"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/unmaskparasites/status/1567604988750483457"

strings:
		$ekfl = /77.91.74.92/
condition:
		$ekfl
}

rule ekf_magecart_exfiltration_298 : hash
{
meta:
		name      = "Magecart (exfiltration)"
		type      = "hash"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

condition:
		hash.sha256(0, filesize) == "ad7f76306b7deced1aea2cafb9e0cdfd00716ba713b382a079c7d743a396cf87"
}

rule ekf_rig_ek_26450 : uri
{
meta:
		name      = "RIG EK"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/rig-exploit-kit-diving-deeper-into-the-infrastructure/"

strings:
		$ekfl = /https?:\/\/[^\x3f]+\/\x3f[^\x3f]+Q[cdM][_fPrv][bDfLPTWXjn][acdefYZVUb][abKLJ][^\n]+$/
condition:
		$ekfl
}

rule ekf_purplefox_ek_29362 : uri
{
meta:
		name      = "PurpleFox EK"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://www.trendmicro.com/en_ca/research/20/i/purple-fox-ek-relies-on-cloudflare-for-stability.html"
		comment   = "the regex uses negative lookahead"

strings:
		$ekfl = /http(s|):\/\/[^.]([a-z0-9-]+\.){2}[a-z]{2,7}\/news\/((crypto-js|zepto|aes|base64)\.min\.js$|index\.php\?key=[0-9]\w{15}&id)/
condition:
		$ekfl
}

rule ekf_purplefox_ek_payload_6393 : uri
{
meta:
		name      = "PurpleFox EK (payload)"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /http(s|):\/\/[a-z0-9-]{3}\.[a-z]{2,7}\/(i\.php\?i=1|[0-9]{2}\.png)$/
condition:
		$ekfl
}

rule ekf_magnitude_ek_1818 : uri
{
meta:
		name      = "Magnitude EK"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://malware.dontneedcoffee.com/2018/03/CVE-2018-4878.html"
		comment   = "the regex uses negative lookahead"

strings:
		$ekfl = /http:\/\/((.*\d){4})(.*[a-zA-Z])[0-9a-zA-Z!@#$%]{8,}\.[a-z]{6,7}\.[a-z]{3,15}\/$/
condition:
		$ekfl
}

rule ekf_underminer_ek_11080 : ip
{
meta:
		name      = "Underminer EK"
		type      = "ip"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /216.250.255.122/
condition:
		$ekfl
}

rule ekf_cve_2021_40444_32447 : sourcecode
{
meta:
		name      = "CVE-2021-40444"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444"

strings:
		$ekfl = /(':\.'\+'\.\/'\+'\.{2}\/'\+'\.{2}'\+'\/\.'\+'\.\/\.{2}\/)|(\.cpl:(\.{2}/){5})/
condition:
		$ekfl
}

rule ekf_cve_2022_30190_follina_24901 : sourcecode
{
meta:
		name      = "CVE-2022-30190 (Follina)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30190"

strings:
		$ekfl = /i(\/\.\.){14}\/Windows\/System32\/mpsigstub\.exe|\s=\s"ms-msdt:\/id|System3"\+"2\/mpsigstub\.exe|%20%22%6D%73%2D%6D%73%64%74%3A%2F%69%64|"ms-"\+"msdt:\/id/
condition:
		$ekfl
}

rule ekf_suspicious_ip_magecart_3113 : ip
{
meta:
		name      = "Suspicious IP (Magecart)"
		type      = "ip"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /185\.63\.190\.[12][0-9]{2}|185\.253\.3[23]\.[0-9]{2,3}|185\.63\.188\.[0-9]{2}|89\.108\.(109|116|123|126|127)\.[0-9]{2,3}|82\.202\.160\.[0-9]{1,3}/
condition:
		$ekfl
}

rule ekf_suspicious_js_6281 : sourcecode
{
meta:
		name      = "Suspicious JS"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "https://twitter.com/felixaime/status/1542531512758837249"

strings:
		$ekfl = /984abVSe/
condition:
		$ekfl
}

rule ekf_raccoon_stealer_c2_32497 : uri
{
meta:
		name      = "Raccoon Stealer (C2)"
		type      = "uri"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /http(s|):\/\/(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\/(nixsmasterbaks2|\/l\/f\/)/
condition:
		$ekfl
}

rule ekf_fakeupdatessocgholish_c2_20750 : sourcecode
{
meta:
		name      = "FakeUpdates/SocGholish (C2)"
		type      = "sourcecode"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /BuildNumber'\)\);function\s\w{2}\(\w{2},\w{2},\w{2}\)\{var/
condition:
		$ekfl
}

