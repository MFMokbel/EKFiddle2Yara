// Retrieved on 2022-10-13; 07:13:45 PM
// Total number of parsed rules: 51


rule ekf_extract_skimmer_29341 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /Gate: \"	\"/
condition:
		$ekfl
}

rule ekf_extract_skimmer_15441 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /screen-obj\",\s?\"	\"\)/
condition:
		$ekfl
}

rule ekf_extract_skimmer_14414 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /atob\("	"\);/
condition:
		$ekfl
}

rule ekf_extract_skimmer_14458 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /src=atob\(\"	\"\)/
condition:
		$ekfl
}

rule ekf_extract_skimmer_7480 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /img.src = window.atob\(\"	\"\)/
condition:
		$ekfl
}

rule ekf_extract_skimmer_14889 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /\\x68\\x74\\x74\\x70\\x73\\x3[aA]\\x2[fF]\\x2[fF]	((\"|'),(\"|')|\\x22)/
condition:
		$ekfl
}

rule ekf_extract_skimmer_20745 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /\\x43\\x68\\x61\\x72\\x43\\x6[fF]\\x64\\x65\\x28	\\x29/
condition:
		$ekfl
}

rule ekf_extract_skimmer_5572 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /var __zz ?= ?'	'/
condition:
		$ekfl
}

rule ekf_extract_skimmer_29748 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /\\x61\\x48\\x52\\x30\\x63\\x48\\x4[dD]\\x36	\\x4[cC]\\x32\\x6[cC]\\x74\\x5[aA]\\x77/
condition:
		$ekfl
}

rule ekf_extract_skimmer_14577 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /var url = '	&host/
condition:
		$ekfl
}

rule ekf_extract_skimmer_22720 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /\(window,document,'	','script','Y2hlY2tvdXQ='/
condition:
		$ekfl
}

rule ekf_extract_skimmer_17583 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /\\x55\\x52\\x4[cC]","	\\x3[fF]/
condition:
		$ekfl
}

rule ekf_extract_skimmer_7805 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /\\x55\\x52\\x4C","	\\x2E\\x70\\x68\\x70/
condition:
		$ekfl
}

rule ekf_extract_skimmer_31026 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /"\\x55\\x52\\x4C","	\\x76\\x61\\x6C\\x69\\x64\\x61\\x74\\x65\\x2E\\x70\\x68\\x70/
condition:
		$ekfl
}

rule ekf_extract_skimmer_11754 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /"\\x61\\x70\\x70\\x65\\x6E\\x64","	","\\x50\\x4F\\x53\\x54"/
condition:
		$ekfl
}

rule ekf_extract_skimmer_2476 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /urll="https:\/\/	"\+/
condition:
		$ekfl
}

rule ekf_extract_skimmer_28502 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /15,17\)\]\(	\)\+Y/
condition:
		$ekfl
}

rule ekf_extract_skimmer_24434 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /\\x49\\x3d','	','\\x62\\x32\\x35/
condition:
		$ekfl
}

rule ekf_extract_skimmer_18436 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /'c3RyaW5naWZ5','	','b3Blbg==/
condition:
		$ekfl
}

rule ekf_extract_skimmer_20241 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /"\\x66\\x6C\\x6F\\x6F\\x72","	\\x3F","\\x61\\x6A\\x61\\x78",/
condition:
		$ekfl
}

rule ekf_extract_skimmer_30030 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /xhr.open\("POST", 'https:\/\/	', true\);/
condition:
		$ekfl
}

rule ekf_extract_skimmer_5976 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /xhr.open\("POST", '\/	', true\);/
condition:
		$ekfl
}

rule ekf_extract_skimmer_24105 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /Gate:"	",/
condition:
		$ekfl
}

rule ekf_extract_skimmer_351 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /','https:\/\/	','querySelectorAll/
condition:
		$ekfl
}

rule ekf_extract_skimmer_30064 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /n.src\s=\s"\s	\?payment=/
condition:
		$ekfl
}

rule ekf_extract_skimmer_29200 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /\\x36\\x38\\x24\\x37\\x34\\x24\\x37\\x34	\\x36\\x38\\x24\\x37\\x34\\x24\\x37\\x34/
condition:
		$ekfl
}

rule ekf_extract_skimmer_23523 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /eventsListenerPool.src\s=\s"	";/
condition:
		$ekfl
}

rule ekf_extract_skimmer_198 : extract_skimmer
{
meta:
		name      = "extract-skimmer"
		type      = "extract-skimmer"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /eventsListenerPool.src\s=\s'	;/
condition:
		$ekfl
}

rule ekf_extract_phone_9915 : extract_phone
{
meta:
		name      = "extract-phone"
		type      = "extract-phone"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /1-\d\d\d-\d\d\d-\d\d\d\d/
condition:
		$ekfl
}

rule ekf_extract_phone_1009 : extract_phone
{
meta:
		name      = "extract-phone"
		type      = "extract-phone"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /0[1-6](-[0-9]{2}){4}/
condition:
		$ekfl
}

rule ekf_extract_phone_6209 : extract_phone
{
meta:
		name      = "extract-phone"
		type      = "extract-phone"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /\+61\s\d{9}/
condition:
		$ekfl
}

rule ekf_extract_phone_19435 : extract_phone
{
meta:
		name      = "extract-phone"
		type      = "extract-phone"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /\+44\s\d{10}/
condition:
		$ekfl
}

rule ekf_wordpress_16850 : extract_cms
{
meta:
		name      = "WordPress"
		type      = "extract-cms"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /\/wp-content\//
condition:
		#ekfl >= 10
}

rule ekf_joomla_17757 : extract_cms
{
meta:
		name      = "Joomla"
		type      = "extract-cms"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /<meta\sname="generator"\scontent="Joomla!/
condition:
		$ekfl
}

rule ekf_joomla_809 : extract_cms
{
meta:
		name      = "Joomla"
		type      = "extract-cms"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /\/css\/template\.css"\s(rel="stylesheet"\s)?type="text\/css"\s\/>/
condition:
		$ekfl
}

rule ekf_magento_18408 : extract_cms
{
meta:
		name      = "Magento"
		type      = "extract-cms"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /\/skin\/frontend\//
condition:
		#ekfl >= 10
}

rule ekf_magento_14580 : extract_cms
{
meta:
		name      = "Magento"
		type      = "extract-cms"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /<script\stype="text\/x-magento-init">/
condition:
		#ekfl >= 5
}

rule ekf_magento_15081 : extract_cms
{
meta:
		name      = "Magento"
		type      = "extract-cms"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /","magentoCart\-/
condition:
		#ekfl >= 5
}

rule ekf_magento_15600 : extract_cms
{
meta:
		name      = "Magento"
		type      = "extract-cms"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /Mage\.Cookies\.path/
condition:
		$ekfl
}

rule ekf_opencart_18836 : extract_cms
{
meta:
		name      = "OpenCart"
		type      = "extract-cms"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /Powered\sBy\s<a\shref="http:\/\/www.opencart.com/
condition:
		$ekfl
}

rule ekf_opencart_11309 : extract_cms
{
meta:
		name      = "OpenCart"
		type      = "extract-cms"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /\/css\/opencart\.css/
condition:
		$ekfl
}

rule ekf_opencart_26814 : extract_cms
{
meta:
		name      = "OpenCart"
		type      = "extract-cms"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /PayPal\sto\sdonate@opencart.com/
condition:
		$ekfl
}

rule ekf_shopify_19496 : extract_cms
{
meta:
		name      = "Shopify"
		type      = "extract-cms"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /Shopify\.theme(\.handle|\.style)?\s=/
condition:
		#ekfl >= 3
}

rule ekf_drupal_17414 : extract_cms
{
meta:
		name      = "Drupal"
		type      = "extract-cms"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /<meta\sname="[gG]enerator"\scontent="Drupal/
condition:
		$ekfl
}

rule ekf_woocommerce_28110 : extract_cms
{
meta:
		name      = "WooCommerce"
		type      = "extract-cms"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /\.woocommerce/
condition:
		#ekfl >= 10
}

rule ekf_woocommerce_5440 : extract_cms
{
meta:
		name      = "WooCommerce"
		type      = "extract-cms"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /<meta name="generator"\scontent="WooCommerce/
condition:
		$ekfl
}

rule ekf_bigcommerce_26041 : extract_cms
{
meta:
		name      = "BigCommerce"
		type      = "extract-cms"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /cdn11.bigcommerce.com/
condition:
		#ekfl >= 10
}

rule ekf_volusion_16468 : extract_cms
{
meta:
		name      = "Volusion"
		type      = "extract-cms"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /Built\sWith\sVolusion.<\/a>/
condition:
		$ekfl
}

rule ekf_volusion_11036 : extract_cms
{
meta:
		name      = "Volusion"
		type      = "extract-cms"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /volusion.cart.itemCount\(quantityTotal\);/
condition:
		$ekfl
}

rule ekf_prestashop_7917 : extract_cms
{
meta:
		name      = "PrestaShop"
		type      = "extract-cms"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /var\sprestashop\s=\s\{"cart":\{"products":/
condition:
		$ekfl
}

rule ekf_prestashop_31540 : extract_cms
{
meta:
		name      = "PrestaShop"
		type      = "extract-cms"
		author    = "EKFiddle2Yara v1.0"
		date      = "2022-10-13"
		reference = "none"

strings:
		$ekfl = /<meta\sname="generator"\scontent="PrestaShop"/
condition:
		$ekfl
}

