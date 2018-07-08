<!--
Copyright 2017-present Open Networking Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->
<?xml version="1.0" standalone="yes"?>
<!--This XSLT was automatically generated from a Schematron schema.-->
<axsl:stylesheet xmlns:date="http://exslt.org/dates-and-times" xmlns:dyn="http://exslt.org/dynamic" xmlns:exsl="http://exslt.org/common" xmlns:math="http://exslt.org/math" xmlns:random="http://exslt.org/random" xmlns:regexp="http://exslt.org/regular-expressions" xmlns:set="http://exslt.org/sets" xmlns:str="http://exslt.org/strings" xmlns:axsl="http://www.w3.org/1999/XSL/Transform" xmlns:sch="http://www.ascc.net/xml/schematron" xmlns:iso="http://purl.oclc.org/dsdl/schematron" xmlns:voltha="urn:opencord:params:xml:ns:voltha:voltha" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" extension-element-prefixes="date dyn exsl math random regexp set str" version="1.0"><!--Implementers: please note that overriding process-prolog or process-root is 
    the preferred method for meta-stylesheets to use where possible. -->
<axsl:param name="archiveDirParameter"/><axsl:param name="archiveNameParameter"/><axsl:param name="fileNameParameter"/><axsl:param name="fileDirParameter"/>

<!--PHASES-->


<!--PROLOG-->
<axsl:output xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" xmlns:svrl="http://purl.oclc.org/dsdl/svrl" method="xml" omit-xml-declaration="no" standalone="yes" indent="yes"/>

<!--KEYS-->


<!--DEFAULT RULES-->


<!--MODE: SCHEMATRON-SELECT-FULL-PATH-->
<!--This mode can be used to generate an ugly though full XPath for locators-->
<axsl:template match="*" mode="schematron-select-full-path"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:template>

<!--MODE: SCHEMATRON-FULL-PATH-->
<!--This mode can be used to generate an ugly though full XPath for locators-->
<axsl:template match="*" mode="schematron-get-full-path"><axsl:apply-templates select="parent::*" mode="schematron-get-full-path"/><axsl:text>/</axsl:text><axsl:choose><axsl:when test="namespace-uri()=''"><axsl:value-of select="name()"/><axsl:variable name="p_1" select="1+    count(preceding-sibling::*[name()=name(current())])"/><axsl:if test="$p_1&gt;1 or following-sibling::*[name()=name(current())]">[<axsl:value-of select="$p_1"/>]</axsl:if></axsl:when><axsl:otherwise><axsl:text>*[local-name()='</axsl:text><axsl:value-of select="local-name()"/><axsl:text>' and namespace-uri()='</axsl:text><axsl:value-of select="namespace-uri()"/><axsl:text>']</axsl:text><axsl:variable name="p_2" select="1+   count(preceding-sibling::*[local-name()=local-name(current())])"/><axsl:if test="$p_2&gt;1 or following-sibling::*[local-name()=local-name(current())]">[<axsl:value-of select="$p_2"/>]</axsl:if></axsl:otherwise></axsl:choose></axsl:template><axsl:template match="@*" mode="schematron-get-full-path"><axsl:text>/</axsl:text><axsl:choose><axsl:when test="namespace-uri()=''">@<axsl:value-of select="name()"/></axsl:when><axsl:otherwise><axsl:text>@*[local-name()='</axsl:text><axsl:value-of select="local-name()"/><axsl:text>' and namespace-uri()='</axsl:text><axsl:value-of select="namespace-uri()"/><axsl:text>']</axsl:text></axsl:otherwise></axsl:choose></axsl:template>

<!--MODE: SCHEMATRON-FULL-PATH-2-->
<!--This mode can be used to generate prefixed XPath for humans-->
<axsl:template match="node() | @*" mode="schematron-get-full-path-2"><axsl:for-each select="ancestor-or-self::*"><axsl:text>/</axsl:text><axsl:value-of select="name(.)"/><axsl:if test="preceding-sibling::*[name(.)=name(current())]"><axsl:text>[</axsl:text><axsl:value-of select="count(preceding-sibling::*[name(.)=name(current())])+1"/><axsl:text>]</axsl:text></axsl:if></axsl:for-each><axsl:if test="not(self::*)"><axsl:text/>/@<axsl:value-of select="name(.)"/></axsl:if></axsl:template>

<!--MODE: GENERATE-ID-FROM-PATH -->
<axsl:template match="/" mode="generate-id-from-path"/><axsl:template match="text()" mode="generate-id-from-path"><axsl:apply-templates select="parent::*" mode="generate-id-from-path"/><axsl:value-of select="concat('.text-', 1+count(preceding-sibling::text()), '-')"/></axsl:template><axsl:template match="comment()" mode="generate-id-from-path"><axsl:apply-templates select="parent::*" mode="generate-id-from-path"/><axsl:value-of select="concat('.comment-', 1+count(preceding-sibling::comment()), '-')"/></axsl:template><axsl:template match="processing-instruction()" mode="generate-id-from-path"><axsl:apply-templates select="parent::*" mode="generate-id-from-path"/><axsl:value-of select="concat('.processing-instruction-', 1+count(preceding-sibling::processing-instruction()), '-')"/></axsl:template><axsl:template match="@*" mode="generate-id-from-path"><axsl:apply-templates select="parent::*" mode="generate-id-from-path"/><axsl:value-of select="concat('.@', name())"/></axsl:template><axsl:template match="*" mode="generate-id-from-path" priority="-0.5"><axsl:apply-templates select="parent::*" mode="generate-id-from-path"/><axsl:text>.</axsl:text><axsl:value-of select="concat('.',name(),'-',1+count(preceding-sibling::*[name()=name(current())]),'-')"/></axsl:template><!--MODE: SCHEMATRON-FULL-PATH-3-->
<!--This mode can be used to generate prefixed XPath for humans 
	(Top-level element has index)-->
<axsl:template match="node() | @*" mode="schematron-get-full-path-3"><axsl:for-each select="ancestor-or-self::*"><axsl:text>/</axsl:text><axsl:value-of select="name(.)"/><axsl:if test="parent::*"><axsl:text>[</axsl:text><axsl:value-of select="count(preceding-sibling::*[name(.)=name(current())])+1"/><axsl:text>]</axsl:text></axsl:if></axsl:for-each><axsl:if test="not(self::*)"><axsl:text/>/@<axsl:value-of select="name(.)"/></axsl:if></axsl:template>

<!--MODE: GENERATE-ID-2 -->
<axsl:template match="/" mode="generate-id-2">U</axsl:template><axsl:template match="*" mode="generate-id-2" priority="2"><axsl:text>U</axsl:text><axsl:number level="multiple" count="*"/></axsl:template><axsl:template match="node()" mode="generate-id-2"><axsl:text>U.</axsl:text><axsl:number level="multiple" count="*"/><axsl:text>n</axsl:text><axsl:number count="node()"/></axsl:template><axsl:template match="@*" mode="generate-id-2"><axsl:text>U.</axsl:text><axsl:number level="multiple" count="*"/><axsl:text>_</axsl:text><axsl:value-of select="string-length(local-name(.))"/><axsl:text>_</axsl:text><axsl:value-of select="translate(name(),':','.')"/></axsl:template><!--Strip characters--><axsl:template match="text()" priority="-1"/>

<!--SCHEMA METADATA-->
<axsl:template match="/"><svrl:schematron-output xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" title="" schemaVersion=""><axsl:comment><axsl:value-of select="$archiveDirParameter"/>   
		 <axsl:value-of select="$archiveNameParameter"/>  
		 <axsl:value-of select="$fileNameParameter"/>  
		 <axsl:value-of select="$fileDirParameter"/></axsl:comment><svrl:ns-prefix-in-attribute-values uri="http://exslt.org/dynamic" prefix="dyn"/><svrl:ns-prefix-in-attribute-values uri="urn:opencord:params:xml:ns:voltha:voltha" prefix="voltha"/><svrl:ns-prefix-in-attribute-values uri="urn:ietf:params:xml:ns:netconf:base:1.0" prefix="nc"/><svrl:active-pattern><axsl:attribute name="id">voltha</axsl:attribute><axsl:attribute name="name">voltha</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M4"/><svrl:active-pattern><axsl:attribute name="id">idm139853992598368</axsl:attribute><axsl:attribute name="name">idm139853992598368</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M5"/><svrl:active-pattern><axsl:attribute name="id">idm139853992594640</axsl:attribute><axsl:attribute name="name">idm139853992594640</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M6"/><svrl:active-pattern><axsl:attribute name="id">idm139853992593776</axsl:attribute><axsl:attribute name="name">idm139853992593776</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M7"/><svrl:active-pattern><axsl:attribute name="id">idm139853992565136</axsl:attribute><axsl:attribute name="name">idm139853992565136</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M8"/><svrl:active-pattern><axsl:attribute name="id">idm139853992564208</axsl:attribute><axsl:attribute name="name">idm139853992564208</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M9"/><svrl:active-pattern><axsl:attribute name="id">idm139853992563280</axsl:attribute><axsl:attribute name="name">idm139853992563280</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M10"/><svrl:active-pattern><axsl:attribute name="id">idm139853992544272</axsl:attribute><axsl:attribute name="name">idm139853992544272</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M11"/><svrl:active-pattern><axsl:attribute name="id">idm139853992539920</axsl:attribute><axsl:attribute name="name">idm139853992539920</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M12"/><svrl:active-pattern><axsl:attribute name="id">idm139853992538992</axsl:attribute><axsl:attribute name="name">idm139853992538992</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M13"/><svrl:active-pattern><axsl:attribute name="id">idm139853992510432</axsl:attribute><axsl:attribute name="name">idm139853992510432</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M14"/><svrl:active-pattern><axsl:attribute name="id">idm139853992509504</axsl:attribute><axsl:attribute name="name">idm139853992509504</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M15"/><svrl:active-pattern><axsl:attribute name="id">idm139853992508576</axsl:attribute><axsl:attribute name="name">idm139853992508576</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M16"/><svrl:active-pattern><axsl:attribute name="id">idm139853992475568</axsl:attribute><axsl:attribute name="name">idm139853992475568</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M17"/><svrl:active-pattern><axsl:attribute name="id">idm139853992471552</axsl:attribute><axsl:attribute name="name">idm139853992471552</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M18"/><svrl:active-pattern><axsl:attribute name="id">idm139853992470624</axsl:attribute><axsl:attribute name="name">idm139853992470624</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M19"/><svrl:active-pattern><axsl:attribute name="id">idm139853992442064</axsl:attribute><axsl:attribute name="name">idm139853992442064</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M20"/><svrl:active-pattern><axsl:attribute name="id">idm139853992441136</axsl:attribute><axsl:attribute name="name">idm139853992441136</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M21"/><svrl:active-pattern><axsl:attribute name="id">idm139853992440208</axsl:attribute><axsl:attribute name="name">idm139853992440208</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M22"/><svrl:active-pattern><axsl:attribute name="id">idm139853992420976</axsl:attribute><axsl:attribute name="name">idm139853992420976</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M23"/><svrl:active-pattern><axsl:attribute name="id">idm139853992416960</axsl:attribute><axsl:attribute name="name">idm139853992416960</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M24"/><svrl:active-pattern><axsl:attribute name="id">idm139853992416032</axsl:attribute><axsl:attribute name="name">idm139853992416032</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M25"/><svrl:active-pattern><axsl:attribute name="id">idm139853992387472</axsl:attribute><axsl:attribute name="name">idm139853992387472</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M26"/><svrl:active-pattern><axsl:attribute name="id">idm139853992386544</axsl:attribute><axsl:attribute name="name">idm139853992386544</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M27"/><svrl:active-pattern><axsl:attribute name="id">idm139853992385616</axsl:attribute><axsl:attribute name="name">idm139853992385616</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M28"/><svrl:active-pattern><axsl:attribute name="id">idm139853992361888</axsl:attribute><axsl:attribute name="name">idm139853992361888</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M29"/><svrl:active-pattern><axsl:attribute name="id">idm139853992357872</axsl:attribute><axsl:attribute name="name">idm139853992357872</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M30"/><svrl:active-pattern><axsl:attribute name="id">idm139853992356944</axsl:attribute><axsl:attribute name="name">idm139853992356944</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M31"/><svrl:active-pattern><axsl:attribute name="id">idm139853992328384</axsl:attribute><axsl:attribute name="name">idm139853992328384</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M32"/><svrl:active-pattern><axsl:attribute name="id">idm139853992327456</axsl:attribute><axsl:attribute name="name">idm139853992327456</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M33"/><svrl:active-pattern><axsl:attribute name="id">idm139853992326528</axsl:attribute><axsl:attribute name="name">idm139853992326528</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M34"/><svrl:active-pattern><axsl:attribute name="id">idm139853992312448</axsl:attribute><axsl:attribute name="name">idm139853992312448</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M35"/><svrl:active-pattern><axsl:attribute name="id">idm139853992308432</axsl:attribute><axsl:attribute name="name">idm139853992308432</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M36"/><svrl:active-pattern><axsl:attribute name="id">idm139853992307504</axsl:attribute><axsl:attribute name="name">idm139853992307504</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M37"/><svrl:active-pattern><axsl:attribute name="id">idm139853992278944</axsl:attribute><axsl:attribute name="name">idm139853992278944</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M38"/><svrl:active-pattern><axsl:attribute name="id">idm139853992278016</axsl:attribute><axsl:attribute name="name">idm139853992278016</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M39"/><svrl:active-pattern><axsl:attribute name="id">idm139853992277088</axsl:attribute><axsl:attribute name="name">idm139853992277088</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M40"/><svrl:active-pattern><axsl:attribute name="id">idm139853992264352</axsl:attribute><axsl:attribute name="name">idm139853992264352</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M41"/><svrl:active-pattern><axsl:attribute name="id">idm139853992242320</axsl:attribute><axsl:attribute name="name">idm139853992242320</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M42"/><svrl:active-pattern><axsl:attribute name="id">idm139853992198304</axsl:attribute><axsl:attribute name="name">idm139853992198304</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M43"/><svrl:active-pattern><axsl:attribute name="id">idm139853992192064</axsl:attribute><axsl:attribute name="name">idm139853992192064</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M44"/><svrl:active-pattern><axsl:attribute name="id">idm139853992179296</axsl:attribute><axsl:attribute name="name">idm139853992179296</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M45"/><svrl:active-pattern><axsl:attribute name="id">idm139853992178336</axsl:attribute><axsl:attribute name="name">idm139853992178336</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M46"/><svrl:active-pattern><axsl:attribute name="id">idm139853992177376</axsl:attribute><axsl:attribute name="name">idm139853992177376</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M47"/><svrl:active-pattern><axsl:attribute name="id">idm139853992176432</axsl:attribute><axsl:attribute name="name">idm139853992176432</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M48"/><svrl:active-pattern><axsl:attribute name="id">idm139853992175488</axsl:attribute><axsl:attribute name="name">idm139853992175488</axsl:attribute><axsl:apply-templates/></svrl:active-pattern><axsl:apply-templates select="/" mode="M49"/></svrl:schematron-output></axsl:template>

<!--SCHEMATRON PATTERNS-->
<axsl:param name="root" select="/nc:config"/>

<!--PATTERN voltha-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:adapters" priority="1059" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:adapters"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:adapters[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:adapters[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:adapters/voltha:logical_device_ids" priority="1058" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:adapters/voltha:logical_device_ids"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:logical_device_ids[voltha:logical_device_ids=current()/voltha:logical_device_ids]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:logical_device_ids[voltha:logical_device_ids=current()/voltha:logical_device_ids]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:logical_device_ids"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:logical_devices" priority="1057" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:logical_devices"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:logical_devices[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:logical_devices[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:logical_devices/voltha:ports" priority="1056" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:logical_devices/voltha:ports"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:ports[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:ports[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:devices" priority="1055" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:devices"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:devices[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:devices[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:devices/voltha:ports" priority="1054" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:devices/voltha:ports"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:ports[voltha:port_no=current()/voltha:port_no]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:ports[voltha:port_no=current()/voltha:port_no]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:port_no"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:devices/voltha:ports/voltha:peers" priority="1053" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:devices/voltha:ports/voltha:peers"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:peers[voltha:device_id=current()/voltha:device_id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:peers[voltha:device_id=current()/voltha:device_id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:device_id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_types" priority="1052" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_types"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:device_types[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:device_types[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_groups" priority="1051" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_groups"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:device_groups[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:device_groups[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:logical_devices" priority="1050" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:logical_devices"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:logical_devices[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:logical_devices[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:logical_devices/voltha:ports" priority="1049" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:logical_devices/voltha:ports"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:ports[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:ports[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices" priority="1048" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:devices[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:devices[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices/voltha:ports" priority="1047" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices/voltha:ports"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:ports[voltha:port_no=current()/voltha:port_no]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:ports[voltha:port_no=current()/voltha:port_no]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:port_no"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices/voltha:ports/voltha:peers" priority="1046" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices/voltha:ports/voltha:peers"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:peers[voltha:device_id=current()/voltha:device_id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:peers[voltha:device_id=current()/voltha:device_id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:device_id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:alarm_filters" priority="1045" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:alarm_filters"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:alarm_filters[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:alarm_filters[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:alarm_filters/voltha:rules" priority="1044" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:alarm_filters/voltha:rules"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:rules[voltha:key=current()/voltha:key]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:rules[voltha:key=current()/voltha:key]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:key"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstances/voltha:items" priority="1043" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstances/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:items=current()/voltha:items]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:items=current()/voltha:items]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:items"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances" priority="1042" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:instances[voltha:instance_id=current()/voltha:instance_id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:instances[voltha:instance_id=current()/voltha:instance_id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:instance_id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:adapters" priority="1041" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:adapters"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:adapters[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:adapters[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:adapters/voltha:logical_device_ids" priority="1040" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:adapters/voltha:logical_device_ids"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:logical_device_ids[voltha:logical_device_ids=current()/voltha:logical_device_ids]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:logical_device_ids[voltha:logical_device_ids=current()/voltha:logical_device_ids]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:logical_device_ids"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:logical_devices" priority="1039" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:logical_devices"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:logical_devices[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:logical_devices[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:logical_devices/voltha:ports" priority="1038" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:logical_devices/voltha:ports"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:ports[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:ports[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:devices" priority="1037" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:devices"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:devices[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:devices[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:devices/voltha:ports" priority="1036" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:devices/voltha:ports"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:ports[voltha:port_no=current()/voltha:port_no]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:ports[voltha:port_no=current()/voltha:port_no]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:port_no"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:devices/voltha:ports/voltha:peers" priority="1035" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:devices/voltha:ports/voltha:peers"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:peers[voltha:device_id=current()/voltha:device_id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:peers[voltha:device_id=current()/voltha:device_id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:device_id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_types" priority="1034" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_types"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:device_types[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:device_types[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups" priority="1033" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:device_groups[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:device_groups[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:logical_devices" priority="1032" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:logical_devices"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:logical_devices[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:logical_devices[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:logical_devices/voltha:ports" priority="1031" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:logical_devices/voltha:ports"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:ports[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:ports[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices" priority="1030" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:devices[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:devices[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices/voltha:ports" priority="1029" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices/voltha:ports"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:ports[voltha:port_no=current()/voltha:port_no]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:ports[voltha:port_no=current()/voltha:port_no]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:port_no"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices/voltha:ports/voltha:peers" priority="1028" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices/voltha:ports/voltha:peers"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:peers[voltha:device_id=current()/voltha:device_id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:peers[voltha:device_id=current()/voltha:device_id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:device_id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:alarm_filters" priority="1027" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:alarm_filters"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:alarm_filters[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:alarm_filters[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:alarm_filters/voltha:rules" priority="1026" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:alarm_filters/voltha:rules"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:rules[voltha:key=current()/voltha:key]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:rules[voltha:key=current()/voltha:key]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:key"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:adapters" priority="1025" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:adapters"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:adapters[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:adapters[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:adapters/voltha:logical_device_ids" priority="1024" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:adapters/voltha:logical_device_ids"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:logical_device_ids[voltha:logical_device_ids=current()/voltha:logical_device_ids]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:logical_device_ids[voltha:logical_device_ids=current()/voltha:logical_device_ids]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:logical_device_ids"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:logical_devices" priority="1023" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:logical_devices"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:logical_devices[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:logical_devices[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:logical_devices/voltha:ports" priority="1022" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:logical_devices/voltha:ports"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:ports[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:ports[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:devices" priority="1021" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:devices"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:devices[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:devices[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:devices/voltha:ports" priority="1020" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:devices/voltha:ports"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:ports[voltha:port_no=current()/voltha:port_no]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:ports[voltha:port_no=current()/voltha:port_no]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:port_no"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:devices/voltha:ports/voltha:peers" priority="1019" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:devices/voltha:ports/voltha:peers"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:peers[voltha:device_id=current()/voltha:device_id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:peers[voltha:device_id=current()/voltha:device_id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:device_id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:device_groups" priority="1018" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:device_groups"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:device_groups[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:device_groups[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:device_groups/voltha:logical_devices" priority="1017" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:device_groups/voltha:logical_devices"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:logical_devices[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:logical_devices[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:device_groups/voltha:logical_devices/voltha:ports" priority="1016" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:device_groups/voltha:logical_devices/voltha:ports"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:ports[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:ports[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices" priority="1015" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:devices[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:devices[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices/voltha:ports" priority="1014" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices/voltha:ports"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:ports[voltha:port_no=current()/voltha:port_no]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:ports[voltha:port_no=current()/voltha:port_no]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:port_no"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices/voltha:ports/voltha:peers" priority="1013" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices/voltha:ports/voltha:peers"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:peers[voltha:device_id=current()/voltha:device_id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:peers[voltha:device_id=current()/voltha:device_id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:device_id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_hello/voltha:elements" priority="1012" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_hello/voltha:elements"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:elements[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:elements[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_port_mod/voltha:hw_addr" priority="1011" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_port_mod/voltha:hw_addr"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:hw_addr[voltha:hw_addr=current()/voltha:hw_addr]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:hw_addr[voltha:hw_addr=current()/voltha:hw_addr]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:hw_addr"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_meter_mod/voltha:bands" priority="1010" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_meter_mod/voltha:bands"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:bands[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:bands[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_table_features/voltha:properties" priority="1009" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_table_features/voltha:properties"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:properties[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:properties[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_group_features/voltha:max_groups" priority="1008" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_group_features/voltha:max_groups"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:max_groups[voltha:max_groups=current()/voltha:max_groups]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:max_groups[voltha:max_groups=current()/voltha:max_groups]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:max_groups"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_group_features/voltha:actions" priority="1007" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_group_features/voltha:actions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:actions[voltha:actions=current()/voltha:actions]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:actions[voltha:actions=current()/voltha:actions]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:actions"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_meter_stats/voltha:band_stats" priority="1006" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_meter_stats/voltha:band_stats"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:band_stats[voltha:packet_band_count=current()/voltha:packet_band_count]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:band_stats[voltha:packet_band_count=current()/voltha:packet_band_count]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:packet_band_count"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_meter_config/voltha:bands" priority="1005" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_meter_config/voltha:bands"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:bands[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:bands[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_queue_get_config_reply/voltha:queues" priority="1004" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_queue_get_config_reply/voltha:queues"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:queues[voltha:queue_id=current()/voltha:queue_id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:queues[voltha:queue_id=current()/voltha:queue_id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:queue_id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_queue_get_config_reply/voltha:queues/voltha:properties" priority="1003" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_queue_get_config_reply/voltha:queues/voltha:properties"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:properties[voltha:property=current()/voltha:property]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:properties[voltha:property=current()/voltha:property]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:property"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_async_config/voltha:packet_in_mask" priority="1002" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_async_config/voltha:packet_in_mask"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:packet_in_mask[voltha:packet_in_mask=current()/voltha:packet_in_mask]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:packet_in_mask[voltha:packet_in_mask=current()/voltha:packet_in_mask]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:packet_in_mask"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_async_config/voltha:port_status_mask" priority="1001" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_async_config/voltha:port_status_mask"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:port_status_mask[voltha:port_status_mask=current()/voltha:port_status_mask]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:port_status_mask[voltha:port_status_mask=current()/voltha:port_status_mask]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:port_status_mask"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_async_config/voltha:flow_removed_mask" priority="1000" mode="M4"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_async_config/voltha:flow_removed_mask"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:flow_removed_mask[voltha:flow_removed_mask=current()/voltha:flow_removed_mask]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:flow_removed_mask[voltha:flow_removed_mask=current()/voltha:flow_removed_mask]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "voltha:flow_removed_mask"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template><axsl:template match="text()" priority="-1" mode="M4"/><axsl:template match="@*|node()" priority="-2" mode="M4"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M4"/></axsl:template>

<!--PATTERN idm139853992598368-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:logical_devices/voltha:ports/voltha:ofp_port/voltha:hw_addr" priority="1000" mode="M5"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:logical_devices/voltha:ports/voltha:ofp_port/voltha:hw_addr"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:hw_addr[voltha:hw_addr=current()/voltha:hw_addr]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:hw_addr[voltha:hw_addr=current()/voltha:hw_addr]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "hw_addr"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M5"/></axsl:template><axsl:template match="text()" priority="-1" mode="M5"/><axsl:template match="@*|node()" priority="-2" mode="M5"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M5"/></axsl:template>

<!--PATTERN idm139853992594640-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:logical_devices/voltha:flows/voltha:items" priority="1001" mode="M6"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:logical_devices/voltha:flows/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M6"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:logical_devices/voltha:flows/voltha:items/voltha:instructions" priority="1000" mode="M6"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:logical_devices/voltha:flows/voltha:items/voltha:instructions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M6"/></axsl:template><axsl:template match="text()" priority="-1" mode="M6"/><axsl:template match="@*|node()" priority="-2" mode="M6"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M6"/></axsl:template>

<!--PATTERN idm139853992593776-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:logical_devices/voltha:flow_groups/voltha:items" priority="1002" mode="M7"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:logical_devices/voltha:flow_groups/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M7"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets" priority="1001" mode="M7"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "weight"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M7"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions" priority="1000" mode="M7"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M7"/></axsl:template><axsl:template match="text()" priority="-1" mode="M7"/><axsl:template match="@*|node()" priority="-2" mode="M7"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M7"/></axsl:template>

<!--PATTERN idm139853992565136-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:devices/voltha:flows/voltha:items" priority="1001" mode="M8"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:devices/voltha:flows/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M8"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:devices/voltha:flows/voltha:items/voltha:instructions" priority="1000" mode="M8"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:devices/voltha:flows/voltha:items/voltha:instructions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M8"/></axsl:template><axsl:template match="text()" priority="-1" mode="M8"/><axsl:template match="@*|node()" priority="-2" mode="M8"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M8"/></axsl:template>

<!--PATTERN idm139853992564208-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:devices/voltha:flow_groups/voltha:items" priority="1002" mode="M9"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:devices/voltha:flow_groups/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M9"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets" priority="1001" mode="M9"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "weight"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M9"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions" priority="1000" mode="M9"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M9"/></axsl:template><axsl:template match="text()" priority="-1" mode="M9"/><axsl:template match="@*|node()" priority="-2" mode="M9"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M9"/></axsl:template>

<!--PATTERN idm139853992563280-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:devices/voltha:pm_configs/voltha:groups" priority="1002" mode="M10"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:devices/voltha:pm_configs/voltha:groups"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:groups[voltha:group_name=current()/voltha:group_name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:groups[voltha:group_name=current()/voltha:group_name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "group_name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M10"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:devices/voltha:pm_configs/voltha:groups/voltha:metrics" priority="1001" mode="M10"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:devices/voltha:pm_configs/voltha:groups/voltha:metrics"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M10"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:devices/voltha:pm_configs/voltha:metrics" priority="1000" mode="M10"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:devices/voltha:pm_configs/voltha:metrics"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M10"/></axsl:template><axsl:template match="text()" priority="-1" mode="M10"/><axsl:template match="@*|node()" priority="-2" mode="M10"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M10"/></axsl:template>

<!--PATTERN idm139853992544272-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:logical_devices/voltha:ports/voltha:ofp_port/voltha:hw_addr" priority="1000" mode="M11"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:logical_devices/voltha:ports/voltha:ofp_port/voltha:hw_addr"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:hw_addr[voltha:hw_addr=current()/voltha:hw_addr]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:hw_addr[voltha:hw_addr=current()/voltha:hw_addr]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "hw_addr"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M11"/></axsl:template><axsl:template match="text()" priority="-1" mode="M11"/><axsl:template match="@*|node()" priority="-2" mode="M11"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M11"/></axsl:template>

<!--PATTERN idm139853992539920-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:logical_devices/voltha:flows/voltha:items" priority="1001" mode="M12"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:logical_devices/voltha:flows/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M12"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:logical_devices/voltha:flows/voltha:items/voltha:instructions" priority="1000" mode="M12"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:logical_devices/voltha:flows/voltha:items/voltha:instructions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M12"/></axsl:template><axsl:template match="text()" priority="-1" mode="M12"/><axsl:template match="@*|node()" priority="-2" mode="M12"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M12"/></axsl:template>

<!--PATTERN idm139853992538992-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:logical_devices/voltha:flow_groups/voltha:items" priority="1002" mode="M13"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:logical_devices/voltha:flow_groups/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M13"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets" priority="1001" mode="M13"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "weight"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M13"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions" priority="1000" mode="M13"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M13"/></axsl:template><axsl:template match="text()" priority="-1" mode="M13"/><axsl:template match="@*|node()" priority="-2" mode="M13"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M13"/></axsl:template>

<!--PATTERN idm139853992510432-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices/voltha:flows/voltha:items" priority="1001" mode="M14"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices/voltha:flows/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M14"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices/voltha:flows/voltha:items/voltha:instructions" priority="1000" mode="M14"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices/voltha:flows/voltha:items/voltha:instructions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M14"/></axsl:template><axsl:template match="text()" priority="-1" mode="M14"/><axsl:template match="@*|node()" priority="-2" mode="M14"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M14"/></axsl:template>

<!--PATTERN idm139853992509504-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices/voltha:flow_groups/voltha:items" priority="1002" mode="M15"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices/voltha:flow_groups/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M15"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets" priority="1001" mode="M15"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "weight"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M15"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions" priority="1000" mode="M15"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M15"/></axsl:template><axsl:template match="text()" priority="-1" mode="M15"/><axsl:template match="@*|node()" priority="-2" mode="M15"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M15"/></axsl:template>

<!--PATTERN idm139853992508576-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices/voltha:pm_configs/voltha:groups" priority="1002" mode="M16"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices/voltha:pm_configs/voltha:groups"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:groups[voltha:group_name=current()/voltha:group_name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:groups[voltha:group_name=current()/voltha:group_name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "group_name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M16"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices/voltha:pm_configs/voltha:groups/voltha:metrics" priority="1001" mode="M16"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices/voltha:pm_configs/voltha:groups/voltha:metrics"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M16"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices/voltha:pm_configs/voltha:metrics" priority="1000" mode="M16"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:VolthaInstance/voltha:device_groups/voltha:devices/voltha:pm_configs/voltha:metrics"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M16"/></axsl:template><axsl:template match="text()" priority="-1" mode="M16"/><axsl:template match="@*|node()" priority="-2" mode="M16"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M16"/></axsl:template>

<!--PATTERN idm139853992475568-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:logical_devices/voltha:ports/voltha:ofp_port/voltha:hw_addr" priority="1000" mode="M17"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:logical_devices/voltha:ports/voltha:ofp_port/voltha:hw_addr"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:hw_addr[voltha:hw_addr=current()/voltha:hw_addr]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:hw_addr[voltha:hw_addr=current()/voltha:hw_addr]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "hw_addr"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M17"/></axsl:template><axsl:template match="text()" priority="-1" mode="M17"/><axsl:template match="@*|node()" priority="-2" mode="M17"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M17"/></axsl:template>

<!--PATTERN idm139853992471552-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:logical_devices/voltha:flows/voltha:items" priority="1001" mode="M18"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:logical_devices/voltha:flows/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M18"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:logical_devices/voltha:flows/voltha:items/voltha:instructions" priority="1000" mode="M18"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:logical_devices/voltha:flows/voltha:items/voltha:instructions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M18"/></axsl:template><axsl:template match="text()" priority="-1" mode="M18"/><axsl:template match="@*|node()" priority="-2" mode="M18"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M18"/></axsl:template>

<!--PATTERN idm139853992470624-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:logical_devices/voltha:flow_groups/voltha:items" priority="1002" mode="M19"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:logical_devices/voltha:flow_groups/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M19"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets" priority="1001" mode="M19"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "weight"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M19"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions" priority="1000" mode="M19"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M19"/></axsl:template><axsl:template match="text()" priority="-1" mode="M19"/><axsl:template match="@*|node()" priority="-2" mode="M19"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M19"/></axsl:template>

<!--PATTERN idm139853992442064-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:devices/voltha:flows/voltha:items" priority="1001" mode="M20"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:devices/voltha:flows/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M20"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:devices/voltha:flows/voltha:items/voltha:instructions" priority="1000" mode="M20"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:devices/voltha:flows/voltha:items/voltha:instructions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M20"/></axsl:template><axsl:template match="text()" priority="-1" mode="M20"/><axsl:template match="@*|node()" priority="-2" mode="M20"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M20"/></axsl:template>

<!--PATTERN idm139853992441136-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:devices/voltha:flow_groups/voltha:items" priority="1002" mode="M21"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:devices/voltha:flow_groups/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M21"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets" priority="1001" mode="M21"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "weight"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M21"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions" priority="1000" mode="M21"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M21"/></axsl:template><axsl:template match="text()" priority="-1" mode="M21"/><axsl:template match="@*|node()" priority="-2" mode="M21"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M21"/></axsl:template>

<!--PATTERN idm139853992440208-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:devices/voltha:pm_configs/voltha:groups" priority="1002" mode="M22"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:devices/voltha:pm_configs/voltha:groups"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:groups[voltha:group_name=current()/voltha:group_name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:groups[voltha:group_name=current()/voltha:group_name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "group_name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M22"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:devices/voltha:pm_configs/voltha:groups/voltha:metrics" priority="1001" mode="M22"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:devices/voltha:pm_configs/voltha:groups/voltha:metrics"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M22"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:devices/voltha:pm_configs/voltha:metrics" priority="1000" mode="M22"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:devices/voltha:pm_configs/voltha:metrics"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M22"/></axsl:template><axsl:template match="text()" priority="-1" mode="M22"/><axsl:template match="@*|node()" priority="-2" mode="M22"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M22"/></axsl:template>

<!--PATTERN idm139853992420976-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:logical_devices/voltha:ports/voltha:ofp_port/voltha:hw_addr" priority="1000" mode="M23"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:logical_devices/voltha:ports/voltha:ofp_port/voltha:hw_addr"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:hw_addr[voltha:hw_addr=current()/voltha:hw_addr]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:hw_addr[voltha:hw_addr=current()/voltha:hw_addr]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "hw_addr"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M23"/></axsl:template><axsl:template match="text()" priority="-1" mode="M23"/><axsl:template match="@*|node()" priority="-2" mode="M23"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M23"/></axsl:template>

<!--PATTERN idm139853992416960-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:logical_devices/voltha:flows/voltha:items" priority="1001" mode="M24"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:logical_devices/voltha:flows/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M24"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:logical_devices/voltha:flows/voltha:items/voltha:instructions" priority="1000" mode="M24"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:logical_devices/voltha:flows/voltha:items/voltha:instructions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M24"/></axsl:template><axsl:template match="text()" priority="-1" mode="M24"/><axsl:template match="@*|node()" priority="-2" mode="M24"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M24"/></axsl:template>

<!--PATTERN idm139853992416032-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:logical_devices/voltha:flow_groups/voltha:items" priority="1002" mode="M25"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:logical_devices/voltha:flow_groups/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M25"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets" priority="1001" mode="M25"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "weight"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M25"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions" priority="1000" mode="M25"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M25"/></axsl:template><axsl:template match="text()" priority="-1" mode="M25"/><axsl:template match="@*|node()" priority="-2" mode="M25"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M25"/></axsl:template>

<!--PATTERN idm139853992387472-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices/voltha:flows/voltha:items" priority="1001" mode="M26"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices/voltha:flows/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M26"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices/voltha:flows/voltha:items/voltha:instructions" priority="1000" mode="M26"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices/voltha:flows/voltha:items/voltha:instructions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M26"/></axsl:template><axsl:template match="text()" priority="-1" mode="M26"/><axsl:template match="@*|node()" priority="-2" mode="M26"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M26"/></axsl:template>

<!--PATTERN idm139853992386544-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices/voltha:flow_groups/voltha:items" priority="1002" mode="M27"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices/voltha:flow_groups/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M27"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets" priority="1001" mode="M27"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "weight"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M27"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions" priority="1000" mode="M27"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M27"/></axsl:template><axsl:template match="text()" priority="-1" mode="M27"/><axsl:template match="@*|node()" priority="-2" mode="M27"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M27"/></axsl:template>

<!--PATTERN idm139853992385616-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices/voltha:pm_configs/voltha:groups" priority="1002" mode="M28"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices/voltha:pm_configs/voltha:groups"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:groups[voltha:group_name=current()/voltha:group_name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:groups[voltha:group_name=current()/voltha:group_name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "group_name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M28"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices/voltha:pm_configs/voltha:groups/voltha:metrics" priority="1001" mode="M28"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices/voltha:pm_configs/voltha:groups/voltha:metrics"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M28"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices/voltha:pm_configs/voltha:metrics" priority="1000" mode="M28"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:instances/voltha:device_groups/voltha:devices/voltha:pm_configs/voltha:metrics"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M28"/></axsl:template><axsl:template match="text()" priority="-1" mode="M28"/><axsl:template match="@*|node()" priority="-2" mode="M28"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M28"/></axsl:template>

<!--PATTERN idm139853992361888-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:logical_devices/voltha:ports/voltha:ofp_port/voltha:hw_addr" priority="1000" mode="M29"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:logical_devices/voltha:ports/voltha:ofp_port/voltha:hw_addr"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:hw_addr[voltha:hw_addr=current()/voltha:hw_addr]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:hw_addr[voltha:hw_addr=current()/voltha:hw_addr]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "hw_addr"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M29"/></axsl:template><axsl:template match="text()" priority="-1" mode="M29"/><axsl:template match="@*|node()" priority="-2" mode="M29"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M29"/></axsl:template>

<!--PATTERN idm139853992357872-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:logical_devices/voltha:flows/voltha:items" priority="1001" mode="M30"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:logical_devices/voltha:flows/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M30"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:logical_devices/voltha:flows/voltha:items/voltha:instructions" priority="1000" mode="M30"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:logical_devices/voltha:flows/voltha:items/voltha:instructions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M30"/></axsl:template><axsl:template match="text()" priority="-1" mode="M30"/><axsl:template match="@*|node()" priority="-2" mode="M30"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M30"/></axsl:template>

<!--PATTERN idm139853992356944-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:logical_devices/voltha:flow_groups/voltha:items" priority="1002" mode="M31"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:logical_devices/voltha:flow_groups/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M31"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets" priority="1001" mode="M31"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "weight"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M31"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions" priority="1000" mode="M31"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M31"/></axsl:template><axsl:template match="text()" priority="-1" mode="M31"/><axsl:template match="@*|node()" priority="-2" mode="M31"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M31"/></axsl:template>

<!--PATTERN idm139853992328384-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:devices/voltha:flows/voltha:items" priority="1001" mode="M32"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:devices/voltha:flows/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M32"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:devices/voltha:flows/voltha:items/voltha:instructions" priority="1000" mode="M32"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:devices/voltha:flows/voltha:items/voltha:instructions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M32"/></axsl:template><axsl:template match="text()" priority="-1" mode="M32"/><axsl:template match="@*|node()" priority="-2" mode="M32"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M32"/></axsl:template>

<!--PATTERN idm139853992327456-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:devices/voltha:flow_groups/voltha:items" priority="1002" mode="M33"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:devices/voltha:flow_groups/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M33"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets" priority="1001" mode="M33"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "weight"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M33"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions" priority="1000" mode="M33"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M33"/></axsl:template><axsl:template match="text()" priority="-1" mode="M33"/><axsl:template match="@*|node()" priority="-2" mode="M33"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M33"/></axsl:template>

<!--PATTERN idm139853992326528-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:devices/voltha:pm_configs/voltha:groups" priority="1002" mode="M34"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:devices/voltha:pm_configs/voltha:groups"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:groups[voltha:group_name=current()/voltha:group_name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:groups[voltha:group_name=current()/voltha:group_name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "group_name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M34"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:devices/voltha:pm_configs/voltha:groups/voltha:metrics" priority="1001" mode="M34"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:devices/voltha:pm_configs/voltha:groups/voltha:metrics"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M34"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:devices/voltha:pm_configs/voltha:metrics" priority="1000" mode="M34"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:devices/voltha:pm_configs/voltha:metrics"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M34"/></axsl:template><axsl:template match="text()" priority="-1" mode="M34"/><axsl:template match="@*|node()" priority="-2" mode="M34"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M34"/></axsl:template>

<!--PATTERN idm139853992312448-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:device_groups/voltha:logical_devices/voltha:ports/voltha:ofp_port/voltha:hw_addr" priority="1000" mode="M35"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:device_groups/voltha:logical_devices/voltha:ports/voltha:ofp_port/voltha:hw_addr"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:hw_addr[voltha:hw_addr=current()/voltha:hw_addr]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:hw_addr[voltha:hw_addr=current()/voltha:hw_addr]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "hw_addr"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M35"/></axsl:template><axsl:template match="text()" priority="-1" mode="M35"/><axsl:template match="@*|node()" priority="-2" mode="M35"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M35"/></axsl:template>

<!--PATTERN idm139853992308432-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:device_groups/voltha:logical_devices/voltha:flows/voltha:items" priority="1001" mode="M36"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:device_groups/voltha:logical_devices/voltha:flows/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M36"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:device_groups/voltha:logical_devices/voltha:flows/voltha:items/voltha:instructions" priority="1000" mode="M36"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:device_groups/voltha:logical_devices/voltha:flows/voltha:items/voltha:instructions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M36"/></axsl:template><axsl:template match="text()" priority="-1" mode="M36"/><axsl:template match="@*|node()" priority="-2" mode="M36"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M36"/></axsl:template>

<!--PATTERN idm139853992307504-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:device_groups/voltha:logical_devices/voltha:flow_groups/voltha:items" priority="1002" mode="M37"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:device_groups/voltha:logical_devices/voltha:flow_groups/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M37"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:device_groups/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets" priority="1001" mode="M37"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:device_groups/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "weight"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M37"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:device_groups/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions" priority="1000" mode="M37"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:device_groups/voltha:logical_devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M37"/></axsl:template><axsl:template match="text()" priority="-1" mode="M37"/><axsl:template match="@*|node()" priority="-2" mode="M37"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M37"/></axsl:template>

<!--PATTERN idm139853992278944-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices/voltha:flows/voltha:items" priority="1001" mode="M38"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices/voltha:flows/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:id=current()/voltha:id]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "id"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M38"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices/voltha:flows/voltha:items/voltha:instructions" priority="1000" mode="M38"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices/voltha:flows/voltha:items/voltha:instructions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M38"/></axsl:template><axsl:template match="text()" priority="-1" mode="M38"/><axsl:template match="@*|node()" priority="-2" mode="M38"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M38"/></axsl:template>

<!--PATTERN idm139853992278016-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices/voltha:flow_groups/voltha:items" priority="1002" mode="M39"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices/voltha:flow_groups/voltha:items"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:items[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M39"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets" priority="1001" mode="M39"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:buckets[voltha:weight=current()/voltha:weight]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "weight"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M39"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions" priority="1000" mode="M39"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices/voltha:flow_groups/voltha:items/voltha:buckets/voltha:actions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M39"/></axsl:template><axsl:template match="text()" priority="-1" mode="M39"/><axsl:template match="@*|node()" priority="-2" mode="M39"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M39"/></axsl:template>

<!--PATTERN idm139853992277088-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices/voltha:pm_configs/voltha:groups" priority="1002" mode="M40"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices/voltha:pm_configs/voltha:groups"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:groups[voltha:group_name=current()/voltha:group_name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:groups[voltha:group_name=current()/voltha:group_name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "group_name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M40"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices/voltha:pm_configs/voltha:groups/voltha:metrics" priority="1001" mode="M40"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices/voltha:pm_configs/voltha:groups/voltha:metrics"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M40"/></axsl:template>

	<!--RULE -->
<axsl:template match="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices/voltha:pm_configs/voltha:metrics" priority="1000" mode="M40"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:Voltha/voltha:device_groups/voltha:devices/voltha:pm_configs/voltha:metrics"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:metrics[voltha:name=current()/voltha:name]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "name"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M40"/></axsl:template><axsl:template match="text()" priority="-1" mode="M40"/><axsl:template match="@*|node()" priority="-2" mode="M40"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M40"/></axsl:template>

<!--PATTERN idm139853992264352-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_hello/voltha:elements/voltha:versionbitmap/voltha:bitmaps" priority="1000" mode="M41"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_hello/voltha:elements/voltha:versionbitmap/voltha:bitmaps"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:bitmaps[voltha:bitmaps=current()/voltha:bitmaps]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:bitmaps[voltha:bitmaps=current()/voltha:bitmaps]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "bitmaps"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M41"/></axsl:template><axsl:template match="text()" priority="-1" mode="M41"/><axsl:template match="@*|node()" priority="-2" mode="M41"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M41"/></axsl:template>

<!--PATTERN idm139853992242320-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_flow_removed/voltha:match/voltha:oxm_fields" priority="1000" mode="M42"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_flow_removed/voltha:match/voltha:oxm_fields"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:oxm_fields[voltha:oxm_class=current()/voltha:oxm_class]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:oxm_fields[voltha:oxm_class=current()/voltha:oxm_class]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "oxm_class"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M42"/></axsl:template><axsl:template match="text()" priority="-1" mode="M42"/><axsl:template match="@*|node()" priority="-2" mode="M42"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M42"/></axsl:template>

<!--PATTERN idm139853992198304-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_flow_stats_request/voltha:match/voltha:oxm_fields" priority="1000" mode="M43"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_flow_stats_request/voltha:match/voltha:oxm_fields"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:oxm_fields[voltha:oxm_class=current()/voltha:oxm_class]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:oxm_fields[voltha:oxm_class=current()/voltha:oxm_class]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "oxm_class"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M43"/></axsl:template><axsl:template match="text()" priority="-1" mode="M43"/><axsl:template match="@*|node()" priority="-2" mode="M43"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M43"/></axsl:template>

<!--PATTERN idm139853992192064-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_aggregate_stats_request/voltha:match/voltha:oxm_fields" priority="1000" mode="M44"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_aggregate_stats_request/voltha:match/voltha:oxm_fields"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:oxm_fields[voltha:oxm_class=current()/voltha:oxm_class]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:oxm_fields[voltha:oxm_class=current()/voltha:oxm_class]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "oxm_class"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M44"/></axsl:template><axsl:template match="text()" priority="-1" mode="M44"/><axsl:template match="@*|node()" priority="-2" mode="M44"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M44"/></axsl:template>

<!--PATTERN idm139853992179296-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_table_features/voltha:properties/voltha:instructions/voltha:instructions" priority="1000" mode="M45"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_table_features/voltha:properties/voltha:instructions/voltha:instructions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:instructions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M45"/></axsl:template><axsl:template match="text()" priority="-1" mode="M45"/><axsl:template match="@*|node()" priority="-2" mode="M45"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M45"/></axsl:template>

<!--PATTERN idm139853992178336-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_table_features/voltha:properties/voltha:next_tables/voltha:next_table_ids" priority="1000" mode="M46"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_table_features/voltha:properties/voltha:next_tables/voltha:next_table_ids"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:next_table_ids[voltha:next_table_ids=current()/voltha:next_table_ids]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:next_table_ids[voltha:next_table_ids=current()/voltha:next_table_ids]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "next_table_ids"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M46"/></axsl:template><axsl:template match="text()" priority="-1" mode="M46"/><axsl:template match="@*|node()" priority="-2" mode="M46"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M46"/></axsl:template>

<!--PATTERN idm139853992177376-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_table_features/voltha:properties/voltha:actions/voltha:actions" priority="1000" mode="M47"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_table_features/voltha:properties/voltha:actions/voltha:actions"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:actions[voltha:type=current()/voltha:type]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "type"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M47"/></axsl:template><axsl:template match="text()" priority="-1" mode="M47"/><axsl:template match="@*|node()" priority="-2" mode="M47"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M47"/></axsl:template>

<!--PATTERN idm139853992176432-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_table_features/voltha:properties/voltha:oxm/voltha:oxm_ids" priority="1000" mode="M48"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_table_features/voltha:properties/voltha:oxm/voltha:oxm_ids"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:oxm_ids[voltha:oxm_ids=current()/voltha:oxm_ids]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:oxm_ids[voltha:oxm_ids=current()/voltha:oxm_ids]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "oxm_ids"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M48"/></axsl:template><axsl:template match="text()" priority="-1" mode="M48"/><axsl:template match="@*|node()" priority="-2" mode="M48"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M48"/></axsl:template>

<!--PATTERN idm139853992175488-->


	<!--RULE -->
<axsl:template match="/nc:config/voltha:ofp_table_features/voltha:properties/voltha:experimenter/voltha:experimenter_data" priority="1000" mode="M49"><svrl:fired-rule xmlns:svrl="http://purl.oclc.org/dsdl/svrl" context="/nc:config/voltha:ofp_table_features/voltha:properties/voltha:experimenter/voltha:experimenter_data"/>

		<!--REPORT -->
<axsl:if test="preceding-sibling::voltha:experimenter_data[voltha:experimenter_data=current()/voltha:experimenter_data]"><svrl:successful-report xmlns:svrl="http://purl.oclc.org/dsdl/svrl" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:schold="http://www.ascc.net/xml/schematron" test="preceding-sibling::voltha:experimenter_data[voltha:experimenter_data=current()/voltha:experimenter_data]"><axsl:attribute name="location"><axsl:apply-templates select="." mode="schematron-get-full-path"/></axsl:attribute><svrl:text>Duplicate key "experimenter_data"</svrl:text></svrl:successful-report></axsl:if><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M49"/></axsl:template><axsl:template match="text()" priority="-1" mode="M49"/><axsl:template match="@*|node()" priority="-2" mode="M49"><axsl:apply-templates select="*|comment()|processing-instruction()" mode="M49"/></axsl:template></axsl:stylesheet>
