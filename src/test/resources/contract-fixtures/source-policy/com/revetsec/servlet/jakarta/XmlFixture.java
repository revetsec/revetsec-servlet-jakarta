/*
 * Copyright 2026 Revetware LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.revetsec.servlet.jakarta;

import javax.xml.xpath.*;

/**
 * Seeded violations: adapters never name the XML factory types, use XPath (the on-demand import names the package)
 * or look DOM elements up without a namespace. The namespace-aware lookup is a control.
 */
final class XmlFixture {
	void seeded(org.w3c.dom.Document document) throws Exception {
		javax.xml.parsers.DocumentBuilderFactory.newInstance();
		javax.xml.parsers.SAXParserFactory.newInstance();
		javax.xml.transform.TransformerFactory.newInstance();
		javax.xml.validation.SchemaFactory.newDefaultInstance();
		javax.xml.stream.XMLInputFactory.newFactory();
		org.xml.sax.helpers.XMLReaderFactory.createXMLReader();
		XPathFactory.newInstance();
		XPathConstants.NODESET.getLocalPart();
		document.getElementsByTagName("Assertion");
		java.util.function.Function<String, org.w3c.dom.NodeList> lookup = document::getElementsByTagName;
		document.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion");
	}
}
