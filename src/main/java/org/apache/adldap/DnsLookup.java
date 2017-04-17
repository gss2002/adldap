/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.adldap;

import java.util.Hashtable;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DnsLookup {
	private static final Logger LOG = LoggerFactory.getLogger(DnsLookup.class);
	private static final String MX_ATTRIB = "MX";
	private static final String ADDR_ATTRIB = "A";
	private static final String SRV_ATTRIB = "SRV";
	private static String[] MX_ATTRIBS = { MX_ATTRIB };
	private static String[] ADDR_ATTRIBS = { ADDR_ATTRIB };
	private static String[] SRV_ATTRIBS = { SRV_ATTRIB };

	public static void main(String[] args) {
		// TODO Auto-generated method stub

		Hashtable<String, String> env = new Hashtable<String, String>();
		env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
		DirContext ctx = null;
		try {
			ctx = new InitialDirContext(env);
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			Attributes attrs = ctx.getAttributes("_kerberos._tcp.hdpusr.senia.org", SRV_ATTRIBS);
			Attribute attr = attrs.get(SRV_ATTRIB);

			if (attr != null) {
				for (int i = 0; i < attr.size(); i++) {
					String srvAttr = (String) attr.get(i);
					String[] parts = srvAttr.split(" ");
					LOG.debug(parts[parts.length - 1]);
					// Split off the priority, and take the last field
					// servers.add(parts[parts.length - 1]);
				}
			}
			ctx.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			LOG.error(e.getMessage());
		}
	}

	public String getLdapServer(String domain) {
		// TODO Auto-generated method stub

		Hashtable<String, String> env = new Hashtable<String, String>();
		env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
		DirContext ctx = null;
		try {
			ctx = new InitialDirContext(env);
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			LOG.error(e.getMessage());
		}
		try {
			Attributes attrs = ctx.getAttributes("_kerberos._tcp.gaadc._sites." + domain, SRV_ATTRIBS);
			Attribute attr = attrs.get(SRV_ATTRIB);

			if (attr != null) {
				for (int i = 0; i < attr.size(); i++) {
					String srvAttr = (String) attr.get(i);
					String[] parts = srvAttr.split(" ");
					LOG.debug(parts[parts.length - 1]);
					return parts[parts.length - 1].substring(0, parts[parts.length - 1].length() - 1);
					// Split off the priority, and take the last field
					// servers.add(parts[parts.length - 1]);
				}
			}
			ctx.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			LOG.error(e.getMessage());
		}
		return domain;
	}
}
