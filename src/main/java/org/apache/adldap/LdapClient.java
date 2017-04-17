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

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LdapClient {
	private LdapBean ldapBean;
	private static final Logger LOG = LoggerFactory.getLogger(LdapClient.class);

	public LdapClient() {

	}

	public LdapBean getLdapBean() {
		return ldapBean;
	}

	public static void destroyLdapClient(InitialDirContext ldapCtx) {
		if (ldapCtx != null) {
			try {
				LOG.info("Closing Connection: " + ldapCtx.getEnvironment().get(Context.PROVIDER_URL));
				ldapCtx.close();
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
}
