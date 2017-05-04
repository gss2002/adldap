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
import javax.naming.directory.SearchControls;


import java.security.PrivilegedAction;
import java.util.Hashtable;



public class LdapClientSASLImpl implements PrivilegedAction<Object> {
	InitialDirContext ldapCtx;
	Hashtable<String, Object> env;
	String ldapUrl;
	String baseDN;
	SearchControls constraints;
	LdapBean ldapbean;
	
	/**
	* Create a LdapClient with baseDn and ldapURL.
	* @param baseDN
    * @param ldapURL
	*/	
	public LdapClientSASLImpl(String baseDN, String ldapUrl) {
		this.ldapUrl = ldapUrl;
		this.baseDN = baseDN;
	}
	
	public Hashtable<String, Object> getEnv(){
		return this.env;
	}
	
	public LdapBean createLdapClient() {
		// Create a trust manager that does not validate certificate chains

		// Install the all-trusting trust manager
		
		this.env = new Hashtable<String, Object>();
	    this.env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        this.env.put(Context.PROVIDER_URL, this.ldapUrl);
        if (System.getProperty("ldap.ssl") != null) {
        	if (System.getProperty("ldap.ssl").equalsIgnoreCase("true")) {
        		this.env.put(Context.SECURITY_PROTOCOL, "ssl");
        		this.env.put("java.naming.ldap.factory.socket", LdapTrustManager.LdapSSLSocketFactory.class.getName());
        	}
        }
        this.env.put(Context.SECURITY_AUTHENTICATION, "GSSAPI");
        this.env.put("java.naming.ldap.attributes.binary", "objectGUID");
        this.env.put("javax.security.sasl.server.authentication", "true");

		try {
			ldapCtx = new InitialDirContext(this.env);
	    	this.constraints = new SearchControls();
	    	this.constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
		} catch (NamingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
	
		}
		this.ldapbean = new LdapBean();
		this.ldapbean.setConstraints(this.constraints);
		this.ldapbean.setLdapCtx(this.ldapCtx);
		return this.ldapbean;
	}
	
	public void destroyLdapClient() {
		if (ldapCtx != null){
			try {
				ldapCtx.close();
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	  

		@Override
		public LdapBean run() {
			// TODO Auto-generated method stub
			return this.createLdapClient();
		}

	
	
}