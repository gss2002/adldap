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
import java.util.Hashtable;

public class LdapClientSimple extends LdapClient {
	InitialDirContext ldapCtx;
	Hashtable<String, Object> env;
	String ldapUrl;
	String bindDN;
	String bindPW;
	String baseDN;
	SearchControls constraints;
	LdapBean ldapBean;
	
	/**
	* Create a LdapClient with baseDn, bindDN, bindPW, and ldapURL.
	* @param baseDN
	* @param bindDN
	* @param bindPW
    * @param ldapURL
	*/	
	public LdapClientSimple(String baseDN, String bindDN, String bindPW, String ldapUrl) {
		this.ldapUrl = ldapUrl;
		this.bindDN = bindDN;
		this.bindPW = bindPW;
		this.baseDN = baseDN;
		this.ldapBean = this.createLdapClient();
	}
	
	@Override
	public LdapBean getLdapBean() {
		return this.ldapBean;
	}
	
	public Hashtable<String, Object> getEnv(){
		return this.env;
	}
	
	
	public LdapBean createLdapClient() {
		// Create a trust manager that does not validate certificate chains

		// Install the all-trusting trust manager
		
		this.env = new Hashtable<String, Object>();
	    this.env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        this.env.put(Context.SECURITY_PROTOCOL, "ssl");
        this.env.put(Context.PROVIDER_URL, this.ldapUrl);
        this.env.put("java.naming.ldap.factory.socket", LdapTrustManager.LdapSSLSocketFactory.class.getName());
	    
        this.env.put(Context.SECURITY_AUTHENTICATION, "simple");
        this.env.put(Context.SECURITY_PRINCIPAL, this.bindDN);
        this.env.put(Context.SECURITY_CREDENTIALS, this.bindPW);
        this.env.put("java.naming.ldap.attributes.binary", "objectGUID");
		try {
			ldapCtx = new InitialDirContext(this.env);
	    	this.constraints = new SearchControls();
	    	this.constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
		} catch (NamingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
	
		}
		this.ldapBean = new LdapBean();
		this.ldapBean.setConstraints(this.constraints);
		this.ldapBean.setLdapCtx(this.ldapCtx);
		return this.ldapBean;

	}

	
}
