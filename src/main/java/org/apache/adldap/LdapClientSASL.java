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
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.Subject;

import org.apache.adldap.LdapClientSimple.DummyTrustmanager;
import org.apache.adldap.LdapClientSimple.LdapSSLSocketFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Hashtable;



public class LdapClientSASL extends LdapClient {
	InitialDirContext ldapCtx;
	Hashtable<String, Object> env;
	String ldapUrl;
	String bindDN;
	String bindPW;
	String baseDN;
	Subject subject;
	SearchControls constraints;
	LdapBean ldapBean;
	
	/**
	* Create a LdapClient with baseDn, ldapURL.
	* @param baseDN
    * @param ldapURL
	*/	
	public LdapClientSASL(String baseDN, String ldapUrl, Subject subject) {
		this.ldapUrl = ldapUrl;
		this.baseDN = baseDN;
		this.subject = subject;
		this.ldapBean = (LdapBean) Subject.doAs(this.subject,new LdapClientSASLImpl(baseDN, ldapUrl));

	}
	
	@Override
	public LdapBean getLdapBean() {
		return this.ldapBean;
	}
	
	public Hashtable<String, Object> getEnv(){
		return this.env;
	}
	

	
}
