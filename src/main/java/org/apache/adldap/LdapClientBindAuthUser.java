package org.apache.adldap;

import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;

public class LdapClientBindAuthUser {

	private String gcldapURL;

	public LdapClientBindAuthUser(String gcldapURL) {
		this.gcldapURL = gcldapURL;
	}

	public boolean authBindUser(String userDn, String pwd) {
		InitialDirContext ldapCtx = null;
		Hashtable<String, Object> env = null;
		Boolean authn = false;
		env = new Hashtable<String, Object>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.SECURITY_PROTOCOL, "ssl");
		env.put(Context.PROVIDER_URL, this.gcldapURL);
		env.put("java.naming.ldap.factory.socket", LdapTrustManager.LdapSSLSocketFactory.class.getName());
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		env.put(Context.SECURITY_PRINCIPAL, userDn);
		env.put(Context.SECURITY_CREDENTIALS, pwd);
		env.put("java.naming.ldap.attributes.binary", "objectGUID");
		try {
			ldapCtx = new InitialDirContext(env);
			if (ldapCtx != null) {
				ldapCtx.close();
			}
			authn = true;
		} catch (NamingException e1) {
			ldapCtx = null;
			authn = false;
		} finally {
			if (ldapCtx != null) {
				try {
					ldapCtx.close();
				} catch (NamingException e) {
					e.printStackTrace();
				}
			}
		}
		return authn;
	}
}