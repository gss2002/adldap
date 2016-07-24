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