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
