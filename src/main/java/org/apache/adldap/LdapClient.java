package org.apache.adldap;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;

public class LdapClient {
    private LdapBean ldapBean;
    private InitialDirContext ldapCtx;

    public LdapClient() {
    	
    }
    public LdapBean getLdapBean() {
        return ldapBean;
    }
	public static void destroyLdapClient(InitialDirContext ldapCtx) {
		if (ldapCtx != null){
			try {
				System.out.println("Closing Conntection: "+ldapCtx.getEnvironment().get(Context.PROVIDER_URL));
				ldapCtx.close();
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
}
