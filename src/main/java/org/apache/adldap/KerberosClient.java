package org.apache.adldap;

import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import java.security.Principal;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;

public class KerberosClient {
	private static final Logger LOG = LoggerFactory.getLogger(KerberosClient.class);

	private final static String JAAS_IBM = "JaasIBM";
	private final static String JAAS_SUN = "JaasSUN";
	Subject subject;
	public static final String JAVA_VENDOR_NAME = System.getProperty("java.vendor");
	public static final boolean IBM_JAVA = JAVA_VENDOR_NAME.contains("IBM");
	InitialDirContext ldapCtx;
	Hashtable<String, Object> env;
	String upn;
	String upnPw;
	String upnKeyTab;

	/**
	 * Create a LdapClient with bindDN, bindPW.
	 * 
	 * @param upn
	 * @param upnPw
	 */
	public KerberosClient(String upn, String upnPw, String upnKeyTab) {
		this.upn = upn;
		this.upnPw = upnPw;
		this.upnKeyTab = upnKeyTab;
		LOG.debug("InitContext Start: " + System.currentTimeMillis());
		reinitContext();
		LOG.debug("InitContext Complete: " + System.currentTimeMillis());
	}
	public KerberosClient(String upn) {
		this.upn = upn;
		LOG.debug("InitContext Start: " + System.currentTimeMillis());
		reinitContext();
		LOG.debug("InitContext Complete: " + System.currentTimeMillis());
	}
	
	public void reinitContext() {
		LOG.debug("InitContext Start: " + System.currentTimeMillis());
		if (this.upnPw != null && this.upnKeyTab == null) {
			LOG.debug("UPN w/Password: " + System.currentTimeMillis());
			this.initContextUp(this.upn, this.upnPw);
		}
		if (this.upnPw == null && this.upnKeyTab != null) {
			LOG.debug("UPN w/keytab: " + System.currentTimeMillis());
			LOG.debug("UPN w/keytab: " +this.upnKeyTab);
			LOG.debug("UPN: " +this.upn);

			this.initContextKeyTab(this.upn, this.upnKeyTab);
		}
		if (this.upnPw == null && this.upnKeyTab == null && this.upn != null) {
			LOG.debug("UPN: " +this.upn);
			this.initContextCCcache(this.upn);
		}
		LOG.debug("InitContext Complete: " + System.currentTimeMillis());
	}

	public Subject getSubject() {
		return this.subject;

	}

	public void initContextUp(String realUserIn, String realPasswdIn) {
		javax.security.auth.login.Configuration config = null;
		config = new KrbUPAuthConfig(realUserIn, realPasswdIn);

		// THIS SETS THE LoginContext Object and performs a login with the
		// credentials
		// from above and passes the KrbAuthConfig Object Class in as the
		// configuration
		LoginContext context = null;
		try {
			if (IBM_JAVA) {
				context = new LoginContext(JAAS_IBM, null, new UPLoginCallbackHandler(realUserIn, realPasswdIn),
						config);
			} else {
				context = new LoginContext(JAAS_SUN, null, new UPLoginCallbackHandler(realUserIn, realPasswdIn),
						config);

			}
		} catch (LoginException e) {
			// TODO Auto-generated catch block
			LOG.error(e.getMessage());
		}

		// Log the Context in
		try {
			LOG.debug("ContextLogin Start: " + System.currentTimeMillis());
			context.login();
			LOG.debug("ContextLogin Complete: " + System.currentTimeMillis());

		} catch (LoginException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Obtain the Sec SUJECT FROM THE LOGINCONTEXT!!!
		this.subject = context.getSubject();
		LOG.debug("getSubject Complete: " + System.currentTimeMillis());

	}
	
	public void initContextKeyTab(String realUserIn, String keyTab) {
		javax.security.auth.login.Configuration config = null;
		config = new KrbKeytabAuthConfig(realUserIn, keyTab);

		// THIS SETS THE LoginContext Object and performs a login with the
		// credentials
		// from above and passes the KrbAuthConfig Object Class in as the
		// configuration
		LoginContext context = null;
		try {
			if (IBM_JAVA) {
				context = new LoginContext(JAAS_IBM, null, null, config);
			} else {
				context = new LoginContext(JAAS_SUN, null, null, config);
			}
		} catch (LoginException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Log the Context in
		try {
			LOG.debug("ContextLogin Start: " + System.currentTimeMillis());
			context.login();
			LOG.debug("ContextLogin Complete: " + System.currentTimeMillis());

		} catch (LoginException e) {
			// TODO Auto-generated catch block
			LOG.error(e.getMessage());
		}

		// Obtain the Sec SUJECT FROM THE LOGINCONTEXT!!!
		this.subject = context.getSubject();
		LOG.debug("getSubject Complete: " + System.currentTimeMillis());

	}
	
	public void initContextCCcache(String realUserIn) {
		javax.security.auth.login.Configuration config = null;
		config = new KrbCCacheAuthConfig(realUserIn);

		// THIS SETS THE LoginContext Object and performs a login with the
		// credentials
		// from above and passes the KrbAuthConfig Object Class in as the
		// configuration
		LoginContext context = null;
		try {
			if (IBM_JAVA) {
				context = new LoginContext(JAAS_IBM, null, null, config);
			} else {
				context = new LoginContext(JAAS_SUN, null, null, config);
			}
		} catch (LoginException e) {
			// TODO Auto-generated catch block
			LOG.error(e.getMessage());
		}

		// Log the Context in
		try {
			LOG.debug("ContextLogin Start: " + System.currentTimeMillis());
			context.login();
			LOG.debug("ContextLogin Complete: " + System.currentTimeMillis());

		} catch (LoginException e) {
			// TODO Auto-generated catch block
			LOG.error(e.getMessage());
		}

		// Obtain the Sec SUJECT FROM THE LOGINCONTEXT!!!
		this.subject = context.getSubject();
		LOG.debug("getSubject Complete: " + System.currentTimeMillis());

	}

	/**
	 * KrbAuthConfig maintains Kerberos Configuration information for
	 * username/password authentication without keytab or kinit.
	 */

	static class KrbUPAuthConfig extends javax.security.auth.login.Configuration {
		// THIS INNER CLASS DYNAMICALLY BUILDS THE JAAS.CONF FILE

		private Map<String, Object> configMap = new HashMap<String, Object>();

		KrbUPAuthConfig(String user, String pass) {
			// LOG.info("UserPassword HDFSAUTH: "+user);
			Map<String, String> options = new HashMap<String, String>();
			if (IBM_JAVA) {
				options.put("debug", "false");
				options.put("forwardable", "true");
				options.put("principal", user);
				options.put("credsType", "initiator");
				options.put("moduleBanner", "true");
				options.put("useFirstPass", "true");
				configMap.put(JAAS_IBM,
						new AppConfigurationEntry[] {
								new AppConfigurationEntry("com.ibm.security.auth.module.Krb5LoginModule",
										LoginModuleControlFlag.REQUIRED, options) });
			} else {
				options.put("principal", user);
				options.put("debug", "false");
				options.put("useTicketCache", "false");
				options.put("useKeyTab", "false");
				options.put("doNotPrompt", "false");
				options.put("isInitiator", "true");
				options.put("storePass", "true");
				options.put("forwardable", "true");
				configMap.put(JAAS_SUN,
						new AppConfigurationEntry[] {
								new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
										LoginModuleControlFlag.REQUIRED, options) });

			}

		}

		public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
			return (AppConfigurationEntry[]) configMap.get(name);
		}

	}

	/**
	 * KrbAuthConfig maintains Kerberos Configuration information for
	 * username/password authentication without keytab or kinit.
	 */

	static class KrbKeytabAuthConfig extends javax.security.auth.login.Configuration {
		// THIS INNER CLASS DYNAMICALLY BUILDS THE JAAS.CONF FILE

		private Map<String, Object> configMap = new HashMap<String, Object>();

		KrbKeytabAuthConfig(String user, String keyTab) {
			// LOG.info("UserPassword HDFSAUTH: "+user);
			Map<String, String> options = new HashMap<String, String>();
			if (IBM_JAVA) {
				options.put("debug", "false");
				options.put("forwardable", "true");
				options.put("principal", user);
				options.put("credsType", "initiator");
				options.put("moduleBanner", "true");
				options.put("useFirstPass", "true");
				configMap.put(JAAS_IBM,
						new AppConfigurationEntry[] {
								new AppConfigurationEntry("com.ibm.security.auth.module.Krb5LoginModule",
										LoginModuleControlFlag.REQUIRED, options) });
			} else {
				LOG.debug("User:"+user);
				options.put("principal", user);
				options.put("debug", "false");
				options.put("useTicketCache", "false");
				options.put("useKeyTab", "true");
				options.put("storeKey", "true");
				options.put("keyTab", keyTab);
				options.put("forwardable", "true");
				configMap.put(JAAS_SUN,
						new AppConfigurationEntry[] {
								new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
										LoginModuleControlFlag.REQUIRED, options) });

			}


		}

		@Override
		public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
			return (AppConfigurationEntry[]) configMap.get(name);
		}
    }

		static class KrbCCacheAuthConfig extends javax.security.auth.login.Configuration {
			// THIS INNER CLASS DYNAMICALLY BUILDS THE JAAS.CONF FILE

			private Map<String, Object> configMap = new HashMap<String, Object>();
			String ticketCache = System.getenv("KRB5CCNAME");

			KrbCCacheAuthConfig(String user) {
				// LOG.info("UserPassword HDFSAUTH: "+user);
				Map<String, String> options = new HashMap<String, String>();
				if (IBM_JAVA) {
					options.put("debug", "false");
					options.put("forwardable", "true");
					options.put("principal", user);
					options.put("credsType", "initiator");
					options.put("moduleBanner", "true");
					options.put("useFirstPass", "true");
					options.put("useDefaultCcache", "true");
					System.setProperty("KRB5CCNAME", ticketCache);
					configMap.put(JAAS_IBM,
							new AppConfigurationEntry[] {
									new AppConfigurationEntry("com.ibm.security.auth.module.Krb5LoginModule",
											LoginModuleControlFlag.REQUIRED, options) });
				} else {
					LOG.debug("User:" + user);
					options.put("principal", user);
					options.put("debug", "false");
					options.put("useTicketCache", "true");
					options.put("useKeyTab", "false");
					options.put("storeKey", "false");
					options.put("forwardable", "true");
					options.put("ticketCache", ticketCache);
					configMap.put(JAAS_SUN,
							new AppConfigurationEntry[] {
									new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
											LoginModuleControlFlag.REQUIRED, options) });

				}

			}

			@Override
			public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
				return (AppConfigurationEntry[]) configMap.get(name);
			}
		}


}