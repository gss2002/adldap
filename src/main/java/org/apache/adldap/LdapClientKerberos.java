package org.apache.adldap;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

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
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;

public class LdapClientKerberos {
    private final static String JAAS_IBM = "JaasIBM";
    private final static String JAAS_SUN = "JaasSUN";
    public static final String JAVA_VENDOR_NAME = System.getProperty("java.vendor");
    public static final boolean IBM_JAVA = JAVA_VENDOR_NAME.contains("IBM");
	InitialDirContext ldapCtx;
	Hashtable<String, Object> env;
	String ldapUrl;
	String bindDN;
	String bindPW;
	String baseDN;
	SearchControls constraints;
	
	/**
	* Create a LdapClient with baseDn, bindDN, bindPW, and ldapURL.
	* @param baseDN
	* @param bindDN
	* @param bindPW
    * @param ldapURL
	*/	
	public LdapClientKerberos(String baseDN, String bindDN, String bindPW, String ldapUrl) {
		this.ldapUrl = ldapUrl;
		this.bindDN = bindDN;
		this.bindPW = bindPW;
		this.baseDN = baseDN;
		this.createLdapClient();
	}
	
	public Hashtable<String, Object> getEnv(){
		return this.env;
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
	
	public void test() {
	    javax.security.auth.login.Configuration config = null;
	  	config = new KrbAuthConfig(realUserIn, realPasswdIn);


	    // THIS SETS THE LoginContext Object and performs a login with the credentials 
	    //from above and passes the HiveAuthConfig Object Class in as the configuration
	    LoginContext context = null;
		try {
	         if (IBM_JAVA) {
	        	 context = new LoginContext(JAAS_IBM,null,new UPLoginCallbackHandler(realUserIn,realPasswdIn), config);
	         } else {
	        	 context = new LoginContext(JAAS_SUN,null,new UPLoginCallbackHandler(realUserIn,realPasswdIn), config);

	         }
		} catch (LoginException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	    // Log the Context in
	    try {
			context.login();
		} catch (LoginException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    
	    //Obtain the Sec SUJECT FROM THE LOGINCONTEXT!!!
	    Subject subject = context.getSubject();
	    
	    // EXTRA SEE THE INFO ABOUT THE TICKET!!
        if (IBM_JAVA) {

        	KerberosTicket ticket = (KerberosTicket) subject.getPrivateCredentials(KerberosTicket.class).iterator().next();
        	if (ticket.isForwardable()) {
        		LOG.debug("The ticket is forwardable");
        		LOG.debug("Ticket Info: "+ticket.getClient().getName());
        	} else {
        		LOG.debug("The ticket is not forwardable");
        	}
        	LOG.debug(ticket);
        }
	    
	    
	    Set<Principal> loginPrincipals = subject.getPrincipals();
	    if (loginPrincipals.isEmpty()) {
	      throw new RuntimeException("No login principals found!");
	    }
	    LOG.debug("LoginPrincipals: "+loginPrincipals);
	    if (loginPrincipals.size() != 1) {
	      LOG.warn("found more than one principal found");
	    }

	    subject.getPrincipals().add(ugiUser);
	    
	    LOG.debug("SubjectPrincipals: "+subject.getPrincipals());

	}
	
	public void createLdapClient() {
		// Create a trust manager that does not validate certificate chains

		// Install the all-trusting trust manager
		
		this.env = new Hashtable<String, Object>();
	    this.env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        this.env.put(Context.SECURITY_PROTOCOL, "ssl");
        this.env.put(Context.PROVIDER_URL, this.ldapUrl);
        this.env.put("java.naming.ldap.factory.socket", LdapClientKerberos.LdapSSLSocketFactory.class.getName());
	    
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

	}
	
	  /** 
	   * HDFSAuthConfig maintains UGI Configuration information
	   * for username/password authentication without keytab or kinit.
	   */
	  
	  static class KrbAuthConfig extends javax.security.auth.login.Configuration {
	      // THIS INNER CLASS DYNAMICALLY BUILDS THE JAAS.CONF FILE

	      private Map<String, Object> configMap = new HashMap<String, Object>();
	      KrbAuthConfig(String user, String pass)
	      {
	    	 //LOG.info("UserPassword HDFSAUTH: "+user);
	         Map<String,String> options = new HashMap<String,String>(); 
	         if (IBM_JAVA) {
		         options.put("debug","true");  
		         options.put("forwardable", "true");
		         options.put("principal", user);
		         options.put("credsType", "initiator");
		         options.put("moduleBanner", "true");
		         options.put("useFirstPass", "true");
	        	 configMap.put(JAAS_IBM, new AppConfigurationEntry[]{ new AppConfigurationEntry("com.ibm.security.auth.module.Krb5LoginModule",LoginModuleControlFlag.REQUIRED,options)});
	         } else {
				  options.put("principal", user);
				  options.put("debug", "true");
				  options.put("useTicketCache", "false");
				  options.put("useKeyTab", "false");
				  options.put("doNotPrompt","false");
				  options.put("isInitiator", "true");
	              options.put("storePass", "true");
				  options.put("forwardable", "true");
		         configMap.put(JAAS_SUN, new AppConfigurationEntry[]{ new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",LoginModuleControlFlag.REQUIRED,options)});

	         }

	      }
	      public AppConfigurationEntry[] getAppConfigurationEntry(String name)
	      {
	         return (AppConfigurationEntry[]) configMap.get(name);
	      }
	      
	      public void refresh()
	      {
	      	
	      }
	}
	  
	
	
	public static class DummyTrustmanager implements X509TrustManager {
		  public void checkClientTrusted(X509Certificate[] xcs, String string) throws CertificateException
		  {
		    // do nothing
		  }
		  public void checkServerTrusted(X509Certificate[] xcs, String string) throws CertificateException
		  {
		    // do nothing
		  }
		  public X509Certificate[] getAcceptedIssuers()
		  {
		    return new java.security.cert.X509Certificate[0];
		  }
		}

		public static class LdapSSLSocketFactory extends SSLSocketFactory
		{
		  private SSLSocketFactory socketFactory;
		  public LdapSSLSocketFactory()
		  {
		    try {
		      SSLContext ctx = SSLContext.getInstance("TLS");
		      ctx.init(null, new TrustManager[]{ new DummyTrustmanager()}, new SecureRandom());
		      socketFactory = ctx.getSocketFactory();
		    } catch ( Exception ex ){ ex.printStackTrace(System.err);  /* handle exception */ }
		  }
		  public static SocketFactory getDefault(){
		    return new LdapSSLSocketFactory();
		  }
		  @Override
		  public String[] getDefaultCipherSuites()
		  {
		    return socketFactory.getDefaultCipherSuites();
		  }
		  @Override
		  public String[] getSupportedCipherSuites()
		  {
		    return socketFactory.getSupportedCipherSuites();
		  }
		  @Override
		  public Socket createSocket(Socket socket, String string, int i, boolean bln) throws IOException
		  {
		    return socketFactory.createSocket(socket, string, i, bln);
		  }
		  @Override
		  public Socket createSocket(String string, int i) throws IOException, UnknownHostException
		  {
		    return socketFactory.createSocket(string, i);
		  }
		  @Override
		  public Socket createSocket(String string, int i, InetAddress ia, int i1) throws IOException, UnknownHostException
		  {
		    return socketFactory.createSocket(string, i, ia, i1);
		  }
		  @Override
		  public Socket createSocket(InetAddress ia, int i) throws IOException
		  {
		    return socketFactory.createSocket(ia, i);
		  }
		  @Override
		  public Socket createSocket(InetAddress ia, int i, InetAddress ia1, int i1) throws IOException
		  {
		    return socketFactory.createSocket(ia, i, ia1, i1);
		  }
		}

	
	
}
