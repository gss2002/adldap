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

import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Hashtable;

public class LdapClient {
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
	public LdapClient(String baseDN, String bindDN, String bindPW, String ldapUrl) {
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
	
	public void createLdapClient() {
		// Create a trust manager that does not validate certificate chains

		// Install the all-trusting trust manager
		
		this.env = new Hashtable<String, Object>();
	    this.env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        this.env.put(Context.SECURITY_PROTOCOL, "ssl");
        this.env.put(Context.PROVIDER_URL, this.ldapUrl);
        this.env.put("java.naming.ldap.factory.socket", LdapClient.LdapSSLSocketFactory.class.getName());
	    
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
