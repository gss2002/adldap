package org.apache.adldap;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

public class DnsLookup {
	private static final String MX_ATTRIB = "MX";
	private static final String ADDR_ATTRIB = "A";
	private static final String SRV_ATTRIB = "SRV";
	private static String[] MX_ATTRIBS = {MX_ATTRIB};
	private static String[] ADDR_ATTRIBS = {ADDR_ATTRIB};
	private static String[] SRV_ATTRIBS = {SRV_ATTRIB};

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
	Hashtable<String, String> env = new Hashtable<String, String>();
	env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
	DirContext ctx = null;
	try {
		ctx = new InitialDirContext(env);
	} catch (NamingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	try {
		Attributes attrs = ctx.getAttributes("_kerberos._tcp.hdpusr.senia.org",SRV_ATTRIBS);
		  Attribute attr = attrs.get(SRV_ATTRIB);
		  
		  if (attr != null) {
		    for (int i = 0; i < attr.size(); i++) {
		      String srvAttr = (String) attr.get(i);
		      String[] parts = srvAttr.split(" ");
		      System.out.println(parts[parts.length - 1]);
		      // Split off the priority, and take the last field
		      //servers.add(parts[parts.length - 1]);
		    }
		  }
		  ctx.close();	
	} catch (NamingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	}
	
	public String getLdapServer(String domain) {
		// TODO Auto-generated method stub
		
	Hashtable<String, String> env = new Hashtable<String, String>();
	env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
	DirContext ctx = null;
	try {
		ctx = new InitialDirContext(env);
	} catch (NamingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	try {
		Attributes attrs = ctx.getAttributes("_kerberos._tcp.gaadc._sites."+domain ,SRV_ATTRIBS);
		  Attribute attr = attrs.get(SRV_ATTRIB);
		  
		  if (attr != null) {
		    for (int i = 0; i < attr.size(); i++) {
		      String srvAttr = (String) attr.get(i);
		      String[] parts = srvAttr.split(" ");
		      System.out.println(parts[parts.length - 1]);
		      return parts[parts.length - 1].substring(0,parts[parts.length - 1].length()-1);
		      // Split off the priority, and take the last field
		      //servers.add(parts[parts.length - 1]);
		    }
		  }
		  ctx.close();	
	} catch (NamingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	return domain;
	}
}
