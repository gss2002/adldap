package org.apache.adldap;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

public class LdapApi {
    /**
     * @param ldapDate
     * @return Date ldapDate
     */
	public String parseLdapDate(String ldapDate){
	    SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
	    sdf.setTimeZone(TimeZone.getTimeZone("GMT"));

	    try {
	        return sdf.parse(ldapDate).toGMTString();
	    } catch (ParseException e) {
	        // TODO Auto-generated catch block
	        e.printStackTrace();
	    }
	    return null;
	}
	
	public String parseMSTime(long ldapTimeStamp){
	     long llastLogonAdjust=11644473600000L;  // adjust factor for converting it to java    
         //date Epoch
	     Date lastLogon = new Date(ldapTimeStamp/10000-llastLogonAdjust); // 
	     return lastLogon.toGMTString();
	}
	
	
    /**
     * @param ldapClient
     * @param baseDn
     * @param samAccountName
     * @return String telephoneNumber
     */
    public String getPhoneNumber(LdapClient ldapClient, String baseDn, String samAccountName ) {
        InitialDirContext ctx = null;
		try {
			ctx = new InitialDirContext(ldapClient.env);
		} catch (NamingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
    	SearchControls constraints = new SearchControls();
    	constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
      String filter = "(&(samAccountName="+samAccountName+")(objectclass=person))";
      NamingEnumeration<SearchResult> results;
      try {
    	  results = ctx.search(baseDn, filter, constraints);
    	  while (results.hasMore()) {
                            SearchResult searchResult = results.next();
                            Attributes attributes = searchResult.getAttributes();
                            Attribute attr = attributes.get("telephoneNumber");
                            if (attr != null) {
                            	String telephoneNumber = (String) attr.get();
                            	return telephoneNumber;
                            }
                    }
              } catch (NamingException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
              }
      return null;
    }
    
        /**
         * @param ldapClient
         * @param baseDn
         * @param samAccountName
         * @return String mail
         */
        public String getUserMail(LdapClient ldapClient, String baseDn, String samAccountName ) {
            InitialDirContext ctx = null;
    		try {
    			ctx = new InitialDirContext(ldapClient.env);
    		} catch (NamingException e1) {
    			// TODO Auto-generated catch block
    			e1.printStackTrace();
    		}  
        SearchControls constraints = new SearchControls();
          constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
          String filter = "(&(samAccountName="+samAccountName+")(objectclass=person))";
          NamingEnumeration<SearchResult> results;
          try {
                        results = ctx.search(baseDn, filter, constraints);
                        while (results.hasMore()) {
                                SearchResult searchResult = results.next();
                                Attributes attributes = searchResult.getAttributes();
                                Attribute attr = attributes.get("mail");
                                if (attr != null) {
                                	String mail = (String) attr.get();
                                	return mail;
                                }
                        }
                  } catch (NamingException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                  }
          return null;
        }
        
        /**
         * @param ldapClient
         * @param baseDn
         * @param samAccountName
         * @return String whenChanged
         */
        public String getWhenChanged(LdapClient ldapClient, String baseDn, String samAccountName ) {
            InitialDirContext ctx = null;
    		try {
    			ctx = new InitialDirContext(ldapClient.env);
    		} catch (NamingException e1) {
    			// TODO Auto-generated catch block
    			e1.printStackTrace();
    		}  
        SearchControls constraints = new SearchControls();
          constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
          String filter = "(&(samAccountName="+samAccountName+")(objectclass=person))";
          NamingEnumeration<SearchResult> results;
          try {
                        results = ctx.search(baseDn, filter, constraints);
                        while (results.hasMore()) {
                                SearchResult searchResult = results.next();
                                Attributes attributes = searchResult.getAttributes();
                                Attribute attr = attributes.get("whenChanged");
                                if (attr != null) {
                                	String whenChanged = (String) attr.get();
                                	return parseLdapDate(whenChanged);
                                }
                        }
                  } catch (NamingException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                  }
          return null;
        }
        /**
         * @param ldapClient
         * @param baseDn
         * @param samAccountName
         * @return String whenChanged
         */
        public String getWhenCreated(LdapClient ldapClient, String baseDn, String samAccountName ) {
            InitialDirContext ctx = null;
    		try {
    			ctx = new InitialDirContext(ldapClient.env);
    		} catch (NamingException e1) {
    			// TODO Auto-generated catch block
    			e1.printStackTrace();
    		}  
        SearchControls constraints = new SearchControls();
          constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
          String filter = "(&(samAccountName="+samAccountName+")(objectclass=person))";
          NamingEnumeration<SearchResult> results;
          try {
                        results = ctx.search(baseDn, filter, constraints);
                        while (results.hasMore()) {
                                SearchResult searchResult = results.next();
                                Attributes attributes = searchResult.getAttributes();
                                Attribute attr = attributes.get("whenCreated");
                                if (attr != null) {
                                	String whenCreated = (String) attr.get();
                                	return parseLdapDate(whenCreated);
                                }
                        }
                  } catch (NamingException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                  }
          return null;
        }
        /**
         * @param ldapClient
         * @param baseDn
         * @param samAccountName
         * @return String userPrincipalName
         */
        public String getUPN(LdapClient ldapClient, String baseDn, String samAccountName ) {
            InitialDirContext ctx = null;
    		try {
    			ctx = new InitialDirContext(ldapClient.env);
    		} catch (NamingException e1) {
    			// TODO Auto-generated catch block
    			e1.printStackTrace();
    		} 
                  SearchControls constraints = new SearchControls();
          constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
          String filter = "(&(samAccountName="+samAccountName+")(objectclass=person))";
          NamingEnumeration<SearchResult> results;
          try {
                        results = ctx.search(baseDn, filter, constraints);
                        while (results.hasMore()) {
                                SearchResult searchResult = results.next();
                                Attributes attributes = searchResult.getAttributes();
                                Attribute attr = attributes.get("userPrincipalName");
                                if (attr != null) {
                                	String userPrincipalName = (String) attr.get();
                                	return userPrincipalName;
                                }
                        }
                  } catch (NamingException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                  }
          return null;
        }
        /**
         * @param ldapClient
         * @param baseDn
         * @param samAccountName
         * @return String badPwdCount
         */
        public String getBadPwdCount(LdapClient ldapClient, String baseDn, String samAccountName ) {
            InitialDirContext ctx = null;
    		try {
    			ctx = new InitialDirContext(ldapClient.env);
    		} catch (NamingException e1) {
    			// TODO Auto-generated catch block
    			e1.printStackTrace();
    		} 
                  SearchControls constraints = new SearchControls();
          constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
          String filter = "(&(samAccountName="+samAccountName+")(objectclass=person))";
          NamingEnumeration<SearchResult> results;
          try {
                        results = ctx.search(baseDn, filter, constraints);
                        while (results.hasMore()) {
                                SearchResult searchResult = results.next();
                                Attributes attributes = searchResult.getAttributes();
                                Attribute attr = attributes.get("badPwdCount");
                                if (attr != null) {
                                	String badPwdCount = (String) attr.get();
                                	return badPwdCount;
                                }
                        }
                  } catch (NamingException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                  }
          return null;
        }
        /**
         * @param ldapClient
         * @param baseDn
         * @param samAccountName
         * @return String badPwdCount
         */
        public String getBadPwdTime(LdapClient ldapClient, String baseDn, String samAccountName ) {
            InitialDirContext ctx = null;
    		try {
    			ctx = new InitialDirContext(ldapClient.env);
    		} catch (NamingException e1) {
    			// TODO Auto-generated catch block
    			e1.printStackTrace();
    		} 
                  SearchControls constraints = new SearchControls();
          constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
          String filter = "(&(samAccountName="+samAccountName+")(objectclass=person))";
          NamingEnumeration<SearchResult> results;
          try {
                        results = ctx.search(baseDn, filter, constraints);
                        while (results.hasMore()) {
                                SearchResult searchResult = results.next();
                                Attributes attributes = searchResult.getAttributes();
                                Attribute attr = attributes.get("badPasswordTime");
                                if (attr != null) {
                                	long badPasswordTime = Long.parseLong((String) attr.get());
                                	return parseMSTime(badPasswordTime);
                                }
                        }
                  } catch (NamingException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                  }
          return null;
        }
        /**
         * @param ldapClient
         * @param baseDn
         * @param samAccountName
         * @return String lastLogonTimeStamp
         */
        public String getLastLogonTimeStamp(LdapClient ldapClient, String baseDn, String samAccountName ) {
            InitialDirContext ctx = null;
    		try {
    			ctx = new InitialDirContext(ldapClient.env);
    		} catch (NamingException e1) {
    			// TODO Auto-generated catch block
    			e1.printStackTrace();
    		} 
                  SearchControls constraints = new SearchControls();
          constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
          String filter = "(&(samAccountName="+samAccountName+")(objectclass=person))";
          NamingEnumeration<SearchResult> results;
          try {
                        results = ctx.search(baseDn, filter, constraints);
                        while (results.hasMore()) {
                                SearchResult searchResult = results.next();
                                Attributes attributes = searchResult.getAttributes();
                                Attribute attr = attributes.get("lastLogonTimeStamp");
                                if (attr != null) {
                                	long lastLogon = Long.parseLong((String)attr.get());
                                	return parseMSTime(lastLogon);
                                }
                        }
                  } catch (NamingException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                  }
          return null;
        }
        /**
         * @param ldapClient
         * @param baseDn
         * @param samAccountName
         * @return String pwdLastSet
         */
        public String getPwdLastSet(LdapClient ldapClient, String baseDn, String samAccountName ) {
            InitialDirContext ctx = null;
    		try {
    			ctx = new InitialDirContext(ldapClient.env);
    		} catch (NamingException e1) {
    			// TODO Auto-generated catch block
    			e1.printStackTrace();
    		} 
                  SearchControls constraints = new SearchControls();
          constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
          String filter = "(&(samAccountName="+samAccountName+")(objectclass=person))";
          NamingEnumeration<SearchResult> results;
          try {
                        results = ctx.search(baseDn, filter, constraints);
                        while (results.hasMore()) {
                                SearchResult searchResult = results.next();
                                Attributes attributes = searchResult.getAttributes();
                                Attribute attr = attributes.get("pwdLastSet");
                                if (attr != null) {
                                	long pwdLastSet = Long.parseLong((String)attr.get());
                                	return parseMSTime(pwdLastSet);
                                }
                        }
                  } catch (NamingException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                  }
          return null;
        }
        /**
         * @param ldapClient
         * @param baseDn
         * @param samAccountName
         * @return String lockoutTime
         */
        public String getLockOutTime(LdapClient ldapClient, String baseDn, String samAccountName ) {
            InitialDirContext ctx = null;
    		try {
    			ctx = new InitialDirContext(ldapClient.env);
    		} catch (NamingException e1) {
    			// TODO Auto-generated catch block
    			e1.printStackTrace();
    		} 
                  SearchControls constraints = new SearchControls();
          constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
          String filter = "(&(samAccountName="+samAccountName+")(objectclass=person))";
          NamingEnumeration<SearchResult> results;
          try {
                        results = ctx.search(baseDn, filter, constraints);
                        while (results.hasMore()) {
                                SearchResult searchResult = results.next();
                                Attributes attributes = searchResult.getAttributes();
                                Attribute attr = attributes.get("lockoutTime");
                                if (attr != null) {
                                	long lockoutTime = Long.parseLong((String)attr.get());
                                	return parseMSTime(lockoutTime);
                                }
                        }
                  } catch (NamingException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                  }
          return null;
        }
        /**
         * @param ldapClient
         * @param baseDn
         * @param samAccountName
         * @return String displayName
         */
        public String getDisplayName(LdapClient ldapClient, String baseDn, String samAccountName ) {
            InitialDirContext ctx = null;
    		try {
    			ctx = new InitialDirContext(ldapClient.env);
    		} catch (NamingException e1) {
    			// TODO Auto-generated catch block
    			e1.printStackTrace();
    		} 
                  SearchControls constraints = new SearchControls();
          constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
          String filter = "(&(samAccountName="+samAccountName+")(objectclass=person))";
          NamingEnumeration<SearchResult> results;
          try {
                        results = ctx.search(baseDn, filter, constraints);
                        while (results.hasMore()) {
                                SearchResult searchResult = results.next();
                                Attributes attributes = searchResult.getAttributes();
                                Attribute attr = attributes.get("displayName");
                                if (attr != null) {
                                	String displayName = (String)attr.get();
                                	return displayName;
                                }
                        }
                  } catch (NamingException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                  }
          return null;
        }
        /**
         * @param ldapClient
         * @param baseDn
         * @param samAccountName
         * @return String lockoutTime
         */
        public String getUAC(LdapClient ldapClient, String baseDn, String samAccountName ) {
            InitialDirContext ctx = null;
    		try {
    			ctx = new InitialDirContext(ldapClient.env);
    		} catch (NamingException e1) {
    			// TODO Auto-generated catch block
    			e1.printStackTrace();
    		} 
                  SearchControls constraints = new SearchControls();
          constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
          String filter = "(&(samAccountName="+samAccountName+")(objectclass=person))";
          NamingEnumeration<SearchResult> results;
          try {
                        results = ctx.search(baseDn, filter, constraints);
                        while (results.hasMore()) {
                                SearchResult searchResult = results.next();
                                Attributes attributes = searchResult.getAttributes();
                                Attribute attr = attributes.get("lockoutTime");
                                if (attr != null) {
                                	long lockoutTime = Long.parseLong((String)attr.get());
                                	return parseMSTime(lockoutTime);
                                }
                        }
                  } catch (NamingException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                  }
          return null;
        }
}
