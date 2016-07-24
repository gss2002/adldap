package org.apache.adldap;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.apache.log4j.Logger;

public class LdapApi {

	Logger LOG = Logger.getLogger(LdapApi.class);

	
	// some useful constants from lmaccess.h
	int UF_SCRIPT = 0x001;
	int UF_ACCOUNTDISABLE = 0x0002;
	int UF_HOMEDIR_REQUIRED = 0x0008;
	int UF_LOCKOUT = 0x0010;
	int UF_PASSWD_NOTREQD = 0x0020;
	int UF_PASSWD_CANT_CHANGE = 0x0040;
	int UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x0080;
	int UF_TEMP_DUPLICATE_ACCOUNT = 0x0100;
	int UF_NORMAL_ACCOUNT = 0x0200;
	int UF_INTERDOMAIN_TRUST_ACCOUNT = 0x0800;
	int UF_WORKSTATION_TRUST_ACCOUNT = 0x01000;
	int UF_SERVER_TRUST_ACCOUNT = 0x02000;
	int UF_DONT_EXPIRE_PASSWD = 0x10000;
	int UF_MNS_LOGON_ACCOUNT = 0x20000;
	int UF_SMARTCARD_REQUIRED = 0x40000;
	int UF_TRUSTED_FOR_DELEGATION = 0x80000;
	int UF_NOT_DELEGATED = 0x100000;
	int UF_USE_DES_KEY_ONLY = 0x200000;
	int UF_DONT_REQUIRE_PREAUTH = 0x400000;
	int UF_PASSWORD_EXPIRED = 0x800000;

	String[] globalUserCatalogAttrs = { "canonicalName", "cn", "c", "createTimeStamp", "description", "displayName",
			"distinguishedName", "givenName", "l", "lastLogonTimestamp", "mail", "manager", "memberOf",
			"modifyTimeStamp", "msDS-KeyVersionNumber", "msDS-parentdistname", "msDS-PrincipalName",
			"msDS-User-Account-Control-Computed", "msDS-UserPasswordExpiryTimeComputed", "name", "objectCategory",
			"objectGUID", "objectSid", "primaryGroupID", "sAMAccountName", "sDRightsEffective", "sn", "st",
			"telephoneNumber", "userAccountControl", "userPrincipalName", "uSNChanged", "uSNCreated", "whenChanged",
			"whenCreated", "pwdLastSet", "badPasswordTime", "badPwdCount",
			"lockoutTime" };
	String[] globalGroupCatalogAttrs = { "canonicalName", "cn", "createTimeStamp", "description", "displayName",
			"distinguishedName", "groupType", "mail", "member", "modifyTimeStamp", "msDS-parentdistname",
			"msDS-PrincipalName", "name", "objectCategory", "objectGUID", "objectSid", "sAMAccountName",
			"sDRightsEffective", "uSNChanged", "uSNCreated", "whenChanged", "whenCreated" };

	
	String[] reverseAttrs = { "sAMAccountName", "cn" };

	/**
	 * @param ldapDate
	 * @return Date ldapDate
	 */
	public String parseLdapDate(String ldapDate) {
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

	public String parseMSTime(long ldapTimeStamp) {
		long llastLogonAdjust = 11644473600000L; // adjust factor for converting
													// it to java
		// date Epoch
		Date lastLogon = new Date(ldapTimeStamp / 10000 - llastLogonAdjust); //
		return lastLogon.toGMTString();
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String telephoneNumber
	 */
	public String getPhoneNumber(LdapClient ldapClient, String baseDn, String samAccountName) {
		String filter = "(&(samAccountName=" + samAccountName + ")(objectclass=person))";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("telephoneNumber");
				if (attr != null) {
					String telephoneNumber = (String) attr.get();
					if (results != null)
						results.close();
					return telephoneNumber;
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String telephoneNumber
	 */
	public String getPhoneNumber(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("telephoneNumber");
		if (attr != null) {
			String telephoneNumber = null;
			try {
				telephoneNumber = (String) attr.get();
				return telephoneNumber;
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String mail
	 */
	public String getUserMail(LdapClient ldapClient, String baseDn, String samAccountName) {
		String filter = "(samAccountName=" + samAccountName + ")";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("mail");
				if (attr != null) {
					String mail = (String) attr.get();
					return mail;
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String mail
	 */
	public String getUserMail(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("mail");
		if (attr != null) {
			String mail = null;
			try {
				mail = (String) attr.get();
				return mail;
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String uSNChanged
	 */
	public String getUSNChanged(LdapClient ldapClient, String baseDn, String samAccountName) {
		String filter = "(samAccountName=" + samAccountName + ")";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("uSNChanged");
				if (attr != null) {
					String uSNChanged = (String) attr.get();
					if (results != null)
						results.close();
					return uSNChanged;
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String uSNChanged
	 */
	public String getUSNChanged(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("uSNChanged");
		if (attr != null) {
			String uSNChanged = null;
			try {
				uSNChanged = (String) attr.get();
				return uSNChanged;
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String uSNCreated
	 */
	public String getUSNCreated(LdapClient ldapClient, String baseDn, String samAccountName) {
		String filter = "(samAccountName=" + samAccountName + ")";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("uSNCreated");
				if (attr != null) {
					String uSNCreated = (String) attr.get();
					if (results != null)
						results.close();
					return uSNCreated;
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String uSNCreated
	 */
	public String getUSNCreated(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("uSNCreated");
		if (attr != null) {
			String uSNCreated = null;
			try {
				uSNCreated = (String) attr.get();
				return uSNCreated;
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String cn
	 */
	public String getCN(LdapClient ldapClient, String baseDn, String samAccountName) {
		String filter = "(samAccountName=" + samAccountName + ")";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("cn");
				if (attr != null) {
					String cn = (String) attr.get();
					if (results != null)
						results.close();
					return cn;
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String cn
	 */
	public String getCN(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("cn");
		if (attr != null) {
			String cn = null;
			try {
				cn = (String) attr.get();
				return cn;
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String distinguishedName
	 */
	public String getDN(LdapClient ldapClient, String baseDn, String samAccountName) {
		String filter = "(samAccountName=" + samAccountName + ")";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("distinguishedName");
				if (attr != null) {
					String distinguishedName = (String) attr.get();
					if (results != null)
						results.close();
					return distinguishedName;
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String distinguishedName
	 */
	public String getDN(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("distinguishedName");
		if (attr != null) {
			String distinguishedName = null;
			try {
				distinguishedName = (String) attr.get();
				return distinguishedName;
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String manager
	 */
	public String getManager(LdapClient ldapClient, String baseDn, String samAccountName) {
		String filter = "(samAccountName=" + samAccountName + ")";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("manager");
				if (attr != null) {
					String manager = (String) attr.get();
					if (results != null)
						results.close();
					return manager;
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String manager
	 */
	public String getManager(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("manager");
		if (attr != null) {
			String manager = null;
			try {
				manager = (String) attr.get();
				return manager;
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String whenChanged
	 */
	public String getWhenChanged(LdapClient ldapClient, String baseDn, String samAccountName) {

		String filter = "(samAccountName=" + samAccountName + ")";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("whenChanged");
				if (attr != null) {
					String whenChanged = (String) attr.get();
					if (results != null)
						results.close();
					return parseLdapDate(whenChanged);
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String whenChanged
	 */
	public String getWhenChanged(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("whenChanged");
		if (attr != null) {
			String whenChanged = null;
			try {
				whenChanged = (String) attr.get();
				return parseLdapDate(whenChanged);
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String modifyTimeStamp
	 */
	public String getModifyTimeStamp(LdapClient ldapClient, String baseDn, String samAccountName) {

		String filter = "(samAccountName=" + samAccountName + ")";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("modifyTimestamp");
				if (attr != null) {
					String modifyTimeStamp = (String) attr.get();
					if (results != null)
						results.close();
					return parseLdapDate(modifyTimeStamp);
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String modifyTimeStamp
	 */
	public String getModifyTimeStamp(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("modifyTimeStamp");
		if (attr != null) {
			String modifyTimeStamp = null;
			try {
				modifyTimeStamp = (String) attr.get();
				return parseLdapDate(modifyTimeStamp);
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String createTimeStamp
	 */
	public String getCreateTimeStamp(LdapClient ldapClient, String baseDn, String samAccountName) {

		String filter = "(samAccountName=" + samAccountName + ")";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("createTimeStamp");
				if (attr != null) {
					String createTimestamp = (String) attr.get();
					if (results != null)
						results.close();
					return parseLdapDate(createTimestamp);
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String createTimeStamp
	 */
	public String getCreateTimeStamp(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("createTimeStamp");
		if (attr != null) {
			String createTimestamp = null;
			try {
				createTimestamp = (String) attr.get();
				return parseLdapDate(createTimestamp);
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String whenCreated
	 */
	public String getWhenCreated(LdapClient ldapClient, String baseDn, String samAccountName) {

		String filter = "(samAccountName=" + samAccountName + ")";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("whenCreated");
				if (attr != null) {
					String whenCreated = (String) attr.get();
					if (results != null)
						results.close();
					return parseLdapDate(whenCreated);
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String getWhenCreated
	 */
	public String getWhenCreated(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("whenCreated");
		if (attr != null) {
			String whenCreated = null;
			try {
				whenCreated = (String) attr.get();
				return parseLdapDate(whenCreated);
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String userPrincipalName
	 */
	public String getUPN(LdapClient ldapClient, String baseDn, String samAccountName) {

		String filter = "(&(samAccountName=" + samAccountName + ")(objectclass=person))";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("userPrincipalName");
				if (attr != null) {
					String userPrincipalName = (String) attr.get();
					if (results != null)
						results.close();
					return userPrincipalName;
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String userPrincipalName
	 */
	public String getUPN(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("userPrincipalName");
		if (attr != null) {
			String userPrincipalName = null;
			try {
				userPrincipalName = (String) attr.get();
				return userPrincipalName;
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String badPwdCount
	 */
	public String getBadPwdCount(LdapClient ldapClient, String baseDn, String samAccountName) {

		String filter = "(&(samAccountName=" + samAccountName + ")(objectclass=person))";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("badPwdCount");
				if (attr != null) {
					String badPwdCount = (String) attr.get();
					if (results != null)
						results.close();
					return badPwdCount;
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String badPwdCount
	 */
	public String getBadPwdCount(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("badPwdCount");
		if (attr != null) {
			String badPwdCount = null;
			try {
				badPwdCount = (String) attr.get();
				return badPwdCount;
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String badPwdCount
	 */
	public String getBadPwdTime(LdapClient ldapClient, String baseDn, String samAccountName) {

		String filter = "(&(samAccountName=" + samAccountName + ")(objectclass=person))";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("badPasswordTime");
				if (attr != null) {
					long badPasswordTime = Long.parseLong((String) attr.get());
					if (results != null)
						results.close();
					return parseMSTime(badPasswordTime);
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String badPasswordTime
	 */
	public String getBadPwdTime(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("badPasswordTime");
		if (attr != null) {
			try {
				long badPasswordTime = Long.parseLong((String) attr.get());
				return parseMSTime(badPasswordTime);
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String lastLogonTimeStamp
	 */
	public String getLastLogonTimeStamp(LdapClient ldapClient, String baseDn, String samAccountName) {

		String filter = "(&(samAccountName=" + samAccountName + ")(objectclass=person))";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("lastLogonTimestamp");
				if (attr != null) {
					long lastLogon = Long.parseLong((String) attr.get());
					if (results != null)
						results.close();
					return parseMSTime(lastLogon);
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String lastLogonTimeStamp
	 */
	public String getLastLogonTimeStamp(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("lastLogonTimestamp");
		if (attr != null) {
			try {
				long lastLogonTimeStamp = Long.parseLong((String) attr.get());
				return parseMSTime(lastLogonTimeStamp);
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String pwdLastSet
	 */
	public String getPwdLastSet(LdapClient ldapClient, String baseDn, String samAccountName) {

		String filter = "(&(samAccountName=" + samAccountName + ")(objectclass=person))";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("pwdLastSet");
				if (attr != null) {
					long pwdLastSet = Long.parseLong((String) attr.get());
					if (results != null)
						results.close();
					return parseMSTime(pwdLastSet);
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String pwdLastSet
	 */
	public String getPwdLastSet(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("pwdLastSet");
		if (attr != null) {
			try {
				long pwdLastSet = Long.parseLong((String) attr.get());
				return parseMSTime(pwdLastSet);
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String lockoutTime
	 */
	public String getLockOutTime(LdapClient ldapClient, String baseDn, String samAccountName) {

		String filter = "(&(samAccountName=" + samAccountName + ")(objectclass=person))";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("lockoutTime");
				if (attr != null) {
					long lockoutTime = Long.parseLong((String) attr.get());
					if (results != null)
						results.close();
					return parseMSTime(lockoutTime);
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String lockoutTime
	 */
	public String getLockOutTime(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("lockoutTime");
		if (attr != null) {
			try {
				long lockoutTime = Long.parseLong((String) attr.get());
				return parseMSTime(lockoutTime);
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String displayName
	 */
	public String getDisplayName(LdapClient ldapClient, String baseDn, String samAccountName) {

		String filter = "(samAccountName=" + samAccountName + ")";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("displayName");
				if (attr != null) {
					String displayName = (String) attr.get();
					if (results != null)
						results.close();
					return displayName;
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String displayName
	 */
	public String getDisplayName(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("displayName");
		if (attr != null) {
			try {
				String displayName = (String) attr.get();
				return displayName;
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String sAMAccountName
	 */
	public String getSamAccountName(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("sAMAccountName");
		if (attr != null) {
			try {
				String sAMAccountName = (String) attr.get();
				return sAMAccountName;
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String st
	 */
	public String getSt(LdapClient ldapClient, String baseDn, String samAccountName) {

		String filter = "(&(samAccountName=" + samAccountName + ")(objectclass=person))";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("st");
				if (attr != null) {
					String st = (String) attr.get();
					if (results != null)
						results.close();
					return st;
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String st
	 */
	public String getSt(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("st");
		if (attr != null) {
			try {
				String st = (String) attr.get();
				return st;
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String location
	 */
	public String getLocation(LdapClient ldapClient, String baseDn, String samAccountName) {

		String filter = "(&(samAccountName=" + samAccountName + ")(objectclass=person))";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("l");
				if (attr != null) {
					String l = (String) attr.get();
					if (results != null)
						results.close();
					return l;
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String location
	 */
	public String getLocation(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("l");
		if (attr != null) {
			try {
				String l = (String) attr.get();
				return l;
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String location
	 */
	public String getCountry(LdapClient ldapClient, String baseDn, String samAccountName) {

		String filter = "(&(samAccountName=" + samAccountName + ")(objectclass=person))";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("c");
				if (attr != null) {
					String c = (String) attr.get();
					if (results != null)
						results.close();
					return c;
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String country
	 */
	public String getCountry(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("l");
		if (attr != null) {
			try {
				String c = (String) attr.get();
				return c;
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String objectGuid
	 */
	public String getObjectGuid(LdapClient ldapClient, String baseDn, String samAccountName) {

		String filter = "(samAccountName=" + samAccountName + ")";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("objectGUID");
				if (attr != null) {
					byte[] objectGUID = (byte[]) attr.get();
					if (results != null)
						results.close();
					return convertToBindingString(objectGUID);
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String objectGuid
	 */
	public String getObjectGuid(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("objectGUID");
		if (attr != null) {
			try {
				byte[] objectGUID = (byte[]) attr.get();
				return convertToBindingString(objectGUID);
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return String description
	 */
	public String getDescription(LdapClient ldapClient, String baseDn, String samAccountName) {

		String filter = "(samAccountName=" + samAccountName + ")";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("description");
				if (attr != null) {
					String description = (String) attr.get();
					if (results != null)
						results.close();
					return description;
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @param searchResults
	 * @return String description
	 */
	public String getDescription(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("description");
		if (attr != null) {
			try {
				String description = (String) attr.get();
				return description;
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return List memberOf
	 */
	public List<String> getMemberOf(LdapClient ldapClient, String baseDn, String samAccountName) {
		List<String> groupList = new ArrayList<String>();
		String filter = "(&(samAccountName=" + samAccountName + ")(objectclass=person))";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("memberOf");
				if (attr != null) {
					NamingEnumeration<?> attrEnum = attr.getAll();
					while (attrEnum.hasMore()) {
						String group = attrEnum.next().toString();
						LOG.debug("memberof: "+group);
						groupList.add(group);
					}
					return groupList;
				}
			}
			if (results != null)
				results.close();
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
	 * @return List member
	 */
	public List<String> getGroupMembers(LdapClient ldapClient, String baseDn, String samAccountName) {
		List<String> groupList = new ArrayList<String>();
		String filter = "(&(samAccountName=" + samAccountName + ")(objectclass=group))";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("member");
				if (attr != null) {
					NamingEnumeration<?> attrEnum = attr.getAll();
					while (attrEnum.hasMore()) {
						String group = attrEnum.next().toString();
						LOG.debug("member: "+group);
						groupList.add(group);
					}
					if (results != null)
						results.close();
					return groupList;
				}
			}
			if (results != null)
				results.close();
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
	 * @return 
	 */
	public List<String> getGroupMemberRanging(LdapClient ldapClient, String baseDn, String samAccountName) {
		List<String> groupList = new ArrayList<String>();
		String filter = "(&(samAccountName=" + samAccountName + ")(objectclass=group))";
		boolean endString = true;
		int loopValue = 0;
		while (endString) {
		    int startValue = loopValue * 1000;
		    int endvalue = (loopValue + 1) * 1000;
		    String[] returnedAttrs = new String[1];
		    String range = startValue + "-" + endvalue;
		    returnedAttrs[0] = "member;range=" + range;
		    String memberAttr = "member;range=" + range;
		    SearchControls searchCtls = ldapClient.getLdapBean().getConstraints();
		    searchCtls.setReturningAttributes(returnedAttrs);
		    NamingEnumeration<SearchResult> answer;
			try {
				answer = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
						searchCtls);
				while (answer.hasMore()) {
					SearchResult searchResult = (SearchResult) answer.next();
					//System.out.println(entry.getAttributes());
					Attributes attributes = searchResult.getAttributes();
					Attribute attr = attributes.get(memberAttr);
					if (attr != null) {
						NamingEnumeration<?> attrEnum = attr.getAll();
						while (attrEnum.hasMore()) {
							String group = attrEnum.next().toString();
							LOG.debug("member: "+group);
							groupList.add(group);
						}
					}
					if (searchResult.getAttributes().toString().contains("{member;range=" + startValue + "-*")) {
						endString = false;
					}
				}
				loopValue++;
				//return groupList;
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return groupList;
	}

	/**
	 * @param searchResults
	 * @return List member
	 */
	public List<String> getGroupMembers(Map<String, Attribute> searchResults) {
		List<String> groupList = new ArrayList<String>();
		Attribute attr = searchResults.get("member");
		if (attr != null) {
			NamingEnumeration<?> attrEnum = null;
			try {
				attrEnum = attr.getAll();
				while (attrEnum.hasMore()) {
					String group = attrEnum.next().toString();
					LOG.debug("member: "+group);
					groupList.add(group);
				}
				return groupList;
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		return null;
	}

	/**
	 * @param searchResults
	 * @return boolean exists
	 */
	public boolean groupRangingExists(Map<String, Attribute> searchResults) {
		Attribute attr = searchResults.get("member");
		if (attr != null) {
			LOG.debug("Ranging: "+attr.size());
			if (attr.size() == 0) {
				LOG.debug("AttrSize: 0");
				return true;
			}
			LOG.debug("AttrSize > 0");
			return false;
		}
		return false;
	}
	
	/**
	 * @param searchResults
	 * @return List memberOf
	 */
	public List<String> getMemberOf(Map<String, Attribute> searchResults) {
		List<String> groupList = new ArrayList<String>();
		Attribute attr = searchResults.get("memberOf");
		if (attr != null) {
			NamingEnumeration<?> attrEnum = null;
			try {
				attrEnum = attr.getAll();
				while (attrEnum.hasMore()) {
					String group = attrEnum.next().toString();
					LOG.debug("memberof: "+group);
					groupList.add(group);
				}
				return groupList;
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		return null;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return long msdsUACC
	 */
	public long getUACC(LdapClient ldapClient, String baseDn, String samAccountName) {
		long uacc = 9999999999L;
		String filter = "(&(samAccountName=" + samAccountName + ")(objectclass=person))";
		NamingEnumeration<SearchResult> results;
		try {
			String userReturnedAtts[] = { "msDS-User-Account-Control-Computed", "userAccountControl" };
			SearchControls srchCntrls = ldapClient.getLdapBean().getConstraints();
			srchCntrls.setReturningAttributes(userReturnedAtts);
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter, srchCntrls);
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("msDS-User-Account-Control-Computed");
				if (attr != null) {
					uacc = Long.parseLong((String) attr.get());
					if (results != null)
						results.close();
					return uacc;
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return uacc;
	}

	/**
	 * @param searchResults
	 * @return long msdsUACC
	 */
	public long getUACC(Map<String, Attribute> searchResults) {
		long uacc = 9999999999L;
		Attribute attr = searchResults.get("msDS-User-Account-Control-Computed");
		if (attr != null) {
			try {
				uacc = Long.parseLong((String) attr.get());
				return uacc;
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return uacc;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return Map<String, Attribute> userAttributeMap
	 */
	public Map<String, Attribute> getADUserGCAttrs(LdapClient ldapClient, String baseDn, String samAccountName) {
		String filter = "(&(samAccountName=" + samAccountName + ")(objectclass=person))";
		HashMap<String, Attribute> map = null;
		SearchControls srchCntrls = ldapClient.getLdapBean().getConstraints();
		srchCntrls.setReturningAttributes(globalUserCatalogAttrs);
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter, srchCntrls);
			map = new HashMap<String, Attribute>();
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				NamingEnumeration<? extends Attribute> attrEnum = searchResult.getAttributes().getAll();
				while (attrEnum.hasMore()) {
					Attribute att = attrEnum.next();
					map.put(att.getID(), att);
				}
				return map;
			}
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return map;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return Map<String, Attribute> groupAttributeMap
	 */
	public Map<String, Attribute> getADGroupGCAttrs(LdapClient ldapClient, String baseDn, String samAccountName) {
		String filter = "(&(samAccountName=" + samAccountName + ")(objectclass=group))";
		HashMap<String, Attribute> map = null;
		SearchControls srchCntrls = ldapClient.getLdapBean().getConstraints();
		srchCntrls.setReturningAttributes(globalGroupCatalogAttrs);
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter, srchCntrls);
			map = new HashMap<String, Attribute>();
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				NamingEnumeration<? extends Attribute> attrEnum = searchResult.getAttributes().getAll();
				while (attrEnum.hasMore()) {
					Attribute att = attrEnum.next();
					LOG.debug("Attribute Id: "+att.getID()+" Attribute: "+att);
					map.put(att.getID(), att);
				}
				return map;
			}
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return map;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param dn
	 * @return Map<String, Attribute> userAttributeMap
	 */
	public Map<String, Attribute> getUserDNAttrs(LdapClient ldapClient, String baseDn, String dn) {
		String filter = "(&(distinguishedName=" + dn + ")(objectclass=person))";
		HashMap<String, Attribute> map = null;
		SearchControls srchCntrls = ldapClient.getLdapBean().getConstraints();
		srchCntrls.setReturningAttributes(reverseAttrs);
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter, srchCntrls);
			map = new HashMap<String, Attribute>();
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				NamingEnumeration<? extends Attribute> attrEnum = searchResult.getAttributes().getAll();
				while (attrEnum.hasMore()) {
					Attribute att = attrEnum.next();
					map.put(att.getID(), att);
				}
				if (results != null)
					results.close();
				return map;
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return map;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param dn
	 * @return Map<String, Attribute> groupAttributeMap
	 */
	public Map<String, Attribute> getGroupDNAttrs(LdapClient ldapClient, String baseDn, String dn) {
		String filter = "(&(distinguishedName=" + dn + ")(objectclass=group))";
		HashMap<String, Attribute> map = null;
		SearchControls srchCntrls = ldapClient.getLdapBean().getConstraints();
		srchCntrls.setReturningAttributes(reverseAttrs);
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter, srchCntrls);
			map = new HashMap<String, Attribute>();
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				NamingEnumeration<? extends Attribute> attrEnum = searchResult.getAttributes().getAll();
				while (attrEnum.hasMore()) {
					Attribute att = attrEnum.next();
					map.put(att.getID(), att);
				}
				if (results != null)
					results.close();
				return map;
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return map;
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param samAccountName
	 * @return long userAccountControl
	 */
	public long getUserAccountControl(LdapClient ldapClient, String baseDn, String samAccountName) {
		long userAccountControl = 999999999999999999L;
		String filter = "(&(samAccountName=" + samAccountName + ")(objectclass=person))";
		NamingEnumeration<SearchResult> results;
		try {
			String userReturnedAtts[] = { "msDS-User-Account-Control-Computed", "userAccountControl" };
			SearchControls srchCntrls = ldapClient.getLdapBean().getConstraints();
			srchCntrls.setReturningAttributes(userReturnedAtts);
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter, srchCntrls);
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("userAccountControl");
				if (attr != null) {
					userAccountControl = Long.parseLong((String) attr.get());
					if (results != null)
						results.close();
					return userAccountControl;
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return userAccountControl;
	}

	/**
	 * @param searchResults
	 * @return long userAccountControl
	 */
	public long getUserAccountControl(Map<String, Attribute> searchResults) {
		long userAccountControl = 9999999999L;
		Attribute attr = searchResults.get("userAccountControl");
		if (attr != null) {
			try {
				userAccountControl = Long.parseLong((String) attr.get());
				return userAccountControl;
			} catch (NamingException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return userAccountControl;
	}

	/**
	 * @param uac
	 * @return boolean accountDisabled
	 */
	public boolean getAccountDisabled(long uac) {
		if ((uac & UF_ACCOUNTDISABLE) == UF_ACCOUNTDISABLE) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * @param uac
	 * @return boolean passwordNeverExpires
	 */
	public boolean getPasswordNeverExpires(long uac) {
		if ((uac & UF_DONT_EXPIRE_PASSWD) == UF_DONT_EXPIRE_PASSWD) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * @param uac
	 * @return boolean smartCardRequired
	 */
	public boolean getSmartCardRequired(long uac) {
		if ((uac & UF_SMARTCARD_REQUIRED) == UF_SMARTCARD_REQUIRED) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * @param uac
	 * @return boolean requireKrbPreAuth
	 */
	public boolean getRequireKrbPreAuth(long uac) {
		if ((uac & UF_DONT_REQUIRE_PREAUTH) == UF_DONT_REQUIRE_PREAUTH) {
			return false;
		} else {
			return true;
		}
	}

	/**
	 * @param uac
	 * @return boolean useKrbDESTypes
	 */
	public boolean getUseKrbDESTypes(long uac) {
		if ((uac & UF_USE_DES_KEY_ONLY) == UF_USE_DES_KEY_ONLY) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * @param uac
	 * @return boolean useRevEncryptPasswd
	 */
	public boolean getUseRevEncryptPasswd(long uac) {
		if ((uac & UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED) == UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * @param uac
	 * @return boolean allowDelegation
	 */
	public boolean getAllowDelegation(long uac) {
		if ((uac & UF_NOT_DELEGATED) == UF_NOT_DELEGATED) {
			return false;
		} else {
			return true;
		}
	}

	/**
	 * @param uacc
	 * @return boolean lockedOut
	 */
	public boolean getLockedOut(long uacc) {
		if ((uacc & UF_LOCKOUT) == UF_LOCKOUT) {
			return true;
		} else {
			return false;
		}
	}

	/**
	 * @param ldapClient
	 * @param baseDn
	 * @param cn
	 * @return String samAccountName
	 */
	public String getSamAccountNameFromCN(LdapClient ldapClient, String baseDn, String cn) {
		String filter = "(&(cn=" + cn + ")(|(objectclass=person)(objectclass=group)))";
		NamingEnumeration<SearchResult> results;
		try {
			results = ldapClient.getLdapBean().getLdapCtx().search(baseDn, filter,
					ldapClient.getLdapBean().getConstraints());
			while (results.hasMore()) {
				SearchResult searchResult = results.next();
				Attributes attributes = searchResult.getAttributes();
				Attribute attr = attributes.get("sAMAccountName");
				if (attr != null) {
					String samAccountName = (String) attr.get();
					if (results != null)
						results.close();
					return samAccountName;
				}
			}
			if (results != null)
				results.close();
		} catch (NamingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public String convertToByteString(byte[] objectGUID) {
		StringBuilder result = new StringBuilder();

		for (int i = 0; i < objectGUID.length; i++) {
			String transformed = prefixZeros((int) objectGUID[i] & 0xFF);
			result.append("\\");
			result.append(transformed);
		}

		return result.toString();
	}

	public String convertToBindingString(byte[] objectGUID) {
		StringBuilder displayStr = new StringBuilder();

		displayStr.append("<GUID=");
		displayStr.append(convertToDashedString(objectGUID));
		displayStr.append(">");

		return displayStr.toString();
	}

	public String convertToDashedString(byte[] objectGUID) {
		StringBuilder displayStr = new StringBuilder();

		displayStr.append(prefixZeros((int) objectGUID[3] & 0xFF));
		displayStr.append(prefixZeros((int) objectGUID[2] & 0xFF));
		displayStr.append(prefixZeros((int) objectGUID[1] & 0xFF));
		displayStr.append(prefixZeros((int) objectGUID[0] & 0xFF));
		displayStr.append("-");
		displayStr.append(prefixZeros((int) objectGUID[5] & 0xFF));
		displayStr.append(prefixZeros((int) objectGUID[4] & 0xFF));
		displayStr.append("-");
		displayStr.append(prefixZeros((int) objectGUID[7] & 0xFF));
		displayStr.append(prefixZeros((int) objectGUID[6] & 0xFF));
		displayStr.append("-");
		displayStr.append(prefixZeros((int) objectGUID[8] & 0xFF));
		displayStr.append(prefixZeros((int) objectGUID[9] & 0xFF));
		displayStr.append("-");
		displayStr.append(prefixZeros((int) objectGUID[10] & 0xFF));
		displayStr.append(prefixZeros((int) objectGUID[11] & 0xFF));
		displayStr.append(prefixZeros((int) objectGUID[12] & 0xFF));
		displayStr.append(prefixZeros((int) objectGUID[13] & 0xFF));
		displayStr.append(prefixZeros((int) objectGUID[14] & 0xFF));
		displayStr.append(prefixZeros((int) objectGUID[15] & 0xFF));

		return displayStr.toString();
	}

	private String prefixZeros(int value) {
		if (value <= 0xF) {
			StringBuilder sb = new StringBuilder("0");
			sb.append(Integer.toHexString(value));

			return sb.toString();

		} else {
			return Integer.toHexString(value);
		}
	}

	static void printAttrs(Attributes attrs) {
		if (attrs == null) {
			System.out.println("No attributes");
		} else {
			/* Print each attribute */
			try {
				for (NamingEnumeration ae = attrs.getAll(); ae.hasMore();) {
					Attribute attr = (Attribute) ae.next();
					System.out.println("attribute: " + attr.getID());

					/* print each value */
					for (NamingEnumeration e = attr.getAll(); e.hasMore(); System.out.println("value: " + e.next()))
						;
				}
			} catch (NamingException e) {
				e.printStackTrace();
			}
		}
	}
}
