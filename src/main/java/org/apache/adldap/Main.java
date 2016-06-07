package org.apache.adldap;

import java.util.Map;

import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.SearchResult;

public class Main {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		String baseDn = "OU=INTERNAL,dc=hdpusr,dc=senia,dc=org";
		String bindDn = "cn=ldapsearch,ou=internal,dc=hdpusr,dc=senia,dc=org";
		String bindPw = "";
		String ldapURL = "ldaps://seniadc1.senia.org:3269";
		String samAccountName = "";
		LdapClient ldpClient = new LdapClient(baseDn, bindDn, bindPw, ldapURL);

		LdapApi api = new LdapApi();
		Map<String,Attribute> results = api.getADGCAttrs(ldpClient, baseDn, samAccountName);
		System.out.println("DisplayName: "+api.getDisplayName(ldpClient, baseDn, samAccountName));

		System.out.println("CN: "+api.getCN(results));

		System.out.println("DN: "+api.getDN(results));

		System.out.println("DN: "+api.getManager(results));

		
		System.out.println("UPN: "+api.getUPN(results));

		System.out.println("Phone: "+api.getPhoneNumber(results));

		System.out.println("Email: "+api.getUserMail(results));

		System.out.println("whenChanged: "+api.getWhenChanged(results));

		System.out.println("whenCreated: "+api.getWhenCreated(results));
		
		System.out.println("uSNCreated: "+api.getUSNCreated(results));

		System.out.println("uSNChanged: "+api.getUSNChanged(results));

		System.out.println("createTimeStamp: "+api.getCreateTimeStamp(results));

		
		System.out.println("modifyTimeStamp: "+api.getModifyTimeStamp(results));

		System.out.println("lastLogonTimeStamp: "+api.getLastLogonTimeStamp(results));

		
		System.out.println("pwdLastSet: "+api.getPwdLastSet(results));

		System.out.println("lockoutTime: "+api.getLockOutTime(results));

		System.out.println("badPwdCount: "+api.getBadPwdCount(results));

		System.out.println("badPasswordTime: "+api.getBadPwdTime(results));

		System.out.println("lastLogon: "+api.getLastLogonTimeStamp(results));

		long uacc = api.getUACC(results);
		long uac = api.getUserAccountControl(results);
		System.out.println("Account Disabled: "+api.getAccountDisabled(uac));
		System.out.println("Password Never Expires: "+api.getPasswordNeverExpires(uac));
		System.out.println("SmartCard Required: "+api.getSmartCardRequired(uac));
		System.out.println("Kerberos PreAuth Required: "+api.getRequireKrbPreAuth(uac));
		System.out.println("Kerberos DES Types Allowed: "+api.getUseKrbDESTypes(uac));
		System.out.println("Use Reversible Encryption Password: "+api.getUseRevEncryptPasswd(uac));
		System.out.println("Allow Delegation: "+api.getAllowDelegation(uac));
		System.out.println("Account LockedOut: "+api.getLockedOut(uacc));





		ldpClient.destroyLdapClient();

		}
	}

