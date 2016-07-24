package org.apache.adldap;


import java.util.List;
import java.util.Map;

import javax.naming.directory.Attribute;

public class MainKerb {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		System.setProperty("sun.security.krb5.debug", "true");
		System.setProperty("java.security.krb5.conf", "krb5.conf");
		String gcBaseDn = "";
		String bindDn = "";
		String bindPw = "";
		String gcldapURL = "";
		String samAccountName = "";
		String groupSamAccountName = "";
		System.out.println("LdapClientKerb Start: " + System.currentTimeMillis());
		KerberosClient krbClient = new KerberosClient(bindDn, null, "/Users/username/username.keytab");
		LdapClient gcldpClient = new LdapClientSASL(gcBaseDn, gcldapURL, krbClient.getSubject());

		System.out.println("LdapClientKerb Complete: " + System.currentTimeMillis());

		LdapApi gcApi = new LdapApi();
		String upn = gcApi.getUPN(gcldpClient, gcBaseDn, samAccountName);
		String domain = upn.split("@")[1];
		String[] domain_partial = domain.split("\\.");
		int size = domain_partial.length;
		String dcout = null;
		for (int i = 0; i < size; i++) {
			if (i == 0) {
				dcout = "DC=" + domain_partial[i];
			} else {
				dcout = dcout + ",DC=" + domain_partial[i];
			}
		}
		System.out.println(dcout);
		DnsLookup dns = new DnsLookup();
		String ldapServer = dns.getLdapServer(domain);
		String baseDn = dcout;
		String ldapUrl = "ldap://" + ldapServer + ":389";
		LdapClient ldpClient = new LdapClientSASL(baseDn, ldapUrl, krbClient.getSubject());
		LdapApi api = new LdapApi();

		Map<String, Attribute> groupResults = gcApi.getADGroupGCAttrs(gcldpClient, gcBaseDn, groupSamAccountName);
        
		Map<String,Attribute> results = api.getADUserGCAttrs(ldpClient, baseDn, samAccountName);
        System.out.println("getAttrs Complete: "+System.currentTimeMillis());
        
		System.out.println("getAttrs start: " + System.currentTimeMillis());

		System.out.println("getAttrs Complete: " + System.currentTimeMillis());

		System.out.println("DisplayName: " + api.getDisplayName(ldpClient, baseDn, samAccountName));

		System.out.println("CN: " + api.getCN(results));

		System.out.println("DN: " + api.getDN(results));

		System.out.println("Manger: " + api.getManager(results));

		System.out.println("ObjectGUID: " + api.getObjectGuid(results));

		System.out.println("UPN: " + api.getUPN(results));

		System.out.println("Phone: " + api.getPhoneNumber(results));

		System.out.println("Email: " + api.getUserMail(results));

		System.out.println("whenChanged: " + api.getWhenChanged(results));

		System.out.println("whenCreated: " + api.getWhenCreated(results));

		System.out.println("uSNCreated: " + api.getUSNCreated(results));

		System.out.println("uSNChanged: " + api.getUSNChanged(results));

		System.out.println("createTimeStamp: " + api.getCreateTimeStamp(results));

		System.out.println("modifyTimeStamp: " + api.getModifyTimeStamp(results));

		System.out.println("lastLogonTimeStamp: " + api.getLastLogonTimeStamp(results));

		System.out.println("pwdLastSet: " + api.getPwdLastSet(results));

		System.out.println("lockoutTime: " + api.getLockOutTime(results));

		System.out.println("badPwdCount: " + api.getBadPwdCount(results));

		System.out.println("badPasswordTime: " + api.getBadPwdTime(results));

		System.out.println("lastLogon: " + api.getLastLogonTimeStamp(results));

		long uacc = api.getUACC(results);
		long uac = api.getUserAccountControl(results);
		System.out.println("Account Disabled: " + api.getAccountDisabled(uac));
		System.out.println("Password Never Expires: " + api.getPasswordNeverExpires(uac));
		System.out.println("SmartCard Required: " + api.getSmartCardRequired(uac));
		System.out.println("Kerberos PreAuth Required: " + api.getRequireKrbPreAuth(uac));
		System.out.println("Kerberos DES Types Allowed: " + api.getUseKrbDESTypes(uac));
		System.out.println("Use Reversible Encryption Password: " + api.getUseRevEncryptPasswd(uac));
		System.out.println("Allow Delegation: " + api.getAllowDelegation(uac));
		System.out.println("Account LockedOut: " + api.getLockedOut(uacc));
		List<String> groupList = api.getMemberOf(results);
		for (int i = 0; i < groupList.size(); i++) {
			System.out.println("MemberOf: " + groupList.get(i));
		}
		System.out.println("");
		System.out.println("");
		System.out.println("");

		System.out.println("Get Group Info and Members: " + groupSamAccountName);
		System.out.println("Group CN: " + gcApi.getCN(groupResults));

		System.out.println("Group DN: " + gcApi.getDN(groupResults));

		System.out.println("Group Email: " + gcApi.getUserMail(groupResults));

		System.out.println("Group whenChanged: " + gcApi.getWhenChanged(groupResults));

		System.out.println("Group whenCreated: " + gcApi.getWhenCreated(groupResults));

		System.out.println("Group uSNCreated: " + gcApi.getUSNCreated(groupResults));

		System.out.println("Group uSNChanged: " + gcApi.getUSNChanged(groupResults));

		System.out.println("Group createTimeStamp: " + gcApi.getCreateTimeStamp(groupResults));

		System.out.println("Group modifyTimeStamp: " + gcApi.getModifyTimeStamp(results));
		List<String> groupMbrList = gcApi.getGroupMembers(groupResults);
		for (int i = 0; i < groupMbrList.size(); i++) {
			System.out.println("Group Member: " + groupMbrList.get(i));
		}

		// ldpClient.destroyLdapClient();

	}
}
