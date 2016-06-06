package org.apache.adldap;

public class Main {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		String baseDn = "OU=INTERNAL,dc=hdpusr,dc=senia,dc=org";
		String bindDn = "cn=ldapsearch,ou=internal,dc=hdpusr,dc=senia,dc=org";
		String bindPw = "";
		String ldapURL = "ldaps://seniadc1.senia.org:636";
		String samAccountName = "";
		LdapClient ldpClient = new LdapClient(baseDn, bindDn, bindPw, ldapURL);
		LdapApi api = new LdapApi();
		System.out.println("DisplayName: "+api.getDisplayName(ldpClient, baseDn, samAccountName));

		System.out.println("UPN: "+api.getUPN(ldpClient, baseDn, samAccountName));
		System.out.println("Phone: "+api.getPhoneNumber(ldpClient, baseDn, samAccountName));
		System.out.println("Email: "+api.getUserMail(ldpClient, baseDn, samAccountName));
		System.out.println("whenChanged: "+api.getWhenChanged(ldpClient, baseDn, samAccountName));
		System.out.println("whenCreated: "+api.getWhenCreated(ldpClient, baseDn, samAccountName));
		System.out.println("pwdLastSet: "+api.getPwdLastSet(ldpClient, baseDn, samAccountName));
		System.out.println("lockoutTime: "+api.getLockOutTime(ldpClient, baseDn, samAccountName));
		System.out.println("badPwdCount: "+api.getBadPwdCount(ldpClient, baseDn, samAccountName));
		System.out.println("badPasswordTime: "+api.getBadPwdTime(ldpClient, baseDn, samAccountName));
		System.out.println("lastLogon: "+api.getLastLogonTimeStamp(ldpClient, baseDn, samAccountName));

	}


}
