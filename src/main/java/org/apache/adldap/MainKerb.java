/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.adldap;


import java.util.List;
import java.util.Map;

import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.SearchResult;

public class MainKerb {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		System.setProperty("sun.security.krb5.debug", "false");
		System.setProperty("java.security.krb5.conf", "/Users/gss2002/krb5.conf");
		String gcBaseDn = "dc=hdpusr,dc=senia,dc=org";
		String bindDn = "gss2002@HDPUSR.SENIA.ORGM";
		String bindPw = "";
		String gcldapURL = "ldap://seniadc1.hdpusr.senia.org:3268";
		//String ldapURL = "ldap://seniadc1.hdpusr.senia.org";
		String samAccountName = "gss2002";
		String groupSamAccountName = "hdpdev-user";
		 System.out.println("LdapClientKerb Start: "+System.currentTimeMillis());
		KerberosClient krbClient = new KerberosClient(bindDn, null, "/Users/gss2002/username.keytab");
		LdapClient gcldpClient = new LdapClientSASL(gcBaseDn,gcldapURL, krbClient.getSubject());

		 System.out.println("LdapClientKerb Complete: "+System.currentTimeMillis());

		LdapApi gcApi = new LdapApi();
		String dn = gcApi.getDN(gcldpClient, gcBaseDn, samAccountName);
		String domain_interim = dn.split(",DC=", 2)[1];
		String domain_baseDN = "DC="+domain_interim;
		System.out.println("dn: "+dn);
		System.out.println("baseDN="+domain_baseDN);
		String domain = domain_baseDN.replace("DC=", "").replace(",", ".");
        String baseDn = domain_baseDN;
        System.out.println(domain_baseDN);
        System.out.println(domain);

        DnsLookup dns = new DnsLookup();
        String ldapServer = dns.getLdapServer(domain);
        String ldapUrl = "ldap://"+ldapServer+":389";
		LdapClient ldpClient = new LdapClientSASL(baseDn,ldapUrl, krbClient.getSubject());
		LdapApi api = new LdapApi();

		Map<String,Attribute> groupResults = gcApi.getADGroupGCAttrs(gcldpClient, gcBaseDn, groupSamAccountName);
		System.out.println("getAttrs start: "+System.currentTimeMillis());

		Map<String,Attribute> results = api.getADUserGCAttrs(ldpClient, baseDn, samAccountName);
		 System.out.println("getAttrs Complete: "+System.currentTimeMillis());

		System.out.println("DisplayName: "+api.getDisplayName(ldpClient, baseDn, samAccountName));

		System.out.println("CN: "+api.getCN(results));

		System.out.println("DN: "+api.getDN(results));

		System.out.println("Manger: "+api.getManager(results));
		
		System.out.println("ObjectGUID: "+api.getObjectGuid(results));


		
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
		List<String> groupList = api.getMemberOf(results);
		for (int i = 0; i < groupList.size(); i++) {
			System.out.println("MemberOf: "+groupList.get(i));
		}
		System.out.println("");
		System.out.println("");
		System.out.println("");

		System.out.println("Get Group Info and Members: "+groupSamAccountName);
		System.out.println("Group CN: "+gcApi.getCN(groupResults));

		System.out.println("Group DN: "+gcApi.getDN(groupResults));
		
		System.out.println("Group Email: "+gcApi.getUserMail(groupResults));

		System.out.println("Group whenChanged: "+gcApi.getWhenChanged(groupResults));

		System.out.println("Group whenCreated: "+gcApi.getWhenCreated(groupResults));
		
		System.out.println("Group uSNCreated: "+gcApi.getUSNCreated(groupResults));

		System.out.println("Group uSNChanged: "+gcApi.getUSNChanged(groupResults));

		System.out.println("Group createTimeStamp: "+gcApi.getCreateTimeStamp(groupResults));

		
		System.out.println("Group modifyTimeStamp: "+gcApi.getModifyTimeStamp(results));
		List<String> groupMbrList = gcApi.getGroupMembers(groupResults);
		for (int i = 0; i < groupMbrList.size(); i++) {
			System.out.println("Group Member: "+groupMbrList.get(i));
		}



		//ldpClient.destroyLdapClient();

		}
	}

