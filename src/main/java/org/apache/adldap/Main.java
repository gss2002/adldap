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

public class Main {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		String baseDn = "dc=hdpusr,dc=senia,dc=org";
		String bindDn = "";
		String bindPw = "";
		String ldapURL = "";
		String samAccountName = "";
		String groupSamAccountName = "";
		LdapClient ldpClient = new LdapClientSimple(baseDn, bindDn, bindPw, ldapURL);
		LdapApi api = new LdapApi();
		Map<String,Attribute> groupResults = api.getADGroupGCAttrs(ldpClient, baseDn, groupSamAccountName);
		Map<String,Attribute> results = api.getADUserGCAttrs(ldpClient, baseDn, samAccountName);
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
		System.out.println("Group CN: "+api.getCN(groupResults));

		System.out.println("Group DN: "+api.getDN(groupResults));
		
		System.out.println("Group Email: "+api.getUserMail(groupResults));

		System.out.println("Group whenChanged: "+api.getWhenChanged(groupResults));

		System.out.println("Group whenCreated: "+api.getWhenCreated(groupResults));
		
		System.out.println("Group uSNCreated: "+api.getUSNCreated(groupResults));

		System.out.println("Group uSNChanged: "+api.getUSNChanged(groupResults));

		System.out.println("Group createTimeStamp: "+api.getCreateTimeStamp(groupResults));

		
		System.out.println("Group modifyTimeStamp: "+api.getModifyTimeStamp(results));
		List<String> groupMbrList = api.getGroupMembers(groupResults);
		for (int i = 0; i < groupMbrList.size(); i++) {
			System.out.println("Group Member: "+groupMbrList.get(i));
		}	




		//ldpClient.destroyLdapClient();

		}
	}

