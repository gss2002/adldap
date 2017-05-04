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

import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.security.auth.Subject;

public class LdapBean {
	InitialDirContext ldapCtx;
	SearchControls constraints;
	Subject subject;
	
	public void setLdapCtx(InitialDirContext ldapCtx) {
		this.ldapCtx = ldapCtx;
	}
	public InitialDirContext getLdapCtx() {
		return this.ldapCtx;
	}
	public void setConstraints(SearchControls constraints) {
		this.constraints = constraints;
	}
	public SearchControls getConstraints() {
		return this.constraints;
	}
	public Subject getSubject() {
		return this.subject;
	}
	public void setSubject(Subject subject) {
		this.subject = subject;
	}
}
