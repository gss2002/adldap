package org.apache.adldap;

import java.util.Hashtable;

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
