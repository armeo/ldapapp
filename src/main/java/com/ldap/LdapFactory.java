package com.ldap;

import javax.naming.Context;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;

/**
 * Created by Adisorn Chockaumnuai on 6/25/2014.
 */
public class LdapFactory {

    private String principal;
    private String credential;

    public LdapFactory(String user, String password) {
        this.principal = user;
        this.credential = password;
    }

    public DirContext getConnection() {
        Hashtable<Object, Object> env = new Hashtable<Object, Object>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://oid.fico.com:3060");
        env.put(Context.SECURITY_PRINCIPAL, String.format("cn=%s", this.principal));
        env.put(Context.SECURITY_CREDENTIALS, this.credential);

        try {
            return new InitialDirContext(env);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }

    public String getEmail(String user) {
        DirContext dirContext = getConnection();
        StringBuilder searchUser = new StringBuilder("cn=");
        searchUser.append(user);
        searchUser.append(",cn=Users,dc=fico,dc=com");
        try {
            Attributes attr = dirContext.getAttributes(searchUser.toString(), new String[]{"mail"});

            return attr.get("mail").get().toString();
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return "";
        }
    }
}
