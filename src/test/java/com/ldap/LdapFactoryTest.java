package com.ldap;

import org.junit.Test;

import javax.naming.NamingException;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

/**
 * Created by Adisorn Chockaumnuai on 6/25/2014.
 */
public class LdapFactoryTest {

    @Test
    public void shouldNullWithWrongUsernamePassword() throws NamingException {
        String user = "aaa";
        String password = "xxx";
        LdapFactory ldap = new LdapFactory(user, password);

        assertThat(ldap.getConnection(), is(nullValue()));
    }

    @Test
    public void shouldNotNullWithRightUsernamePassword() throws NamingException {
        String user = "cn=orcladmin";
        String password = "OID#dm1n";
        LdapFactory ldap = new LdapFactory(user, password);

        assertThat(ldap.getConnection(), is(notNullValue()));
    }

    @Test
    public void shouldReturnEmailWhenUserExists(){
        String user = "cn=orcladmin";
        String password = "OID#dm1n";
        LdapFactory ldap = new LdapFactory(user, password);

        assertThat(ldap.getEmail(user), is("orcl@mail.com"));
    }
}
