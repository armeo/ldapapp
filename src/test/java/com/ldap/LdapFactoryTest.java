package com.ldap;

import org.junit.Before;
import org.junit.Test;

import javax.naming.NamingException;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

/**
 * Created by Adisorn Chockaumnuai on 6/25/2014.
 */
public class LdapFactoryTest {

    private LdapFactory ldap;

    @Before
    public void setUp(){
        String user = "orcladmin";
        String password = "OID#dm1n";
        ldap = new LdapFactory(user, password);
    }

    @Test
    public void shouldNullWithWrongUsernamePassword() throws NamingException {
        ldap = new LdapFactory("xxx", "xxx");
        assertThat(ldap.getConnection(), is(nullValue()));
    }

    @Test
    public void shouldNotNullWithRightUsernamePassword() throws NamingException {
        assertThat(ldap.getConnection(), is(notNullValue()));
    }

    @Test
    public void shouldReturnEmailWhenUserExists(){
        assertThat(ldap.getEmail("orcladmin"), is("orcl@mail.com"));
    }

    @Test
    public void shouldReturnEmptyStringWhenUserNotExists(){
        assertThat(ldap.getEmail("notexist"), is(""));
    }
}