package com.ldap;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

/**
 * Created by Adisorn Chockaumnuai on 6/25/2014.
 */
public class LdapFactoryTest {

    @Test
    public void shouldNullWithWrongUsernamePassword(){
        String user = "aaa";
        String password = "xxx";
        LdapFactory ldap = new LdapFactory(user, password);

        assertThat(ldap.getConnection(), is(nullValue()));
    }
}
