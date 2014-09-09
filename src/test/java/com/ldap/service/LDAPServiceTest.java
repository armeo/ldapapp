package com.ldap.service;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldif.LDIFException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

/**
 * Created by Adisorn Chockaumnuai on 9/9/2014.
 */
public class LDAPServiceTest {

    private InMemoryDirectoryServer server;
    private LDAPConnection conn;

    @Before
    public void setUp() throws LDAPException, LDIFException {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=fico,dc=com");
        config.addAdditionalBindCredentials("cn=Directory Manager", "password");
        config.setSchema(null);

        server = new InMemoryDirectoryServer(config);
        server.startListening();

        server.add("dn: dc=fico,dc=com", "objectClass: top", "objectClass: domain");
        server.add("dn: ou=people,dc=fico,dc=com", "objectClass: top", "objectClass: organizationalunit");
        server.add("dn: uid=AdminData1,ou=people,dc=fico,dc=com", "objectclass: top", "objectclass: ficoUser", "uid: AdminData1", "userPassword: cl0ud+rain", "mail: admin@fico.com", "cn: First Last", "givenname: First", "sn: Last");

        conn = server.getConnection();
        System.out.println(conn.getSchema().getSchemaEntry().toLDIFString());
    }

    @After
    public void tearDown() {
        conn.close();
        server.shutDown(true);
    }

    @Test
    public void shouldNotNullWhenLDAPBindSuccessfully() {
        //given
        LDAPService ldapService = new LDAPService();
        String username = "AdminData1";
        String password = "cl0ud+rain";

        //when
        Object ldapBind = ldapService.ldapBind(conn, username, password);

        //then
        assertThat(ldapBind, is(notNullValue()));
    }
}
