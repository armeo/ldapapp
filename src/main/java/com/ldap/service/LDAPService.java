package com.ldap.service;

import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldif.LDIFException;
import org.joda.time.DateTime;

import java.util.Date;

public class LDAPService {

    public static final Date INFINITY_TIME = new Date(Long.MAX_VALUE);
    private LDAPConnection ldapConnection;
    private String parentDN;

    public LDAPService() {
    }

    public LDAPService(String parentDN) {
        this.parentDN = parentDN;
    }

    public LDAPService(LDAPConnection ldapConnection, String parentDN) {
        this.ldapConnection = ldapConnection;
        this.parentDN = parentDN;
    }

    public void setLdapConnection(LDAPConnection ldapConnection) {
        this.ldapConnection = ldapConnection;
    }

    public void setPwdMaxAge(String username) throws LDIFException, LDAPException {
        Modification modification = new Modification(ModificationType.ADD, "pwdMaxAge", "7776000");
        ldapModify(username, modification);
    }

    public void inactivateAccount(String username) throws LDIFException, LDAPException {
        Modification modification = new Modification(ModificationType.ADD, "nsroledn", String.format("cn=nsManagedDisabledRole,%s", parentDN));
        ldapModify(username, modification);

        modification = new Modification(ModificationType.ADD, "nsaccountlock", "true");
        ldapModify(username, modification);
    }

    public void activateAccount(String username) throws LDIFException, LDAPException {
        Modification modification = new Modification(ModificationType.DELETE, "nsroledn");
        ldapModify(username, modification);

        modification = new Modification(ModificationType.DELETE, "nsaccountlock");
        ldapModify(username, modification);
    }

    public void updateUserPassword(String username, String password) throws LDIFException, LDAPException {
        Modification modification = new Modification(ModificationType.REPLACE, "userpassword", password);
        ldapModify(username, modification);
    }

    public String currentUserStatus(String username) throws LDAPException {
        if (isAccountLocked(username)) {
            return "Locked";
        } else {
            return ldapSearch(SearchScope.SUB, String.format("(uid=%s)", username), "nsaccountlock") != null ? "Inactive" : "Active";
        }
    }

    public boolean isAccountLocked(String username) throws LDAPException {
        return ldapSearchBoolean(SearchScope.SUB, String.format("(uid=%s)", username), "accountunlocktime");
    }

    public boolean isAccountActivate(String username) throws LDAPException {
        return !ldapSearchBoolean(SearchScope.SUB, String.format("(uid=%s)", username), "nsaccountlock");
    }

    public Date getUserAccountExpirationDate(String username) {
        try {
            int dayInSeconds = 86400;
            Date userCreateDate = ldapSearchDate(SearchScope.SUB, String.format("(uid=%s)", username), "pwdchangedtime");
            String userPasswordPolicy = ldapSearchString(SearchScope.SUB, String.format("(uid=%s)", username), "passwordpolicysubentry");
            userPasswordPolicy = userPasswordPolicy != null ? userPasswordPolicy : "cn=Password Policy,cn=config";
            this.parentDN = userPasswordPolicy;

            ldapConnection.bind("cn=admin,cn=administrators,cn=dscc", "Odsee#dm1n");
            Integer pwdMaxAge = ldapSearchInteger(SearchScope.BASE, "(objectclass=*)", "pwdMaxAge");

            if (pwdMaxAge == 0) {
                return INFINITY_TIME;
            }

            DateTime dateTime = new DateTime(userCreateDate);
            return dateTime.plusDays(Integer.valueOf(pwdMaxAge) / dayInSeconds).toDate();
        } catch (LDAPException le) {
            System.out.println(String.format("%s - %s", le.getResultCode(), le.getMessage()));
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
        return null;
    }

    public boolean haveLDAPAuthentication(String username, String password){
        return ldapBind(username, password) != null ? true : false;
    }

    private BindResult ldapBind(String username, String password) {
        try {
            return ldapConnection.bind(String.format("uid=%s,ou=people,dc=fico,dc=com", username), password);
        } catch (LDAPException le) {
            System.out.println(String.format("%s - %s", le.getResultCode(), le.getMessage()));
            return null;
        }
    }

    private String ldapSearchString(SearchScope searchScope, String searchFilter, String searchAttribute) throws LDAPSearchException {
        SearchResultEntry entry = ldapSearch(searchScope, searchFilter, searchAttribute);
        return (entry != null) ? entry.getAttributeValue(searchAttribute) : null;
    }

    private Integer ldapSearchInteger(SearchScope searchScope, String searchFilter, String searchAttribute) throws LDAPSearchException {
        SearchResultEntry entry = ldapSearch(searchScope, searchFilter, searchAttribute);
        return (entry != null) ? entry.getAttributeValueAsInteger(searchAttribute) : null;
    }

    private Date ldapSearchDate(SearchScope searchScope, String searchFilter, String searchAttribute) throws LDAPSearchException {
        SearchResultEntry entry = ldapSearch(searchScope, searchFilter, searchAttribute);
        return (entry != null) ? entry.getAttributeValueAsDate(searchAttribute) : null;
    }

    private Boolean ldapSearchBoolean(SearchScope searchScope, String searchFilter, String searchAttribute) throws LDAPSearchException {
        SearchResultEntry entry = ldapSearch(searchScope, searchFilter, searchAttribute);
        return (entry != null) ? entry.getAttributeValueAsBoolean(searchAttribute) : false;
    }

    private SearchResultEntry ldapSearch(SearchScope searchScope, String searchFilter, String searchAttribute) throws LDAPSearchException {
        SearchResult searchResults = ldapConnection.search(parentDN, searchScope, searchFilter, searchAttribute);
        return (searchResults != null && searchResults.getEntryCount() > 0 && searchResults.getSearchEntries().get(0).hasAttribute(searchAttribute)) ? searchResults.getSearchEntries().get(0) : null;
    }

    private LDAPResult ldapModify(String username, Modification modification) throws LDAPException {
        ldapConnection.bind("cn=admin,cn=administrators,cn=dscc", "Odsee#dm1n");
        LDAPResult ldapResult = ldapConnection.modify(String.format("uid=%s,%s", username, parentDN), modification);

        return ldapResult;
    }
}