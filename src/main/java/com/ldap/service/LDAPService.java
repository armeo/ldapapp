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

    public void setPwdMaxAge(LDAPConnection ldapConnection, String username, String parentDN) throws LDIFException, LDAPException {
        Modification modification = new Modification(ModificationType.ADD, "pwdMaxAge", "7776000");
        ldapModify(ldapConnection, username, parentDN, modification);
    }

    public void inactivateAccount(LDAPConnection ldapConnection, String username, String parentDN) throws LDIFException, LDAPException {
        Modification modification = new Modification(ModificationType.ADD, "nsroledn", String.format("cn=nsManagedDisabledRole,%s", parentDN));
        ldapModify(ldapConnection, username, parentDN, modification);

        modification = new Modification(ModificationType.ADD, "nsaccountlock", "true");
        ldapModify(ldapConnection, username, parentDN, modification);
    }

    public void activateAccount(LDAPConnection ldapConnection, String username, String parentDN) throws LDIFException, LDAPException {
        Modification modification = new Modification(ModificationType.DELETE, "nsroledn");
        ldapModify(ldapConnection, username, parentDN, modification);

        modification = new Modification(ModificationType.DELETE, "nsaccountlock");
        ldapModify(ldapConnection, username, parentDN, modification);
    }

    public void updateUserPassword(LDAPConnection ldapConnection, String username, String password, String parentDN) throws LDIFException, LDAPException {
        Modification modification = new Modification(ModificationType.REPLACE, "userpassword", password);
        ldapModify(ldapConnection, username, parentDN, modification);
    }

    public String currentUserStatus(LDAPConnection ldapConnection, String username, String parentDN) throws LDAPException {
        if (isAccountLocked(ldapConnection, username, parentDN)) {
            return "Locked";
        } else {
            return ldapSearch(ldapConnection, parentDN, SearchScope.SUB, String.format("(uid=%s)", username), "nsaccountlock") != null ? "Inactive" : "Active";
        }
    }

    public boolean isAccountLocked(LDAPConnection ldapConnection, String username, String parentDN) throws LDAPException {
        return ldapSearchBoolean(ldapConnection, parentDN, SearchScope.SUB, String.format("(uid=%s)", username), "accountunlocktime");
    }

    public boolean isAccountActivate(LDAPConnection ldapConnection, String username, String parentDN) throws LDAPException {
        return !ldapSearchBoolean(ldapConnection, parentDN, SearchScope.SUB, String.format("(uid=%s)", username), "nsaccountlock");
    }

    public Date getUserAccountExpirationDate(LDAPConnection ldapConnection, String username, String parentDN) {
        try {
            int dayInSeconds = 86400;
            Date userCreateDate = ldapSearchDate(ldapConnection, parentDN, SearchScope.SUB, String.format("(uid=%s)", username), "pwdchangedtime");
            String userPasswordPolicy = ldapSearchString(ldapConnection, parentDN, SearchScope.SUB, String.format("(uid=%s)", username), "passwordpolicysubentry");
            userPasswordPolicy = userPasswordPolicy != null ? userPasswordPolicy : "cn=Password Policy,cn=config";

            ldapConnection.bind("cn=admin,cn=administrators,cn=dscc", "Odsee#dm1n");
            Integer pwdMaxAge = ldapSearchInteger(ldapConnection, userPasswordPolicy, SearchScope.BASE, "(objectclass=*)", "pwdMaxAge");

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

    public BindResult ldapBind(LDAPConnection ldapConnection, String username, String password) {
        try {
            return ldapConnection.bind(String.format("uid=%s,ou=people,dc=fico,dc=com", username), password);
        } catch (LDAPException le) {
            System.out.println(String.format("%s - %s", le.getResultCode(), le.getMessage()));
            return null;
        }
    }

    private String ldapSearchString(LDAPConnection ldapConnection, String parentDN, SearchScope searchScope, String searchFilter, String searchAttribute) throws LDAPSearchException {
        SearchResultEntry entry = ldapSearch(ldapConnection, parentDN, searchScope, searchFilter, searchAttribute);
        return (entry != null) ? entry.getAttributeValue(searchAttribute) : null;
    }

    private Integer ldapSearchInteger(LDAPConnection ldapConnection, String parentDN, SearchScope searchScope, String searchFilter, String searchAttribute) throws LDAPSearchException {
        SearchResultEntry entry = ldapSearch(ldapConnection, parentDN, searchScope, searchFilter, searchAttribute);
        return (entry != null) ? entry.getAttributeValueAsInteger(searchAttribute) : null;
    }

    private Date ldapSearchDate(LDAPConnection ldapConnection, String parentDN, SearchScope searchScope, String searchFilter, String searchAttribute) throws LDAPSearchException {
        SearchResultEntry entry = ldapSearch(ldapConnection, parentDN, searchScope, searchFilter, searchAttribute);
        return (entry != null) ? entry.getAttributeValueAsDate(searchAttribute) : null;
    }

    private Boolean ldapSearchBoolean(LDAPConnection ldapConnection, String parentDN, SearchScope searchScope, String searchFilter, String searchAttribute) throws LDAPSearchException {
        SearchResultEntry entry = ldapSearch(ldapConnection, parentDN, searchScope, searchFilter, searchAttribute);
        return (entry != null) ? entry.getAttributeValueAsBoolean(searchAttribute) : false;
    }

    private SearchResultEntry ldapSearch(LDAPConnection ldapConnection, String parentDN, SearchScope searchScope, String searchFilter, String searchAttribute) throws LDAPSearchException {
        SearchResult searchResults = ldapConnection.search(parentDN, searchScope, searchFilter, searchAttribute);
        return (searchResults != null && searchResults.getEntryCount() > 0 && searchResults.getSearchEntries().get(0).hasAttribute(searchAttribute)) ? searchResults.getSearchEntries().get(0) : null;
    }

    private LDAPResult ldapModify(LDAPConnection ldapConnection, String username, String parentDN, Modification modification) throws LDAPException {
        BindResult bindResult = ldapConnection.bind("cn=admin,cn=administrators,cn=dscc", "Odsee#dm1n");
        LDAPResult ldapResult = ldapConnection.modify(String.format("uid=%s,%s", username, parentDN), modification);

        return ldapResult;
    }
}