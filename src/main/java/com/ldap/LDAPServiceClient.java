package com.ldap;

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

public class LDAPServiceClient {

    public static void setPwdMaxAge(LDAPConnection ldapConnection, String username, String parentDN) throws LDIFException, LDAPException {
        Modification modification = new Modification(ModificationType.ADD, "pwdMaxAge", "7776000");
        ldapModify(ldapConnection, username, parentDN, modification);
    }

    public static void inactivateAccount(LDAPConnection ldapConnection, String username, String parentDN) throws LDIFException, LDAPException {
        Modification modification = new Modification(ModificationType.ADD, "nsroledn", String.format("cn=nsManagedDisabledRole,%s", parentDN));
        ldapModify(ldapConnection, username, parentDN, modification);

        modification = new Modification(ModificationType.ADD, "nsaccountlock", "true");
        ldapModify(ldapConnection, username, parentDN, modification);
    }

    public static void activateAccount(LDAPConnection ldapConnection, String username, String parentDN) throws LDIFException, LDAPException {
        Modification modification = new Modification(ModificationType.DELETE, "nsroledn");
        ldapModify(ldapConnection, username, parentDN, modification);

        modification = new Modification(ModificationType.DELETE, "nsaccountlock");
        ldapModify(ldapConnection, username, parentDN, modification);
    }

    public static void updateUserPassword(LDAPConnection ldapConnection, String username, String password, String parentDN) throws LDIFException, LDAPException {
        Modification modification = new Modification(ModificationType.REPLACE, "userpassword", password);
        ldapModify(ldapConnection, username, parentDN, modification);
    }

    public static String currentUserStatus(LDAPConnection ldapConnection, String username, String parentDN) throws LDAPException {
        if (isAccountLocked(ldapConnection, username, parentDN)) {
            return "Locked";
        } else {
            return ldapSearch(ldapConnection, parentDN, SearchScope.SUB, String.format("(uid=%s)", username), "nsaccountlock") != null ? "Inactive" : "Active";
        }
    }

    public static boolean isAccountLocked(LDAPConnection ldapConnection, String username, String parentDN) throws LDAPException {
        return ldapSearchBoolean(ldapConnection, parentDN, SearchScope.SUB, String.format("(uid=%s)", username), "accountunlocktime");
    }

    public static boolean isAccountActivate(LDAPConnection ldapConnection, String username, String parentDN) throws LDAPException {
        return !ldapSearchBoolean(ldapConnection, parentDN, SearchScope.SUB, String.format("(uid=%s)", username), "nsaccountlock");
    }

    public static Date getUserAccountExpirationDate(LDAPConnection ldapConnection, String username, String parentDN) {
        try {
            int dayInSeconds = 86400;
            Date infinityTime = new Date(Long.MAX_VALUE);
            Date userCreateDate = ldapSearchDate(ldapConnection, parentDN, SearchScope.SUB, String.format("(uid=%s)", username), "pwdchangedtime");
            String userPasswordPolicy = ldapSearchString(ldapConnection, parentDN, SearchScope.SUB, String.format("(uid=%s)", username), "passwordpolicysubentry");
            userPasswordPolicy = userPasswordPolicy != null ? userPasswordPolicy : "cn=Password Policy,cn=config";

            ldapConnection.bind("cn=admin,cn=administrators,cn=dscc", "Odsee#dm1n");
            Integer pwdMaxAge = ldapSearchInteger(ldapConnection, userPasswordPolicy, SearchScope.BASE, "(objectclass=*)", "pwdMaxAge");

            if (pwdMaxAge == 0) {
                return infinityTime;
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

    private static String ldapSearchString(LDAPConnection ldapConnection, String parentDN, SearchScope searchScope, String searchFilter, String searchAttribute) throws LDAPSearchException {
        SearchResultEntry entry = ldapSearch(ldapConnection, parentDN, searchScope, searchFilter, searchAttribute);
        return (entry != null) ? entry.getAttributeValue(searchAttribute) : null;
    }

    private static Integer ldapSearchInteger(LDAPConnection ldapConnection, String parentDN, SearchScope searchScope, String searchFilter, String searchAttribute) throws LDAPSearchException {
        SearchResultEntry entry = ldapSearch(ldapConnection, parentDN, searchScope, searchFilter, searchAttribute);
        return (entry != null) ? entry.getAttributeValueAsInteger(searchAttribute) : null;
    }

    private static Date ldapSearchDate(LDAPConnection ldapConnection, String parentDN, SearchScope searchScope, String searchFilter, String searchAttribute) throws LDAPSearchException {
        SearchResultEntry entry = ldapSearch(ldapConnection, parentDN, searchScope, searchFilter, searchAttribute);
        return (entry != null) ? entry.getAttributeValueAsDate(searchAttribute) : null;
    }

    private static Boolean ldapSearchBoolean(LDAPConnection ldapConnection, String parentDN, SearchScope searchScope, String searchFilter, String searchAttribute) throws LDAPSearchException {
        SearchResultEntry entry = ldapSearch(ldapConnection, parentDN, searchScope, searchFilter, searchAttribute);
        return (entry != null) ? entry.getAttributeValueAsBoolean(searchAttribute) : false;
    }

    private static SearchResultEntry ldapSearch(LDAPConnection ldapConnection, String parentDN, SearchScope searchScope, String searchFilter, String searchAttribute) throws LDAPSearchException {
        SearchResult searchResults = ldapConnection.search(parentDN, searchScope, searchFilter, searchAttribute);
        return (searchResults != null && searchResults.getEntryCount() > 0 && searchResults.getSearchEntries().get(0).hasAttribute(searchAttribute)) ? searchResults.getSearchEntries().get(0) : null;
    }

    private static LDAPResult ldapModify(LDAPConnection ldapConnection, String username, String parentDN, Modification modification) throws LDAPException {
        BindResult bindResult = ldapConnection.bind("cn=admin,cn=administrators,cn=dscc", "Odsee#dm1n");
        LDAPResult ldapResult = ldapConnection.modify(String.format("uid=%s,%s", username, parentDN), modification);

        return ldapResult;
    }

    public static void ldapBind(LDAPConnection ldapConnection, String username, String password) {
        try {
            ldapConnection.bind(String.format("uid=%s,ou=people,dc=fico,dc=com", username), password);
            System.out.println("=== Authen Successfully ===");
        } catch (LDAPException le) {
            System.out.println("=== Authen Faild ===");
            System.out.println(String.format("%s - %s", le.getResultCode(), le.getMessage()));
        }
    }

    public static void main(String[] args) {
        LDAPConnection ldapConnection;
        try {
            String parentDN = "ou=people,dc=fico,dc=com";
            //            SimpleDateFormat dateFormatGmt = new SimpleDateFormat("yyyyMMddHHmmss");
            //            dateFormatGmt.setTimeZone(TimeZone.getTimeZone("GMT"));
            //            System.out.println("DateTimeGMT: " + dateFormatGmt.parse("20140905033227"));
            //
            //            String currentDateTime = String.format("%sZ", dateFormatGmt.format(new Date()));
            //            System.out.println("currentDateTime: " + currentDateTime);
            //
            //            SimpleDateFormat dateFormat = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
            //            dateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
            //            System.out.printf("DateTime: %s\n", dateFormat.parse("20140905033227"));

            ldapConnection = new LDAPConnection("odsee.fico.com", 1389);

            //            ldapBind(ldapConnection, "AdminData3", "M@rwin1129");
            //            updateUserPassword(ldapConnection, "AdminData1", "9885462TRedfd#scsdosssd", parentDN);
            //            setPwdMaxAge(ldapConnection, "AdminData1", parentDN);
            //            System.out.printf("pwdMaxAge: %s", ldapSearch(ldapConnection, "AdminData1", parentDN, "pwdMaxAge"));
            //            passwordpolicysubentry: cn=FicoPasswordPolicy,cn=config
            //            BindResult bindResult = ldapConnection.bind("cn=admin,cn=administrators,cn=dscc", "Odsee#dm1n");
            //            SearchResult searchResults = ldapConnection.search("cn=Password Policy,cn=config", SearchScope.BASE, "(objectclass=*)", "pwdMaxAge");
            //            SearchResult searchResults = ldapConnection.search("cn=FicoPasswordPolicy,cn=config", SearchScope.BASE, "(objectclass=*)", "pwdMaxAge");
            //            String searchResult = null;
            //            if (searchResults.getEntryCount() > 0) {
            //                SearchResultEntry entry = searchResults.getSearchEntries().get(0);
            //                searchResult = entry.getAttributeValue("pwdMaxAge");
            //            }
            //            System.out.println(searchResult);
            //            System.out.printf("Exp: %s\n", getUserAccountExpirationDate(ldapConnection, "AdminData1", parentDN));
            //            System.out.println(new Date(Long.MAX_VALUE));
            //            BindResult bindResult = ldapConnection.bind("cn=admin,cn=administrators,cn=dscc", "Odsee#dm1n");
            //found->true
            DateTime exp = new DateTime(getUserAccountExpirationDate(ldapConnection, "AdminData3", parentDN));
            System.out.println(exp);
            DateTime curr = DateTime.now();
            System.out.println(curr);
            System.out.println(curr.compareTo(exp) <= 0);
        } catch (LDAPException le) {
            System.out.println(String.format("%s - %s", le.getResultCode(), le.getMessage()));
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
    }
}
