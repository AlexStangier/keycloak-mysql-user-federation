/*
   Copyright 2020 Kyriakos Chatzidimitriou

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */
package info.kyrcha.keycloak.mysqluserfederation;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.codec.digest.DigestUtils;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.*;
import org.keycloak.storage.ReadOnlyException;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.adapter.AbstractUserAdapter;
import org.keycloak.storage.federated.UserFederatedStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;

public class MySQLUserStorageProvider
        implements UserStorageProvider, UserLookupProvider, CredentialInputValidator, CredentialInputUpdater, UserQueryProvider {

    protected KeycloakSession session;
    protected Connection conn;
    protected ComponentModel config;

    private static final Logger logger = Logger.getLogger(MySQLUserStorageProvider.class);

    public MySQLUserStorageProvider(KeycloakSession session, ComponentModel config, Connection conn) {
        this.session = session;
        this.config = config;
        this.conn = conn;
    }

    @Override
    public UserModel getUserByUsername(String username, RealmModel realm) {
        Statement stmt = null;
        ResultSet rs = null;
        UserModel adapter = null;
        try {
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT " + this.config.getConfig().getFirst("usernamecol") + ", "
                    + this.config.getConfig().getFirst("passwordcol") + " FROM "
                    + this.config.getConfig().getFirst("table") + " WHERE "
                    + this.config.getConfig().getFirst("usernamecol") + "=" + username + ";");
            String pword = null;
            if (rs.next()) {
                pword = rs.getString(this.config.getConfig().getFirst("passwordcol"));
            }
            if (pword != null) {
                adapter = createAdapter(realm, username);
            }
            // Now do something with the ResultSet ....
        } catch (SQLException ex) {
            // handle any errors
            System.out.println("SQLException: " + ex.getMessage());
            System.out.println("SQLState: " + ex.getSQLState());
            System.out.println("VendorError: " + ex.getErrorCode());
        } finally {
            // it is a good idea to release
            // resources in a finally{} block
            // in reverse-order of their creation
            // if they are no-longer needed

            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException sqlEx) {
                } // ignore

                rs = null;
            }

            if (stmt != null) {
                try {
                    stmt.close();
                } catch (SQLException sqlEx) {
                } // ignore

                stmt = null;
            }
        }
        return adapter;
    }

    protected UserModel createAdapter(RealmModel realm, String username) {
        return new AbstractUserAdapter(session, realm, config) {
            @Override
            public String getUsername() {
                return username;
            }
        };
    }

    @Override
    public UserModel getUserById(String id, RealmModel realm) {
        StorageId storageId = new StorageId(id);
        String username = storageId.getExternalId();
        return getUserByUsername(username, realm);
    }

    @Override
    public UserModel getUserByEmail(String email, RealmModel realm) {
        return null;
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        String password = null;
        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT " + this.config.getConfig().getFirst("usernamecol") + ", "
                    + this.config.getConfig().getFirst("passwordcol") + " FROM "
                    + this.config.getConfig().getFirst("table") + " WHERE "
                    + this.config.getConfig().getFirst("usernamecol") + "=" + user.getUsername() + ";");
            if (rs.next()) {
                password = rs.getString(this.config.getConfig().getFirst("passwordcol"));
            }
            // Now do something with the ResultSet ....
        } catch (SQLException ex) {
            // handle any errors
            System.out.println("SQLException: " + ex.getMessage());
            System.out.println("SQLState: " + ex.getSQLState());
            System.out.println("VendorError: " + ex.getErrorCode());
        } finally {
            // it is a good idea to release
            // resources in a finally{} block
            // in reverse-order of their creation
            // if they are no-longer needed

            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException sqlEx) {
                } // ignore

                rs = null;
            }

            if (stmt != null) {
                try {
                    stmt.close();
                } catch (SQLException sqlEx) {
                } // ignore

                stmt = null;
            }
        }
        return credentialType.equals(CredentialModel.PASSWORD) && password != null;
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return credentialType.equals(CredentialModel.PASSWORD);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!supportsCredentialType(input.getType()))
            return false;
        String password = null;
        Statement stmt = null;
        ResultSet rs = null;
        try {
            stmt = conn.createStatement();
            rs = stmt.executeQuery("SELECT " + this.config.getConfig().getFirst("usernamecol") + ", "
                    + this.config.getConfig().getFirst("passwordcol") + " FROM "
                    + this.config.getConfig().getFirst("table") + " WHERE "
                    + this.config.getConfig().getFirst("usernamecol") + "=" + user.getUsername() + ";");
            if (rs.next()) {
                password = rs.getString(this.config.getConfig().getFirst("passwordcol"));
            }
            // Now do something with the ResultSet ....
        } catch (SQLException ex) {
            // handle any errors
            System.out.println("SQLException: " + ex.getMessage());
            System.out.println("SQLState: " + ex.getSQLState());
            System.out.println("VendorError: " + ex.getErrorCode());
        } finally {
            // it is a good idea to release
            // resources in a finally{} block
            // in reverse-order of their creation
            // if they are no-longer needed

            if (rs != null) {
                try {
                    rs.close();
                } catch (SQLException sqlEx) {
                } // ignore

                rs = null;
            }

            if (stmt != null) {
                try {
                    stmt.close();
                } catch (SQLException sqlEx) {
                } // ignore

                stmt = null;
            }
        }

        if (password == null)
            return false;

        String hex = null;
        if (this.config.getConfig().getFirst("hash").equalsIgnoreCase("SHA1")) {
            hex = DigestUtils.sha1Hex(input.getChallengeResponse());
        } else {
            hex = DigestUtils.md5Hex(input.getChallengeResponse());
        }
        return password.equalsIgnoreCase(hex);
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        if (input.getType().equals(CredentialModel.PASSWORD))
            throw new ReadOnlyException("user is read only for this update");

        return false;
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {

    }

    @Override
    public Set<String> getDisableableCredentialTypes(RealmModel realm, UserModel user) {
        return Collections.EMPTY_SET;
    }

    @Override
    public void close() {
        if (conn != null) {
            try {
                conn.close();
            } catch (SQLException sqlEx) {
                logger.error(sqlEx.getMessage());
            } // ignore
            conn = null;
        }
    }

    /**
     * Returns the number of users, without consider any service account.
     *
     * @param realm the realm
     * @return the number of users
     */
    @Override
    public int getUsersCount(RealmModel realm) {
        return 0;
    }

    /**
     * Returns the number of users that are in at least one of the groups
     * given.
     *
     * @param realm    the realm
     * @param groupIds set of groups id to check for
     * @return the number of users that are in at least one of the groups
     */
    @Override
    public int getUsersCount(RealmModel realm, Set<String> groupIds) {
        return 0;
    }

    /**
     * Returns the number of users that match the given criteria.
     *
     * @param search search criteria
     * @param realm  the realm
     * @return number of users that match the search
     */
    @Override
    public int getUsersCount(String search, RealmModel realm) {
        return 0;
    }

    /**
     * Returns the number of users that match the given criteria and are in
     * at least one of the groups given.
     *
     * @param search   search criteria
     * @param realm    the realm
     * @param groupIds set of groups to check for
     * @return number of users that match the search and given groups
     */
    @Override
    public int getUsersCount(String search, RealmModel realm, Set<String> groupIds) {
        return 0;
    }

    /**
     * Returns the number of users that match the given filter parameters.
     *
     * @param params filter parameters
     * @param realm  the realm
     * @return number of users that match the given filters
     */
    @Override
    public int getUsersCount(Map<String, String> params, RealmModel realm) {
        return 0;
    }

    /**
     * Returns the number of users that match the given filter parameters and is in
     * at least one of the given groups.
     *
     * @param params   filter parameters
     * @param realm    the realm
     * @param groupIds set if groups to check for
     * @return number of users that match the given filters and groups
     */
    @Override
    public int getUsersCount(Map<String, String> params, RealmModel realm, Set<String> groupIds) {
        return 0;
    }

    /**
     * Returns the number of users.
     *
     * @param realm                 the realm
     * @param includeServiceAccount if true, the number of users will also include service accounts. Otherwise, only the number of users.
     * @return the number of users
     */
    @Override
    public int getUsersCount(RealmModel realm, boolean includeServiceAccount) {
        return 0;
    }

    @Override
    public List<UserModel> getUsers(RealmModel realm) {
        return null;
    }

    @Override
    public List<UserModel> getUsers(RealmModel realm, int firstResult, int maxResults) {
        return null;
    }

    /**
     * Search for users with username, email or first + last name that is like search string.
     * <p>
     * If possible, implementations should treat the parameter values as partial match patterns i.e. in RDMBS terms use LIKE.
     * <p>
     * This method is used by the admin console search box
     *
     * @param search
     * @param realm
     * @return
     */
    @Override
    public List<UserModel> searchForUser(String search, RealmModel realm) {





        return null;
    }

    /**
     * Search for users with username, email or first + last name that is like search string.
     * <p>
     * If possible, implementations should treat the parameter values as partial match patterns i.e. in RDMBS terms use LIKE.
     * <p>
     * This method is used by the admin console search box
     *
     * @param search
     * @param realm
     * @param firstResult
     * @param maxResults
     * @return
     */
    @Override
    public List<UserModel> searchForUser(String search, RealmModel realm, int firstResult, int maxResults) {
        return null;
    }

    /**
     * Search for user by parameter.  Valid parameters are:
     * "first" - first name
     * "last" - last name
     * "email" - email
     * "username" - username
     * <p>
     * If possible, implementations should treat the parameter values as partial match patterns i.e. in RDMBS terms use LIKE.
     * <p>
     * This method is used by the REST API when querying users.
     *
     * @param params
     * @param realm
     * @return
     */
    @Override
    public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm) {
        return null;
    }

    /**
     * Search for user by parameter.    Valid parameters are:
     * "first" - first name
     * "last" - last name
     * "email" - email
     * "username" - username
     * <p>
     * If possible, implementations should treat the parameter values as patterns i.e. in RDMBS terms use LIKE.
     * This method is used by the REST API when querying users.
     *
     * @param params
     * @param realm
     * @param firstResult
     * @param maxResults
     * @return
     */
    @Override
    public List<UserModel> searchForUser(Map<String, String> params, RealmModel realm, int firstResult, int maxResults) {
        return null;
    }

    /**
     * Get users that belong to a specific group.  Implementations do not have to search in UserFederatedStorageProvider
     * as this is done automatically.
     *
     * @param realm
     * @param group
     * @param firstResult
     * @param maxResults
     * @return
     * @see UserFederatedStorageProvider
     */
    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group, int firstResult, int maxResults) {
        return null;
    }

    /**
     * Get users that belong to a specific role.
     *
     * @param realm
     * @param role
     * @return
     */
    @Override
    public List<UserModel> getRoleMembers(RealmModel realm, RoleModel role) {
        return null;
    }

    /**
     * Search for users that have a specific role with a specific roleId.
     *
     * @param realm
     * @param role
     * @param firstResult
     * @param maxResults
     * @return
     */
    @Override
    public List<UserModel> getRoleMembers(RealmModel realm, RoleModel role, int firstResult, int maxResults) {
        return null;
    }

    /**
     * Get users that belong to a specific group.  Implementations do not have to search in UserFederatedStorageProvider
     * as this is done automatically.
     *
     * @param realm
     * @param group
     * @return
     * @see UserFederatedStorageProvider
     */
    @Override
    public List<UserModel> getGroupMembers(RealmModel realm, GroupModel group) {
        return null;
    }

    /**
     * Search for users that have a specific attribute with a specific value.
     * Implementations do not have to search in UserFederatedStorageProvider
     * as this is done automatically.
     *
     * @param attrName
     * @param attrValue
     * @param realm
     * @return
     * @see UserFederatedStorageProvider
     */
    @Override
    public List<UserModel> searchForUserByUserAttribute(String attrName, String attrValue, RealmModel realm) {
        return null;
    }

    /**
     * Callback when a realm is removed.  Implement this if, for example, you want to do some
     * cleanup in your user storage when a realm is removed
     *
     * @param realm
     */
    @Override
    public void preRemove(RealmModel realm) {

    }

    /**
     * Callback when a group is removed.  Allows you to do things like remove a user
     * group mapping in your external store if appropriate
     *
     * @param realm
     * @param group
     */
    @Override
    public void preRemove(RealmModel realm, GroupModel group) {

    }

    /**
     * Callback when a role is removed.  Allows you to do things like remove a user
     * role mapping in your external store if appropriate
     *
     * @param realm
     * @param role
     */
    @Override
    public void preRemove(RealmModel realm, RoleModel role) {

    }
}
