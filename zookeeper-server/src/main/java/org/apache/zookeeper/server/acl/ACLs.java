/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.zookeeper.server.acl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.data.ACL;
import org.apache.zookeeper.data.Id;
import org.apache.zookeeper.server.auth.ProviderRegistry;
import org.apache.zookeeper.server.auth.ServerAuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class holds constants and utilities for the management of ACLs
 * and ACL constraints.
 */
public class ACLs {
    private static final Logger LOG = LoggerFactory.getLogger(ACLs.class);

    /**
     * This method checks out the acl making sure it isn't null or empty,
     * it has valid schemes and ids, and expanding any relative ids that
     * depend on the requester's authentication information.
     *
     * @param authInfo list of ACL IDs associated with the client connection
     * @param acls list of ACLs being assigned to the node (create or setACL operation)
     * @return verified and expanded ACLs
     * @throws KeeperException.InvalidACLException
     */
    public static List<ACL> fixupACL(String path, List<Id> authInfo, List<ACL> acls) throws KeeperException.InvalidACLException {
        FixupContext context = new FixupContext() {
                public String getPath() {
                    return path;
                }

                public List<Id> getAuthInfo() {
                    return authInfo;
                }
            };

        return fixupACL(context, acls);
    }

    public static List<ACL> fixupACL(FixupContext context, List<ACL> acls)
        throws KeeperException.InvalidACLException {
        String path = context.getPath();
        // check for well formed ACLs
        // This resolves https://issues.apache.org/jira/browse/ZOOKEEPER-1877
        List<ACL> uniqacls = removeDuplicates(acls);
        if (uniqacls == null || uniqacls.size() == 0) {
            throw new KeeperException.InvalidACLException(path);
        }
        List<ACL> rv = new ArrayList<>();
        for (ACL a : uniqacls) {
            LOG.debug("Processing ACL: {}", a);
            if (a == null) {
                throw new KeeperException.InvalidACLException(path);
            }
            Id id = a.getId();
            if (id == null || id.getScheme() == null) {
                throw new KeeperException.InvalidACLException(path);
            }
            if (id.getScheme().equals("world") && id.getId().equals("anyone")) {
                rv.add(a);
            } else if (id.getScheme().equals("auth")) {
                // This is the "auth" id, so we have to expand it to the
                // authenticated ids of the requester
                boolean authIdValid = false;
                for (Id cid : context.getAuthInfo()) {
                    ServerAuthenticationProvider ap = ProviderRegistry.getServerProvider(cid.getScheme());
                    if (ap == null) {
                        LOG.error("Missing AuthenticationProvider for {}", cid.getScheme());
                    } else if (ap.isAuthenticated()) {
                        authIdValid = true;
                        rv.add(new ACL(a.getPerms(), cid));
                    }
                }
                if (!authIdValid) {
                    throw new KeeperException.InvalidACLException(path);
                }
            } else {
                ServerAuthenticationProvider ap = ProviderRegistry.getServerProvider(id.getScheme());
                if (ap == null || !ap.isValid(id.getId())) {
                    throw new KeeperException.InvalidACLException(path);
                }
                rv.add(a);
            }
        }
        return rv;
    }

    private static List<ACL> removeDuplicates(final List<ACL> acls) {
        if (acls == null || acls.isEmpty()) {
            return Collections.emptyList();
        }

        // This would be done better with a Set but ACL hashcode/equals do not
        // allow for null values
        final ArrayList<ACL> retval = new ArrayList<>(acls.size());
        for (final ACL acl : acls) {
            if (!retval.contains(acl)) {
                retval.add(acl);
            }
        }
        return retval;
    }
}
