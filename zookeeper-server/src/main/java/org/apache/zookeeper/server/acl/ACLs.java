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
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.data.ACL;
import org.apache.zookeeper.data.Id;
import org.apache.zookeeper.server.ZooKeeperServer;
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

    public static final String FIXUP_PROPERTY_PREFIX = "zookeeper.aclFixup.";

    /** the zookeeper acl node that acts as the acl
     * management node for zookeeper */
    public static final String ZOOKEEPER_ACL_PATH = "/zookeeper/acl";

    /**
     * The ACL constraints node.
     */
    public static final String ZOOKEEPER_ACL_CONSTRAINTS_NAME = "zookeeper_constraints";

    /**
     * return the real path associated with this
     * aclPath.
     * @param aclPath the aclPath which's started with /zookeeper/acl
     * @return the real path associated with this aclPath.
     */
    public static String trimConstraintsPath(String aclPath) {
        return aclPath.substring(ZOOKEEPER_ACL_PATH.length());
    }

    private static final List<Fixup> fixups = new ArrayList<>();

    public static class InitializationException extends Exception {
        public InitializationException(String msg, Exception e) {
            super(msg, e);
        }
    }

    public static void initialize() throws InitializationException {
        Map<String, String> defs = new TreeMap<>();

        Enumeration<Object> e = System.getProperties().keys();
        while (e.hasMoreElements()) {
            String key = (String) e.nextElement();
            if (key.startsWith(FIXUP_PROPERTY_PREFIX)) {
                defs.put(key, System.getProperty(key));
            }
        }

        List<Fixup> tmp = new ArrayList<>(Math.max(defs.size(), 1));
        // Loaded in "natural" key order.
        for (Map.Entry<String, String> def : defs.entrySet()) {
            String k = def.getKey();
            String v = def.getValue();
            try {
                Class<?> c = ZooKeeperServer.class.getClassLoader().loadClass(v);
                Fixup fixup = (Fixup) c.getDeclaredConstructor().newInstance();
                LOG.info("Using ACL fixup {} -> {}", k, fixup.getClass());
                tmp.add(fixup);
            } catch (Exception x) {
                LOG.error("Failed to load ACL fixup {} -> {}", k, v, x);
                throw new InitializationException(
                    "Failed to load ACL fixup " + k + " -> " + v, x);
            }
        }

        if (tmp.isEmpty()) {
            LOG.info("Using builtin ACL fixup procedure");
            tmp.add(ACLs::builtinFixup);
        }

        synchronized (ACLs.class) {
            fixups.clear();
            fixups.addAll(tmp);
        }
    }

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

        for (Fixup fixup : fixups) {
            LOG.debug("Applying ACL fixup {}", fixup);
            acls = fixup.apply(context, acls);
        }

        return acls;
    }

    public static List<ACL> builtinFixup(FixupContext context, List<ACL> acls)
        throws KeeperException.InvalidACLException {
        acls = requireNotEmpty(context, acls);
        acls = removeDuplicates(context, acls);
        return expandAndValidateSchemes(context, acls);
    }

    public static List<ACL> requireNotEmpty(FixupContext context, List<ACL> acls)
        throws KeeperException.InvalidACLException {
        if (acls == null || acls.isEmpty()) {
            throw new KeeperException.InvalidACLException(context.getPath());
        }
        return acls;
    }

    public static List<ACL> removeDuplicates(FixupContext context, List<ACL> acls) {
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

    public static List<ACL> expandAndValidateSchemes(FixupContext context, List<ACL> uniqacls)
        throws KeeperException.InvalidACLException {
        String path = context.getPath();
        // check for well formed ACLs
        // This resolves https://issues.apache.org/jira/browse/ZOOKEEPER-1877
        List<ACL> rv = new ArrayList<>();
        for (ACL a : uniqacls) {
            LOG.debug("Processing ACL: {}", a);
            Id id = requireSaneId(path, a);
            if (id.getScheme().equals("world") && id.getId().equals("anyone")) {
                rv.add(a);
            } else if (id.getScheme().equals("auth")) {
                // This is the "auth" id, so we have to expand it to the
                // authenticated ids of the requester
                expandAuth(path, context.getAuthInfo(), a.getPerms(), rv);
            } else {
                validateId(path, id);
                rv.add(a);
            }
        }
        return rv;
    }

    public static Id requireSaneId(String path, ACL aclElement) throws KeeperException.InvalidACLException {
        if (aclElement == null) {
            LOG.debug("Null ACL element");
            throw new KeeperException.InvalidACLException(path);
        }

        Id id = aclElement.getId();
        // Note: aclElement.getId().getId() is not checked for
        // backwards compatibility!
        if (id == null || id.getScheme() == null) {
            LOG.debug("ACL element with Id {}", id);
            throw new KeeperException.InvalidACLException(path);
        }

        return id;
    }

    public static void validateId(String path, Id id) throws KeeperException.InvalidACLException {
        if (id == null || id.getScheme() == null) {
            LOG.debug("Incomplete Id {}", id);
            throw new KeeperException.InvalidACLException(path);
        }

        ServerAuthenticationProvider ap = ProviderRegistry.getServerProvider(id.getScheme());
        if (ap == null || !ap.isValid(id.getId())) {
            LOG.debug("Invalid Id {}", id);
            throw new KeeperException.InvalidACLException(path);
        }
    }

    public static void expandAuth(String path, List<Id> authInfo, int perms, Collection<ACL> collector) throws KeeperException.InvalidACLException {
        boolean authIdValid = false;
        for (Id cid : authInfo) {
            ServerAuthenticationProvider ap = ProviderRegistry.getServerProvider(cid.getScheme());
            if (ap == null) {
                LOG.error("Missing AuthenticationProvider for {}", cid.getScheme());
            } else if (ap.isAuthenticated()) {
                authIdValid = true;
                collector.add(new ACL(perms, cid));
            }
        }
        if (!authIdValid) {
            throw new KeeperException.InvalidACLException(path);
        }
    }
}
