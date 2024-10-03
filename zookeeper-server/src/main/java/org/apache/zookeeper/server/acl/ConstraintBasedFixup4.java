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

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.ZooDefs;
import org.apache.zookeeper.data.ACL;
import org.apache.zookeeper.data.Id;
import org.apache.zookeeper.server.auth.ProviderRegistry;
import org.apache.zookeeper.server.auth.ServerAuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConstraintBasedFixup4 implements Fixup {
    private static final Logger LOG = LoggerFactory.getLogger(ConstraintBasedFixup4.class);

    public List<ACL> apply(FixupContext context, List<ACL> acl)
        throws KeeperException.InvalidACLException {
        for (Id authId : context.getAuthInfo()) {
            if (authId.getScheme().equals("super")) {
                return acl;
            }
        }

        byte[] data = context.loadConstraints();
        if (data != null) {
            try {
                acl = applyEncodedConstraints(context, acl, data);
            } catch (KeeperException.InvalidACLException e) {
                throw e;
            } catch (Exception e) {
                String path = context.getPath();
                LOG.error("Error processing ACL constraints {} for node {}",
                          new String(data, StandardCharsets.UTF_8), path, e);
                throw new KeeperException.InvalidACLException(path);
            }
        }

        return acl;
    }

    protected enum Flag {
        REJECT_UNSAFE,
        MASK_UNSAFE,
        UNSAFE_TO_AUTH,
        ENSURE_AUTH_ADMIN,
        UNSAFE_TO,
    }

    protected static final String UNSAFE_TO_PREFIX = Flag.UNSAFE_TO + ":";

    protected List<ACL> applyEncodedConstraints(FixupContext context, List<ACL> acl, byte[] data)
        throws ParseException, KeeperException.InvalidACLException {
        // Start with ASCII "4,"
        if (data.length < 2 || data[0] != '4' || data[1] != ',') {
            throw new ParseException("Unsupported constraint encoding", 0);
        }

        // Load comma-separated enum values.
        EnumSet<Flag> flags = EnumSet.noneOf(Flag.class);
        Id targetId = null;

        int lastIndex = 1;
        for (int i = 2; i <= data.length; i++) {
            if (i == data.length || data[i] == ',') {
                String s = new String(data, lastIndex + 1, i - 1 - lastIndex,
                                      StandardCharsets.US_ASCII);
                if (s.startsWith(UNSAFE_TO_PREFIX)) {
                    if (targetId != null) {
                        LOG.warn("Already seen {} {} in ACL constraint; "
                                 + "ignoring {}", Flag.UNSAFE_TO, targetId, s);
                    } else {
                        targetId = extractId(s, UNSAFE_TO_PREFIX.length());
                        flags.add(Flag.UNSAFE_TO);
                    }
                } else if (s.length() > 0) {
                    flags.add(Flag.valueOf(s));
                }
                lastIndex = i;
            }
        }

        if (flags.contains(Flag.UNSAFE_TO)) {
            ACLs.validateId(context.getPath(), targetId);
        }

        return applyFlags(context, acl, flags, targetId);
    }

    protected Id extractId(String s, int at) throws ParseException {
        int sep = s.indexOf(':', at);
        if (sep < 0 || sep == s.length()) {
            throw new ParseException("Expected an ID of the form 'scheme:id'; "
                                     + "got '" + s.substring(at) + "'", 0);
        }
        return new Id(s.substring(at, sep), s.substring(sep + 1));
    }

    protected static final int MODIFY = ZooDefs.Perms.ALL & ~ZooDefs.Perms.READ;

    protected List<ACL> applyFlags(FixupContext context, List<ACL> acl, EnumSet<Flag> flags, Id targetId)
        throws KeeperException.InvalidACLException {
        String path = context.getPath();
        List<Id> authInfo = context.getAuthInfo();
        boolean hasAdmin = false;
        List<ACL> newAcl = new ArrayList<>(acl.size());

        for (ACL aclElement : acl) {
            Id id = ACLs.requireSaneId(path, aclElement);
            String scheme = id.getScheme();
            String idid = id.getId();
            int perms = aclElement.getPerms();
            boolean permsHasAdmin = (perms & ZooDefs.Perms.ADMIN) != 0;
            if ("world".equals(scheme) && "anyone".equals(idid)) {
                if ((perms & MODIFY) == 0) {
                    // We accept world READ-only.
                    newAcl.add(aclElement);
                } else {
                    if (flags.contains(Flag.REJECT_UNSAFE)) {
                        throw new KeeperException.InvalidACLException(path);
                    } else if (flags.contains(Flag.UNSAFE_TO)) {
                        newAcl.add(new ACL(perms, targetId));
                        if (permsHasAdmin) {
                            // Kind-of assumes that the target ID is
                            // part of "auth::"!
                            hasAdmin = true;
                        }
                    } else if (flags.contains(Flag.UNSAFE_TO_AUTH)) {
                        ACLs.expandAuth(path, authInfo, perms, newAcl);
                        if (permsHasAdmin) {
                            hasAdmin = true;
                        }
                    } else if (flags.contains(Flag.MASK_UNSAFE)) {
                        int newPerms = perms & ~MODIFY;
                        if (newPerms != 0) {
                            newAcl.add(new ACL(newPerms, id));
                        }
                    }
                }
            } else {
                if (!hasAdmin
                    && permsHasAdmin
                    && flags.contains(Flag.ENSURE_AUTH_ADMIN)) {
                    for (Id cid : authInfo) {
                        if (scheme.equals(cid.getScheme())
                            && idid.equals(cid.getId())) {
                            ServerAuthenticationProvider ap = ProviderRegistry.getServerProvider(scheme);
                            if (ap != null && ap.isAuthenticated()) {
                                hasAdmin = true;
                            }
                        }
                    }
                }
                newAcl.add(aclElement);
            }
        }

        if (!hasAdmin && flags.contains(Flag.ENSURE_AUTH_ADMIN)) {
            ACLs.expandAuth(path, authInfo, ZooDefs.Perms.ADMIN, newAcl);
        }

        return newAcl;
    }
}
