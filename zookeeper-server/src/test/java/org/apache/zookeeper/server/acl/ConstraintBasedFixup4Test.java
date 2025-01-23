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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.ZooDefs;
import org.apache.zookeeper.cli.AclParser;
import org.apache.zookeeper.data.ACL;
import org.apache.zookeeper.data.Id;
import org.apache.zookeeper.server.acl.ConstraintBasedFixup4.Flag;
import org.apache.zookeeper.server.auth.ProviderRegistry;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class ConstraintBasedFixup4Test {
    private static final ConstraintBasedFixup4 INSTANCE = new ConstraintBasedFixup4();

    @BeforeAll
    public static void init() {
        System.setProperty("zookeeper.authProvider.1", "org.apache.zookeeper.server.auth.SASLAuthenticationProvider");
        ProviderRegistry.initialize();
    }

    @AfterAll
    public static void deinit() {
        ProviderRegistry.reset();
        System.clearProperty("zookeeper.authProvider.1");
    }

    private FixupContext mkContext(String path, List<Id> authInfo) {
        List<Id> ids = new ArrayList<>();

        if (authInfo != null) {
            ids.addAll(authInfo);
        }

        return new FixupContext() {
            public String getPath() {
                return path;
            }

            public long getSessionId() {
                return -1;
            }

            public List<Id> getAuthInfo() {
                return ids;
            }

            public byte[] loadConstraints() {
                return null;
            }
        };
    }

    private FixupContext mkContext(String path, String... colSepIdArgs)
        throws ParseException {
        return mkContext(path, mkIds(colSepIdArgs));
    }

    private EnumSet<Flag> mkFlags(Flag... flagArgs) {
        EnumSet<Flag> flags = EnumSet.noneOf(Flag.class);

        for (Flag flag : flagArgs) {
            flags.add(flag);
        }

        return flags;
    }

    private List<Id> mkIds(String... colSepIdArgs)
        throws ParseException {
        if (colSepIdArgs.length == 0) {
            return null;
        }

        List<Id> targetIds = new ArrayList<>();

        for (String colSepId : colSepIdArgs) {
            targetIds.add(INSTANCE.extractId(colSepId, 0));
        }

        return targetIds;
    }

    private List<ACL> mkAcl(String... aclArgs) {
        List<ACL> acl = new ArrayList<>();

        for (String encodedAcl : aclArgs) {
            List<ACL> elements = AclParser.parse(encodedAcl);
            acl.addAll(elements);
        }

        return acl;
    }

    private List<Id> checkDecode(String constraints,
                                 EnumSet<Flag> expectedFlags,
                                 List<Id> expectedTargetIds)
        throws ParseException {
        EnumSet<Flag> flags = EnumSet.noneOf(Flag.class);

        byte[] bytes = constraints.getBytes(StandardCharsets.UTF_8);
        List<Id> targetIds = INSTANCE.decodeFlags(bytes, flags);

        assertEquals(expectedFlags, flags);
        assertEquals(expectedTargetIds, targetIds);

        return targetIds;
    }

    @Test
    public void testDecodeEmpty() throws ParseException {
        checkDecode("4,", mkFlags(), mkIds());
    }

    @Test
    public void testDecodeMany() throws ParseException {
        checkDecode("4,REJECT_UNSAFE,MASK_UNSAFE,UNSAFE_TO_AUTH,ENSURE_AUTH_ADMIN,ENSURE_WORLD_READ,NO_KEEP_WORLD_READ",
                    mkFlags(Flag.REJECT_UNSAFE,
                            Flag.MASK_UNSAFE,
                            Flag.UNSAFE_TO_AUTH,
                            Flag.ENSURE_AUTH_ADMIN,
                            Flag.ENSURE_WORLD_READ,
                            Flag.NO_KEEP_WORLD_READ),
                    mkIds());
    }

    @Test
    public void testDecodeBadEmptyUnsafeTo() throws ParseException {
        EnumSet<Flag> flags = mkFlags(Flag.UNSAFE_TO,
                                      Flag.ENSURE_AUTH_ADMIN,
                                      Flag.ENSURE_WORLD_READ);
        List<Id> targetIds =
            checkDecode("4,ENSURE_AUTH_ADMIN,UNSAFE_TO,ENSURE_WORLD_READ",
                        flags,
                        mkIds());

        assertThrows(KeeperException.InvalidACLException.class, () -> {
                INSTANCE.validateFlags(mkContext("/foo"), flags, targetIds);
            });
    }

    @Test
    public void testDecodeBadUnsafeToScheme() throws ParseException {
        EnumSet<Flag> flags = mkFlags(Flag.UNSAFE_TO);
        List<Id> targetIds =
            checkDecode("4,UNSAFE_TO:yolo:blah",
                        flags,
                        mkIds("yolo:blah"));

        assertThrows(KeeperException.InvalidACLException.class, () -> {
                INSTANCE.validateFlags(mkContext("/foo"), flags, targetIds);
            });
    }

    private List<ACL> doApply(String constraints,
                              FixupContext context,
                              List<ACL> inputAcl)
        throws ParseException, KeeperException.InvalidACLException {
        byte[] data = constraints.getBytes(StandardCharsets.UTF_8);

        return INSTANCE.applyEncodedConstraints(context, inputAcl, data);
    }

    private void checkApply(String constraints,
                            FixupContext context,
                            List<ACL> inputAcl,
                            List<ACL> expectedAcl)
        throws ParseException, KeeperException.InvalidACLException {
        List<ACL> outputAcl = doApply(constraints, context, inputAcl);

        assertEquals(expectedAcl, outputAcl);
    }

    private void checkApply(String constraints,
                            FixupContext context,
                            List<ACL> inputAcl,
                            Set<ACL> expectedAclSet)
        throws ParseException, KeeperException.InvalidACLException {
        List<ACL> outputAcl = doApply(constraints, context, inputAcl);
        Set<ACL> outputAclSet = new HashSet<>(outputAcl);

        assertEquals(expectedAclSet, outputAclSet);
    }

    @Test
    public void testApplyEmpty()
        throws ParseException, KeeperException.InvalidACLException {
        checkApply("4,", mkContext("/foo"),
                   ZooDefs.Ids.OPEN_ACL_UNSAFE,
                   ZooDefs.Ids.READ_ACL_UNSAFE);
    }

    @Test
    public void testApplyEmpty2()
        throws ParseException, KeeperException.InvalidACLException {
        checkApply("4,", mkContext("/foo"),
                   ZooDefs.Ids.READ_ACL_UNSAFE,
                   ZooDefs.Ids.READ_ACL_UNSAFE);
    }

    @Test
    public void testApplyMask()
        throws ParseException, KeeperException.InvalidACLException {
        checkApply("4,MASK_UNSAFE", mkContext("/foo"),
                   ZooDefs.Ids.OPEN_ACL_UNSAFE,
                   ZooDefs.Ids.READ_ACL_UNSAFE);
    }

    @Test
    public void testApplyNoKeepWorldRead()
        throws ParseException, KeeperException.InvalidACLException {
        checkApply("4,NO_KEEP_WORLD_READ", mkContext("/foo"),
                   ZooDefs.Ids.OPEN_ACL_UNSAFE,
                   Collections.emptyList());
    }

    @Test
    public void testApplyUnsafeToId()
        throws ParseException, KeeperException.InvalidACLException {
        checkApply("4,UNSAFE_TO:sasl:foo", mkContext("/foo"),
                   ZooDefs.Ids.OPEN_ACL_UNSAFE,
                   mkAcl("sasl:foo:cdrwa", "world:anyone:r"));
    }

    @Test
    public void testApplyUnsafeToIdPure()
        throws ParseException, KeeperException.InvalidACLException {
        checkApply("4,UNSAFE_TO:sasl:foo,NO_KEEP_WORLD_READ", mkContext("/foo"),
                   ZooDefs.Ids.OPEN_ACL_UNSAFE,
                   mkAcl("sasl:foo:cdrwa"));
    }

    @Test
    public void testApplyUnsafeToIdTwice()
        throws ParseException, KeeperException.InvalidACLException {
        checkApply("4,UNSAFE_TO:sasl:foo,UNSAFE_TO:sasl:bar", mkContext("/foo"),
                   ZooDefs.Ids.OPEN_ACL_UNSAFE,
                   mkAcl("sasl:foo:cdrwa", "sasl:bar:cdrwa", "world:anyone:r"));
    }

    @Test
    public void testApplyUnsafeToAuth()
        throws ParseException, KeeperException.InvalidACLException {
        checkApply("4,UNSAFE_TO_AUTH",
                   mkContext("/foo", "sasl:foo", "sasl:bar"),
                   ZooDefs.Ids.OPEN_ACL_UNSAFE,
                   mkAcl("sasl:foo:cdrwa", "sasl:bar:cdrwa", "world:anyone:r"));
    }

    @Test
    public void testApplyUnsafeToAuthPure()
        throws ParseException, KeeperException.InvalidACLException {
        checkApply("4,UNSAFE_TO_AUTH,NO_KEEP_WORLD_READ",
                   mkContext("/foo", "sasl:foo", "sasl:bar"),
                   ZooDefs.Ids.OPEN_ACL_UNSAFE,
                   mkAcl("sasl:foo:cdrwa", "sasl:bar:cdrwa"));
    }

    @Test
    public void testApplyEnsureAuthAdmin()
        throws ParseException, KeeperException.InvalidACLException {
        checkApply("4,ENSURE_AUTH_ADMIN",
                   mkContext("/foo", "sasl:foo", "sasl:bar"),
                   ZooDefs.Ids.OPEN_ACL_UNSAFE,
                   mkAcl("world:anyone:r", "sasl:foo:a", "sasl:bar:a"));
    }

    @Test
    public void testApplyEnsureAuthAdminPure()
        throws ParseException, KeeperException.InvalidACLException {
        checkApply("4,ENSURE_AUTH_ADMIN,NO_KEEP_WORLD_READ",
                   mkContext("/foo", "sasl:foo", "sasl:bar"),
                   ZooDefs.Ids.OPEN_ACL_UNSAFE,
                   mkAcl("sasl:foo:a", "sasl:bar:a"));
    }

    @Test
    public void testApplyEnsureWorldRead()
        throws ParseException, KeeperException.InvalidACLException {
        checkApply("4,ENSURE_WORLD_READ",
                   mkContext("/foo", "sasl:foo", "sasl:bar"),
                   mkAcl("sasl:foo:cdrwa"),
                   mkAcl("sasl:foo:cdrwa", "world:anyone:r"));
    }
}
