/**
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

package org.apache.zookeeper.test;

import java.io.IOException;

import org.apache.zookeeper.CreateMode;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.Quotas;
import org.apache.zookeeper.StatsTrack;
import org.apache.zookeeper.ZooKeeper;
import org.apache.zookeeper.ZooKeeperMain;
import org.apache.zookeeper.ZooDefs.Ids;
import org.apache.zookeeper.data.Stat;
import org.apache.zookeeper.KeeperException.QuotaExceededException;
import org.apache.zookeeper.server.ZooKeeperServer;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class ZooKeeperQuotaEnforceTest extends ClientBase {

    @Override
    public void setUp() throws Exception {
        System.setProperty("zookeeper.enforceQuotaLimit", "yes");
        super.setUp();
    }    

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testSetQuotaException() throws IOException,
        InterruptedException, KeeperException, Exception {
        thrown.expect(QuotaExceededException.class);
        thrown.expectMessage("QuotaExceeded for /test/quota");

        final ZooKeeper zk = createClient();
        final String path = "/test/quota";
        zk.create("/test", null, Ids.OPEN_ACL_UNSAFE, CreateMode.PERSISTENT);
        zk.create("/test/quota", "data".getBytes(), Ids.OPEN_ACL_UNSAFE,
                CreateMode.PERSISTENT);
        ZooKeeperMain.createQuota(zk, path, 5L, 10);
        zk.setData("/test/quota", "newdata".getBytes(), -1);
    }

    @Test
    public void testSetQuotaExceptionAlreadyAbove() throws IOException,
        InterruptedException, KeeperException, Exception {
        thrown.expect(QuotaExceededException.class);
        thrown.expectMessage("QuotaExceeded for /test/quota/data");

        final ZooKeeper zk = createClient();
        final String path = "/test/quota";
        zk.create("/test", null, Ids.OPEN_ACL_UNSAFE, CreateMode.PERSISTENT);
        zk.create("/test/quota", "data".getBytes(), Ids.OPEN_ACL_UNSAFE,
                CreateMode.PERSISTENT);
        zk.create("/test/quota/data", "data".getBytes(), Ids.OPEN_ACL_UNSAFE,
                CreateMode.PERSISTENT);
        ZooKeeperMain.createQuota(zk, path, 5L, 10);
        zk.setData("/test/quota/data", "newdata".getBytes(), -1);
    }

    @Test
    public void testCreateQuotaException() throws IOException,
        InterruptedException, KeeperException, Exception {
        thrown.expect(QuotaExceededException.class);
        thrown.expectMessage("QuotaExceeded for /test/quota/data");

        final ZooKeeper zk = createClient();
        final String path = "/test/quota";
        zk.create("/test", null, Ids.OPEN_ACL_UNSAFE, CreateMode.PERSISTENT);
        zk.create("/test/quota", "data".getBytes(), Ids.OPEN_ACL_UNSAFE,
                CreateMode.PERSISTENT);
        ZooKeeperMain.createQuota(zk, path, 5L, 10);
        zk.create("/test/quota/data", "data".getBytes(), Ids.OPEN_ACL_UNSAFE,
                CreateMode.PERSISTENT);
    }

    @Test
    public void testCreateQuotaCountException() throws IOException,
        InterruptedException, KeeperException, Exception {
        thrown.expect(QuotaExceededException.class);
        thrown.expectMessage("QuotaExceeded for /test/quota/data");

        final ZooKeeper zk = createClient();
        final String path = "/test/quota";
        zk.create("/test", null, Ids.OPEN_ACL_UNSAFE, CreateMode.PERSISTENT);
        zk.create("/test/quota", "data".getBytes(), Ids.OPEN_ACL_UNSAFE,
                CreateMode.PERSISTENT);
        ZooKeeperMain.createQuota(zk, path, 100L, 1);
        zk.create("/test/quota/data", "data".getBytes(), Ids.OPEN_ACL_UNSAFE,
                CreateMode.PERSISTENT);
    }

}
