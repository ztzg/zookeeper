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

import static org.junit.jupiter.api.Assertions.assertEquals;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.zookeeper.TestableZooKeeper;
import org.apache.zookeeper.WatchedEvent;
import org.apache.zookeeper.Watcher.Event.KeeperState;
import org.apache.zookeeper.server.AuthenticationHelper;
import org.apache.zookeeper.server.auth.IdCountAuthenticationLimiter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class MaxUserCnxnsSaslTest extends ClientBase {
    @BeforeAll
    public static void init() {
        System.setProperty("zookeeper.authProvider.1", "org.apache.zookeeper.server.auth.SASLAuthenticationProvider");

        try {
            File tmpDir = createTmpDir();
            File saslConfFile = new File(tmpDir, "jaas.conf");
            FileWriter fwriter = new FileWriter(saslConfFile);
            fwriter.write("" +
                          "Server {\n" +
                          "    org.apache.zookeeper.server.auth.DigestLoginModule required\n" +
                          "    user_super=\"test\";\n" +
                          "};\n" +
                          "Client {\n" +
                          "    org.apache.zookeeper.server.auth.DigestLoginModule required\n" +
                          "    username=\"super\"\n" +
                          "    password=\"test\";\n" +
                          "};\n");
            fwriter.close();
            System.setProperty("java.security.auth.login.config", saslConfFile.getAbsolutePath());
        } catch (IOException e) {
            // could not create tmp directory to hold JAAS conf file : test will
            // fail now.
        }
    }

    final private int numCnxns = 30;
    String host;
    int port;

    @BeforeEach
    @Override
    public void setUp() throws Exception {
        System.setProperty(AuthenticationHelper.AUTH_LIMITER, IdCountAuthenticationLimiter.class.getName());
        System.setProperty(IdCountAuthenticationLimiter.ZOOKEEPER_CNXN_LIMIT_PER_USER, String.valueOf(numCnxns));

        super.setUp();
    }

    @AfterEach
    @Override
    public void tearDown() throws Exception {
        super.tearDown();

        System.clearProperty(IdCountAuthenticationLimiter.ZOOKEEPER_CNXN_LIMIT_PER_USER);
        System.clearProperty(AuthenticationHelper.AUTH_LIMITER);
        System.clearProperty("zookeeper.authProvider.1");
    }

    private class MyWatcher extends CountdownWatcher {
        @Override
        public synchronized void process(WatchedEvent event) {
            if (event.getState() == KeeperState.SaslAuthenticated) {
                connected = true;
                notifyAll();
                clientConnected.countDown();
            } else if (event.getState() == KeeperState.SyncConnected ||
                       event.getState() == KeeperState.ConnectedReadOnly) {
            } else {
                connected = false;
                notifyAll();
            }
        }
    }

    class UserCnxnThread extends Thread {
        int i;
        AtomicInteger numConnected;
        CountDownLatch closeSignal = new CountDownLatch(1);
        CountDownLatch doneSignal = new CountDownLatch(1);

        public UserCnxnThread(int i, AtomicInteger numConnected) {
            super("UserCnxnThread-"+i);
            this.i = i;
            this.numConnected = numConnected;
        }

        public void run() {
            MyWatcher watcher = new MyWatcher();
            TestableZooKeeper zk;
            try {
                zk = new TestableZooKeeper(hostPort, 1000, watcher);
                System.out.println("start"+i);
                if (watcher.clientConnected.await(1000, TimeUnit.MILLISECONDS)) {
                    numConnected.incrementAndGet();
                }
                System.out.println(i);
                doneSignal.countDown();
                closeSignal.await();
                zk.close();
            } catch (Throwable t) {
                LOG.error("Client failed", t);
            }
        }
    }

    /**
     * Verify the ability to limit the number of concurrent connections by user.
     * @throws IOException
     * @throws InterruptedException
     */
    @Test
    public void testMaxUserCnxns_sasl() throws IOException, InterruptedException{
        AtomicInteger numConnected = new AtomicInteger(0);

        int numThreads = numCnxns + 5;
        UserCnxnThread[] threads = new UserCnxnThread[numThreads];

        for (int i=0;i<numThreads;++i) {
          threads[i] = new UserCnxnThread(i, numConnected);
        }

        // Connect the max conns
        for (int i=0;i<numCnxns;++i) {
            threads[i].start();
        }

        for (int i=0;i<numCnxns;++i) {
                threads[i].doneSignal.await();
        }

        System.out.println("assert");
        assertEquals(numCnxns,numConnected.get());

        // Try to connect 5 more
        for (int i=numCnxns;i<numThreads;++i) {
            threads[i] = new UserCnxnThread(i, numConnected);
        }

        for (int i=numCnxns;i<numThreads;++i) {
            threads[i].start();
        }

        for (int i=numCnxns;i<numThreads;++i) {
                threads[i].doneSignal.await();
        }

        assertEquals(numCnxns,numConnected.get());
    }
}
