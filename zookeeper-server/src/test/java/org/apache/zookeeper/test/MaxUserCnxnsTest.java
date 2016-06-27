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
import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.zookeeper.TestableZooKeeper;
import org.apache.zookeeper.server.AuthenticationHelper;
import org.apache.zookeeper.server.auth.IdCountAuthenticationLimiter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class MaxUserCnxnsTest extends ClientBase {
    final private int numCnxns = 30;

    @BeforeEach
    @Override
    public void setUp() throws Exception {
        System.setProperty(AuthenticationHelper.AUTH_LIMITER, IdCountAuthenticationLimiter.class.getName());
        System.setProperty(IdCountAuthenticationLimiter.ZOOKEEPER_CNXN_LIMIT_PER_USERIP, String.valueOf(numCnxns));

        super.setUp();
    }

    @AfterEach
    @Override
    public void tearDown() throws Exception {
        super.tearDown();

        System.clearProperty(IdCountAuthenticationLimiter.ZOOKEEPER_CNXN_LIMIT_PER_USERIP);
        System.clearProperty(AuthenticationHelper.AUTH_LIMITER);
    }

    class UserCnxnThread extends Thread {
        int i;
        String user;
        AtomicInteger numConnected;
        CountDownLatch closeSignal = new CountDownLatch(1);
        CountDownLatch doneSignal = new CountDownLatch(1);

        public UserCnxnThread(int i, String user, AtomicInteger numConnected) {
            super("UserCnxnThread-"+i);
            this.i = i;
            this.user = user;
            this.numConnected = numConnected;
        }

        public void run() {
            TestableZooKeeper zk;
            try {
                CountdownWatcher watcher = new CountdownWatcher();
                zk = createClient(watcher);
                zk.addAuthInfo("digest", this.user.getBytes());
                try {
                    watcher.waitForDisconnected(1000);
                } catch (TimeoutException e) {
                    numConnected.incrementAndGet();
                }
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
    public void testMaxUserCnxns() throws IOException, InterruptedException{
        AtomicInteger numConnected_foo = new AtomicInteger(0);
        AtomicInteger numConnected_bar = new AtomicInteger(0);

        int numThreads = numCnxns + 5;
        UserCnxnThread[] foo_threads = new UserCnxnThread[numThreads];
        UserCnxnThread[] bar_threads = new UserCnxnThread[numThreads];

        for (int i=0;i<numThreads;++i) {
            foo_threads[i] = new UserCnxnThread(i, "foo", numConnected_foo);
            bar_threads[i] = new UserCnxnThread(i, "bar", numConnected_bar);
        }

        // Connect the max conns for 2 different users
        for (int i=0;i<numCnxns;++i) {
            foo_threads[i].start();
            bar_threads[i].start();
        }

        for (int i=0;i<numCnxns;++i) {
            foo_threads[i].doneSignal.await();
            bar_threads[i].doneSignal.await();
        }
        assertEquals(numCnxns, numConnected_foo.get());
        assertEquals(numCnxns, numConnected_bar.get());

        // Try to connect 5 more
        for (int i=numCnxns;i<numThreads;++i) {
            foo_threads[i].start();
            bar_threads[i].start();
        }

        for (int i=numCnxns;i<numThreads;++i) {
            foo_threads[i].doneSignal.await();
            bar_threads[i].doneSignal.await();
        }
        assertEquals(numCnxns, numConnected_foo.get());
        assertEquals(numCnxns, numConnected_bar.get());

        // Close the 5 unconnected plus 5 others
        for (int i=numCnxns-5;i<numThreads;++i) {
            foo_threads[i].closeSignal.countDown();
            bar_threads[i].closeSignal.countDown();
        }

        for (int i=numCnxns-5;i<numThreads;++i) {
            foo_threads[i].join();
            bar_threads[i].join();
        }

        // Try to reconnect them
        numConnected_foo.set(0);
        numConnected_bar.set(0);

        for (int i=numCnxns-5;i<numThreads;++i) {
            foo_threads[i] = new UserCnxnThread(i, "foo", numConnected_foo);
            bar_threads[i] = new UserCnxnThread(i, "bar", numConnected_bar);
        }

        for (int i=numCnxns-5;i<numThreads;++i) {
            foo_threads[i].start();
            bar_threads[i].start();
        }

        for (int i=numCnxns-5;i<numThreads;++i) {
            foo_threads[i].doneSignal.await();
            bar_threads[i].doneSignal.await();
        }
        assertEquals(5, numConnected_foo.get());
        assertEquals(5, numConnected_bar.get());
    }
}
