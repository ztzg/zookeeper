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

package org.apache.zookeeper.server.auth;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.data.Id;
import org.apache.zookeeper.server.ServerCnxn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IdCountAuthenticationLimiter implements AuthenticationLimiter {
    private static class IdAndIp {
        private final InetAddress inetAddress;

        private final Id id;

        public IdAndIp(InetAddress inetAddress, Id id) {
            this.inetAddress = inetAddress;
            this.id = id;
        }

        public InetAddress getInetAddress() {
            return inetAddress;
        }

        public Id getId() {
            return id;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + ((inetAddress == null) ? 0 : inetAddress.hashCode());
            result = prime * result + ((id == null) ? 0 : id.hashCode());
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj)
                return true;
            if (obj == null)
                return false;
            if (getClass() != obj.getClass())
                return false;
            IdAndIp other = (IdAndIp) obj;
            if (inetAddress == null) {
                if (other.inetAddress != null)
                    return false;
            } else if (!inetAddress.equals(other.inetAddress))
                return false;
            if (id == null) {
                if (other.id != null)
                    return false;
            } else if (!id.equals(other.id))
                return false;
            return true;
        }

        @Override
        public String toString() {
            return "[inetAddress=" + inetAddress + ", id=" + id + "]";
        }
    }

    private static final Logger LOG = LoggerFactory.getLogger(IdCountAuthenticationLimiter.class);

    public static final String ZOOKEEPER_CNXN_LIMIT_PER_USER = "zookeeper.maxClientCnxnsPerUser";
    public static final String ZOOKEEPER_CNXN_LIMIT_PER_USERIP = "zookeeper.maxClientCnxnsPerUserIp";

    private final int maxClientCnxnsPerUser;
    private final int maxClientCnxnsPerUserIp;

    // idMap is used to limit connections per authentication Id
    private final Map<Id, Set<ServerCnxn>> idMap = new ConcurrentHashMap<>();
    // idIpMap is used to limit connections per authentication Id and IP
    private final Map<IdAndIp, Set<ServerCnxn>> idIpMap =
        new ConcurrentHashMap<>();

    public IdCountAuthenticationLimiter() {
        maxClientCnxnsPerUser = Integer.parseInt(System.getProperty(ZOOKEEPER_CNXN_LIMIT_PER_USER, "0"));
        LOG.info("{} = {}", ZOOKEEPER_CNXN_LIMIT_PER_USER, maxClientCnxnsPerUser);

        maxClientCnxnsPerUserIp = Integer.parseInt(System.getProperty(ZOOKEEPER_CNXN_LIMIT_PER_USERIP, "0"));
        LOG.info("{} = {}", ZOOKEEPER_CNXN_LIMIT_PER_USERIP, maxClientCnxnsPerUserIp);
    }

    public void addAuthInfo(ServerCnxn cnxn, Id id) {
        updateAuthInfo(cnxn, id, true);
    }

    public void removeAuthInfo(ServerCnxn cnxn, Id id) {
        updateAuthInfo(cnxn, id, false);
    }

    private void updateAuthInfo(ServerCnxn cnxn, Id id, boolean adding) {
        if (isIgnoredScheme(id)) {
            return;
        }

        if (maxClientCnxnsPerUser > 0) {
            updateAuthInfo(idMap, cnxn, id, adding);
        }

        if (maxClientCnxnsPerUserIp > 0) {
            InetAddress ia = getInetAddress(cnxn);
            IdAndIp key = new IdAndIp(ia, id);
            updateAuthInfo(idIpMap, cnxn, key, adding);
        }
    }

    private static boolean isIgnoredScheme(Id id) {
        return "ip".equals(id.getScheme());
    }

    private static InetAddress getInetAddress(ServerCnxn cnxn) {
        InetSocketAddress sa = cnxn.getRemoteSocketAddress();

        return sa != null ? sa.getAddress() : null;
    }

    private static <T> void updateAuthInfo(Map<T, Set<ServerCnxn>> map, ServerCnxn cnxn, T key, boolean adding) {
        Set<ServerCnxn> set = map.get(key);

        if (set == null && adding) {
            set = Collections.newSetFromMap(new ConcurrentHashMap<ServerCnxn, Boolean>(2));
            Set<ServerCnxn> existingSet = map.putIfAbsent(key, set);
            if (existingSet != null) {
                set = existingSet;
            }
        }

        if (adding) {
            set.add(cnxn);
        } else if (set != null) {
            set.remove(cnxn);
            // We follow the lead of NIOServerCnxnFactory and keep
            // empty mappings in the set.
        }

        LOG.debug("{} auth info; key={}, cnxn={}, count={}",
            adding ? "Added" : "Removed", key, cnxn, set.size());
    }

    public KeeperException.Code checkAuthenticationLimits(ServerCnxn cnxn) {
        if (isAboveLimits(cnxn)) {
            return KeeperException.Code.AUTHFAILED;
        } else {
            return KeeperException.Code.OK;
        }
    }

    private boolean isAboveLimits(ServerCnxn cnxn) {
        InetAddress ia = getInetAddress(cnxn);

        for (Id id : cnxn.getAuthInfo()) {
            if (isIgnoredScheme(id)) {
                continue;
            }

            if (maxClientCnxnsPerUser > 0) {
                if (isAboveLimit(idMap, id, maxClientCnxnsPerUser)) {
                    return true;
                }
            }

            if (maxClientCnxnsPerUserIp > 0) {
                IdAndIp key = new IdAndIp(ia, id);
                if (isAboveLimit(idIpMap, key, maxClientCnxnsPerUserIp)) {
                    return true;
                }
            }
        }

        return false;
    }

    private static <T> boolean isAboveLimit(Map<T, Set<ServerCnxn>> map, T key, int limit) {
        Set<ServerCnxn> cnxns = map.get(key);

        if (cnxns != null) {
            int cnxnCount = cnxns.size();
            if (cnxnCount > limit) {
                LOG.warn("Too many connections from {} - max is {}", key, limit);
                return true;
            }
        }

        return false;
    }
}
