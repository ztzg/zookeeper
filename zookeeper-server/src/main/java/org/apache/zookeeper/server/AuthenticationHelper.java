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
package org.apache.zookeeper.server;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.data.Id;
import org.apache.zookeeper.proto.ReplyHeader;
import org.apache.zookeeper.server.auth.AuthenticationLimiter;
import org.apache.zookeeper.server.auth.ProviderRegistry;
import org.apache.zookeeper.util.ServiceUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Contains helper methods to manage authentication
 */
public class AuthenticationHelper {
    private static final Logger LOG = LoggerFactory.getLogger(AuthenticationHelper.class);

    public static final String AUTH_LIMITER = "zookeeper.auth.limiter";

    private AuthenticationLimiter limiter = null;

    public AuthenticationHelper() {
        initConfigurations();
    }

    private void initConfigurations() {
        String limiterClassName = System.getProperty(AUTH_LIMITER);
        if (limiterClassName != null) {
            try {
                Class<?> c = ZooKeeperServer.class.getClassLoader().loadClass(limiterClassName);
                limiter = (AuthenticationLimiter) c.getDeclaredConstructor().newInstance();
                LOG.info("Installed authentication limiter {}", limiterClassName);
            } catch (Exception e) {
                LOG.warn("Failed to load {} implementation {}",
                         AuthenticationLimiter.class.getName(),
                         limiterClassName, e);
                ServiceUtils.requestSystemExit(ExitCode.UNEXPECTED_ERROR.getValue());
            }
        }
    }

    public KeeperException.Code checkAuthenticationLimits(ServerCnxn connection) {
        if (limiter == null) {
            // Always acceptable.
            return KeeperException.Code.OK;
        }

        return limiter.checkAuthenticationLimits(connection);
    }

    public AuthenticationLimiter getAuthenticationLimiter() {
        return limiter;
    }
}
