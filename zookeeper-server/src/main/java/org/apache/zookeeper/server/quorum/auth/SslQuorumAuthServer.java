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

package org.apache.zookeeper.server.quorum.auth;

import java.io.DataInputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.Principal;
import java.util.Set;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import org.apache.zookeeper.server.quorum.UnifiedServerSocket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SslQuorumAuthServer implements QuorumAuthServer {

    private static final Logger LOG = LoggerFactory.getLogger(SslQuorumAuthServer.class);

    private final Set<String> authzHosts;

    public SslQuorumAuthServer(Set<String> authzHosts) {
        this.authzHosts = authzHosts;
    }

    @Override
    public void authenticate(final Socket sock, final DataInputStream din) throws IOException {
        SSLSocket sslSock = null;

        if (sock instanceof SSLSocket) {
            sslSock = (SSLSocket) sock;
        } else if (sock instanceof UnifiedServerSocket.UnifiedSocket) {
            sslSock = ((UnifiedServerSocket.UnifiedSocket) sock).getSslSocket();
        }

        if (sslSock == null) {
            throw new IOException("Not an SSL socket; class: " + (sock == null ? null : sock.getClass()));
        }

        SSLSession session = sslSock.getSession();

        if (!session.isValid()) {
            throw new IOException("Not a valid SSL session");
        }

        Principal princ = session.getPeerPrincipal();
        String princName = princ.getName();

        LOG.info("Peer principal name: {}", princName);

        boolean authorized = false;

        LdapName ldapName;

        try {
            ldapName = new LdapName(princName);
        } catch(InvalidNameException x) {
            throw new IOException(x);
        }

        for (Rdn rdn : ldapName.getRdns()) {
            if (rdn.getType().equalsIgnoreCase("CN")) {
                String commonName = rdn.getValue().toString();

                if (authzHosts.contains(commonName)) {
                    LOG.info("Successfully authorized learner; principal: {}, CN: {}", princName, commonName);
                    authorized = true;
                } else {
                    LOG.warn("CN={} not in {}", commonName, authzHosts);
                }
            }
        }

        if (!authorized) {
            throw new IOException("No authorization: '" + princName + "'");
        }
    }
}
