/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.zookeeper.server;

import static org.apache.zookeeper.server.persistence.FileSnap.SNAPSHOT_FILE_PREFIX;
import com.fasterxml.jackson.core.io.JsonStringEncoder;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.jute.BinaryInputArchive;
import org.apache.jute.InputArchive;
import org.apache.yetus.audience.InterfaceAudience;
import org.apache.zookeeper.ZKUtil;
import org.apache.zookeeper.data.ACL;
import org.apache.zookeeper.data.StatPersisted;
import org.apache.zookeeper.server.persistence.FileSnap;
import org.apache.zookeeper.server.persistence.SnapStream;
import org.apache.zookeeper.server.persistence.Util;
import org.apache.zookeeper.util.ServiceUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Dump a snapshot file to stdout.
 *
 * For JSON format, followed https://dev.yorhel.nl/ncdu/jsonfmt
 */
@InterfaceAudience.Public
public class SnapshotFormatter {
    private static final Logger LOG = LoggerFactory.getLogger(SnapshotFormatter.class);

    private static final String OPT_DUMP_DATA = "d";

    private static final String OPT_JSON = "json";

    private static final String OPT_DUMP_ACLS = "dump-acls";

    // per-znode counter so ncdu treats each as a unique object
    private static Integer INODE_IDX = 1000;

    /**
     * USAGE: SnapshotFormatter snapshot_file or the ready-made script: zkSnapShotToolkit.sh
     */
    public static void main(String[] args) throws Exception {
        Options options = createOptions();
        String snapshotFile = null;

        CommandLineParser parser = new DefaultParser();
        CommandLine cl = null;
        try {
            cl = parser.parse(options, args);
        } catch (ParseException x) {
            showUsage(options, x);
            return;
        }

        LinkedList<String> positionals = new LinkedList<>(cl.getArgList());

        if (!positionals.isEmpty()) {
            snapshotFile = positionals.removeFirst();
        }

        if (!positionals.isEmpty() || snapshotFile == null) {
            showUsage(options, null);
            return;
        }

        String error = ZKUtil.validateFileInput(snapshotFile);
        if (null != error) {
            LOG.error(error);
            ServiceUtils.requestSystemExit(ExitCode.INVALID_INVOCATION.getValue());
        }

        if (cl.hasOption(OPT_DUMP_DATA) && cl.hasOption(OPT_JSON)) {
            LOG.error("Cannot specify both data dump (-d) and json mode (-json) in same call");
            ServiceUtils.requestSystemExit(ExitCode.INVALID_INVOCATION.getValue());
        }

        new SnapshotFormatter(snapshotFile, cl).run();
    }

    private static Options createOptions() {
        final Options options = new Options();

        options.addOption(
            Option.builder(OPT_DUMP_DATA)
                .longOpt("dump-data")
                .desc("Dump the data for each znode")
                .build());

        options.addOption(
            Option.builder(OPT_JSON)
                .longOpt("json")
                .desc("Dump znode sizes in ncdu(1) JSON format")
                .build());

        options.addOption(
            Option.builder()
                .longOpt(OPT_DUMP_ACLS)
                .desc("Dump the ACL entries for each znode")
                .build());

        return options;
    }

    private static void showUsage(Options options, ParseException x) {
        ExitCode exitCode = ExitCode.INVALID_INVOCATION;
        String footer = null;

        if (x != null) {
            footer = "\n" + x.getMessage();
        }

        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("SnapshotFormatter [-d|-json] snapshot_file",
                            null,
                            options,
                            footer);

        ServiceUtils.requestSystemExit(exitCode.getValue());
    }

    private final String snapshotFileName;

    private final CommandLine commandLine;

    private SnapshotFormatter(String snapshotFileName, CommandLine commandLine) {
        this.snapshotFileName = snapshotFileName;
        this.commandLine = commandLine;
    }

    public void run() throws IOException {
        File snapshotFile = new File(snapshotFileName);
        try (InputStream is = SnapStream.getInputStream(snapshotFile)) {
            InputArchive ia = BinaryInputArchive.getArchive(is);

            DataTree dataTree = new DataTree();
            Map<Long, Integer> sessions = new HashMap<>();

            FileSnap.deserialize(dataTree, sessions, ia);
            long fileNameZxid = Util.getZxidFromName(snapshotFile.getName(), SNAPSHOT_FILE_PREFIX);

            if (commandLine.hasOption(OPT_JSON)) {
                printSnapshotJson(dataTree);
            } else {
                printDetails(dataTree, sessions, fileNameZxid);
            }
        }
    }

    private void printDetails(DataTree dataTree, Map<Long, Integer> sessions, long fileNameZxid) {
        long dtZxid = printZnodeDetails(dataTree);
        printSessionDetails(dataTree, sessions);
        DataTree.ZxidDigest targetZxidDigest = dataTree.getDigestFromLoadedSnapshot();
        if (targetZxidDigest != null) {
            System.out.println(String.format("Target zxid digest is: %s, %s",
                    Long.toHexString(targetZxidDigest.zxid), targetZxidDigest.digest));
        }
        System.out.println(String.format("----%nLast zxid: 0x%s", Long.toHexString(Math.max(fileNameZxid, dtZxid))));
    }

    private long printZnodeDetails(DataTree dataTree) {
        System.out.println(String.format("ZNode Details (count=%d):", dataTree.getNodeCount()));

        final long zxid = printZnode(dataTree, "/");
        System.out.println("----");
        return zxid;
    }

    private long printZnode(DataTree dataTree, String name) {
        System.out.println("----");
        DataNode n = dataTree.getNode(name);
        Set<String> children;
        long zxid;
        synchronized (n) { // keep findbugs happy
            System.out.println(name);
            printStat(n.stat);
            zxid = Math.max(n.stat.getMzxid(), n.stat.getPzxid());
            if (commandLine.hasOption(OPT_DUMP_DATA)) {
                System.out.println("  data = " + (n.data == null ? "" : Base64.getEncoder().encodeToString(n.data)));
            } else {
                System.out.println("  dataLength = " + (n.data == null ? 0 : n.data.length));
            }
            children = n.getChildren();
        }
        if (commandLine.hasOption(OPT_DUMP_ACLS)) {
            try {
                long aclId;
                List<ACL> acl;
                synchronized(n) {
                    aclId = n.acl;
                    acl = dataTree.getACL(n);
                }
                System.out.println("  aclId = " + aclId);
                if (acl == null || acl.isEmpty()) {
                    LOG.warn("Missing ACL; node: {}", name);
                }
                if (acl != null) {
                    for (ACL aclEntry : acl) {
                        if (aclEntry == null || aclEntry.getId() == null) {
                            continue;
                        }
                        System.out.println("  aclEntry = " + formatAclEntry(aclEntry));
                    }
                }
            } catch (Exception x) {
                LOG.error("Exception accessing ACL; node: " + name, x);
            }
        }
        if (children != null) {
            for (String child : children) {
                long cxid = printZnode(dataTree, name + (name.equals("/") ? "" : "/") + child);
                zxid = Math.max(zxid, cxid);
            }
        }
        return zxid;
    }

    private static String formatAclEntry(ACL aclEntry) {
        StringBuilder b = new StringBuilder();

        b.append(aclEntry.getId().getScheme());
        b.append(':');
        b.append(aclEntry.getId().getId());
        b.append(':');

        String flags = "rwcda";
        int perms = aclEntry.getPerms();
        for (int i = 0; i < flags.length(); i++) {
            if ((perms & (1 << i)) != 0) {
                b.append(flags.charAt(i));
            }
        }

        return b.toString();
    }

    private void printSessionDetails(DataTree dataTree, Map<Long, Integer> sessions) {
        System.out.println("Session Details (sid, timeout, ephemeralCount):");
        for (Map.Entry<Long, Integer> e : sessions.entrySet()) {
            long sid = e.getKey();
            System.out.println(String.format("%#016x, %d, %d", sid, e.getValue(), dataTree.getEphemerals(sid).size()));
        }
    }

    private void printStat(StatPersisted stat) {
        printHex("cZxid", stat.getCzxid());
        System.out.println("  ctime = " + new Date(stat.getCtime()).toString());
        printHex("mZxid", stat.getMzxid());
        System.out.println("  mtime = " + new Date(stat.getMtime()).toString());
        printHex("pZxid", stat.getPzxid());
        System.out.println("  cversion = " + stat.getCversion());
        System.out.println("  dataVersion = " + stat.getVersion());
        System.out.println("  aclVersion = " + stat.getAversion());
        printHex("ephemeralOwner", stat.getEphemeralOwner());
    }

    private void printHex(String prefix, long value) {
        System.out.println(String.format("  %s = %#016x", prefix, value));
    }

    private void printSnapshotJson(final DataTree dataTree) {
        JsonStringEncoder encoder = JsonStringEncoder.getInstance();
        System.out.printf(
            "[1,0,{\"progname\":\"SnapshotFormatter.java\",\"progver\":\"0.01\",\"timestamp\":%d}",
            System.currentTimeMillis());
        printZnodeJson(dataTree, "/", encoder);
        System.out.print("]");
    }

    private void printZnodeJson(final DataTree dataTree, final String fullPath, JsonStringEncoder encoder) {


        final DataNode n = dataTree.getNode(fullPath);

        if (null == n) {
            LOG.warn("DataTree Node for {} doesn't exist", fullPath);
            return;
        }

        final String name = fullPath.equals("/")
            ? fullPath
            : fullPath.substring(fullPath.lastIndexOf("/") + 1);

        System.out.print(",");

        int dataLen;
        synchronized (n) { // keep findbugs happy
            dataLen = (n.data == null) ? 0 : n.data.length;
        }
        StringBuilder nodeSB = new StringBuilder();
        nodeSB.append("{");
        nodeSB.append("\"name\":\"").append(encoder.quoteAsString(name)).append("\"").append(",");
        nodeSB.append("\"asize\":").append(dataLen).append(",");
        nodeSB.append("\"dsize\":").append(dataLen).append(",");
        nodeSB.append("\"dev\":").append(0).append(",");
        nodeSB.append("\"ino\":").append(++INODE_IDX);
        nodeSB.append("}");

        Set<String> children;
        synchronized (n) { // keep findbugs happy
            children = n.getChildren();
        }
        if (children != null && children.size() > 0) {
            System.out.print("[" + nodeSB);
            for (String child : children) {
                printZnodeJson(dataTree, fullPath + (fullPath.equals("/") ? "" : "/") + child, encoder);
            }
            System.out.print("]");
        } else {
            System.out.print(nodeSB);
        }
    }

}
