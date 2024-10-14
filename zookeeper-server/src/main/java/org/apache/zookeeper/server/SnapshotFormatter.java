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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.attribute.FileTime;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.apache.jute.BinaryInputArchive;
import org.apache.jute.InputArchive;
import org.apache.yetus.audience.InterfaceAudience;
import org.apache.zookeeper.ZKUtil;
import org.apache.zookeeper.data.ACL;
import org.apache.zookeeper.data.StatPersisted;
import org.apache.zookeeper.server.persistence.FileSnap;
import org.apache.zookeeper.server.persistence.SnapStream;
import org.apache.zookeeper.server.persistence.FileTxnSnapLog;
import org.apache.zookeeper.server.persistence.Util;
import org.apache.zookeeper.util.ServiceUtils;

/**
 * Dump a snapshot file to stdout.
 *
 * For JSON format, followed https://dev.yorhel.nl/ncdu/jsonfmt
 */
@InterfaceAudience.Public
public class SnapshotFormatter {

    // per-znode counter so ncdu treats each as a unique object
    private static Integer INODE_IDX = 1000;

    public static class Options {
        boolean loadDb = false;

        String snapOrSnapDirArg = null;

        String dataDirArg = null;

        boolean dumpData = false;

        boolean dumpJson = false;

        boolean dumpAcls = false;

        ZipOutputStream zip = null;
    }

    public interface Processor<A> {
        A apply(DataTree dataTree, Map<Long, Integer> sessions, long lastZxid, A acc) throws IOException;
    }

    public interface Fold<A> {
        A apply(DataTree dataTree, String path, A acc) throws IOException;
    }

    private final Options options;

    public SnapshotFormatter(Options options) {
        this.options = options;
    }

    /**
     * USAGE: SnapshotFormatter snapshot_file or the ready-made script: zkSnapShotToolkit.sh
     */
    public static void main(String[] args) throws Exception {
        Options options = new Options();
        File zipFile = null;

        int i;
        for (i = 0; i < args.length; i++) {
            if (args[i].equals("-loaddb")) {
                options.loadDb = true;
            } else if (args[i].equals("-d")) {
                options.dumpData = true;
            } else if (args[i].equals("-json")) {
                options.dumpJson = true;
            } else if (args[i].equals("-acls")) {
                options.dumpAcls = true;
            } else if (args[i].equals("-zip")) {
                zipFile = new File(args[i + 1]);
                i++;
            } else if (options.snapOrSnapDirArg == null) {
                options.snapOrSnapDirArg = args[i];
            } else if (options.dataDirArg == null) {
                options.dataDirArg = args[i];
            } else {
                break;
            }
        }

        boolean valid = args.length == i
            && options.snapOrSnapDirArg != null
            && (options.loadDb || options.dataDirArg == null);

        if (!valid) {
            System.err.println("USAGE: SnapshotFormatter [-d|-json] snapshot_file");
            System.err.println("       -acls dump the ACLs for each znode");
            System.err.println("       -zip dump the tree to a ZIP file");
            System.err.println("       -d dump the data for each znode");
            System.err.println("       -json dump znode info in json format");
            ServiceUtils.requestSystemExit(ExitCode.INVALID_INVOCATION.getValue());
            return;
        }

        if (options.dumpData && options.dumpJson) {
            System.err.println("Cannot specify both data dump (-d) and json mode (-json) in same call");
            ServiceUtils.requestSystemExit(ExitCode.INVALID_INVOCATION.getValue());
        }

        if (zipFile != null) {
            File tmpFile = File.createTempFile(zipFile.getName(), null,
                                               zipFile.getAbsoluteFile().getParentFile());
            try (OutputStream os = new FileOutputStream(tmpFile)) {
                try (ZipOutputStream zip = new ZipOutputStream(os)) {
                    zip.setLevel(Deflater.NO_COMPRESSION);

                    options.zip = zip;

                    new SnapshotFormatter(options).run();
                }
            }
            tmpFile.renameTo(zipFile);
        } else {
            new SnapshotFormatter(options).run();
        }
    }

    public void run() throws IOException {
        Object acc = this;
        apply(this::builtinProcessor, acc);
    }

    public <A> A apply(Processor<A> processor, A acc) throws IOException {
        if (options.loadDb) {
            return processDataBase(processor, acc);
        } else {
            return processSnapshot(processor, acc);
        }
    }

    private <A> A processDataBase(Processor<A> processor, A acc) throws IOException {
        File snapDir = new File(options.snapOrSnapDirArg);

        File dataDir;
        if (options.dataDirArg != null) {
            dataDir = new File(options.dataDirArg);
        } else {
            dataDir = snapDir;
        }

        FileTxnSnapLog snapLog =
            new FileTxnSnapLog(dataDir, snapDir, /* forWrite */ false);
        ZKDatabase zkDb = new ZKDatabase(snapLog);

        long lastZxid = zkDb.loadDataBase();

        return processor.apply(zkDb.getDataTree(), zkDb.getSessionWithTimeOuts(), lastZxid, acc);
    }

    private <A> A processSnapshot(Processor<A> processor, A acc) throws IOException {
        String snapshotFileName = options.snapOrSnapDirArg;
        String error = ZKUtil.validateFileInput(snapshotFileName);
        if (null != error) {
            System.err.println(error);
            ServiceUtils.requestSystemExit(ExitCode.INVALID_INVOCATION.getValue());
        }

        File snapshotFile = new File(snapshotFileName);
        try (InputStream is = SnapStream.getInputStream(snapshotFile)) {
            InputArchive ia = BinaryInputArchive.getArchive(is);

            DataTree dataTree = new DataTree();
            Map<Long, Integer> sessions = new HashMap<>();

            FileSnap.deserialize(dataTree, sessions, ia);
            long fileNameZxid = Util.getZxidFromName(snapshotFile.getName(), SNAPSHOT_FILE_PREFIX);

            return processor.apply(dataTree, sessions, fileNameZxid, acc);
        }
    }

    public Object builtinProcessor(DataTree dataTree, Map<Long, Integer> sessions, long lastZxid, Object acc) throws IOException {
        if (options.dumpJson) {
            printSnapshotJson(dataTree);
        } else if (options.zip != null) {
            dumpSnapshotZip(dataTree, "/", options.zip);
        } else {
            printDetails(dataTree, sessions, lastZxid);
        }
        return acc;
    }

    public static <A> A applyToChildren(DataTree dataTree, String parentPath, Collection<String> childNames, Fold<A> fold, A acc) throws IOException {
        String sep = parentPath.equals("/") ? "" : "/";
        for (String childName : childNames) {
            String path = parentPath + sep + childName;
            acc = fold.apply(dataTree, path, acc);
        }
        return acc;
    }

    private void printDetails(DataTree dataTree, Map<Long, Integer> sessions, long fileNameZxid) throws IOException {
        long dtZxid = printZnodeDetails(dataTree);
        printSessionDetails(dataTree, sessions);
        DataTree.ZxidDigest targetZxidDigest = dataTree.getDigestFromLoadedSnapshot();
        if (targetZxidDigest != null) {
            System.out.println(String.format("Target zxid digest is: %s, %s",
                    Long.toHexString(targetZxidDigest.zxid), targetZxidDigest.digest));
        }
        System.out.println(String.format("----%nLast zxid: 0x%s", Long.toHexString(Math.max(fileNameZxid, dtZxid))));
    }

    private long printZnodeDetails(DataTree dataTree) throws IOException {
        System.out.println(String.format("ZNode Details (count=%d):", dataTree.getNodeCount()));

        final long zxid = printZnode(dataTree, "/", 0L);
        System.out.println("----");
        return zxid;
    }

    private Long printZnode(DataTree dataTree, String name, Long zxid) throws IOException {
        System.out.println("----");
        DataNode n = dataTree.getNode(name);
        Set<String> children;
        synchronized (n) { // keep findbugs happy
            System.out.println(name);
            printStat(n.stat);
            zxid = Math.max(n.stat.getMzxid(), n.stat.getPzxid());
            if (options.dumpData) {
                System.out.println("  data = " + (n.data == null ? "" : Base64.getEncoder().encodeToString(n.data)));
            } else {
                System.out.println("  dataLength = " + (n.data == null ? 0 : n.data.length));
            }
            children = n.getChildren();
        }
        if (options.dumpAcls) {
            try {
                List<ACL> acl = dataTree.getACL(n);
                if (acl != null) {
                    for (ACL aclEntry : acl) {
                        if (aclEntry == null || aclEntry.getId() == null) {
                            continue;
                        }
                        System.out.println("  aclEntry = " + formatAclEntry(aclEntry));
                    }
                }
            } catch (Exception x) {
                // TODO: log?
            }
        }
        if (children != null) {
            zxid = applyToChildren(dataTree, name, children, this::printZnode, zxid);
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

    private static void printSessionDetails(DataTree dataTree, Map<Long, Integer> sessions) {
        System.out.println("Session Details (sid, timeout, ephemeralCount):");
        for (Map.Entry<Long, Integer> e : sessions.entrySet()) {
            long sid = e.getKey();
            System.out.println(String.format("%#016x, %d, %d", sid, e.getValue(), dataTree.getEphemerals(sid).size()));
        }
    }

    private static void printStat(StatPersisted stat) {
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

    private static void printHex(String prefix, long value) {
        System.out.println(String.format("  %s = %#016x", prefix, value));
    }

    private static void printSnapshotJson(final DataTree dataTree) throws IOException {
        JsonStringEncoder encoder = JsonStringEncoder.getInstance();
        System.out.printf(
            "[1,0,{\"progname\":\"SnapshotFormatter.java\",\"progver\":\"0.01\",\"timestamp\":%d}",
            System.currentTimeMillis());
        printZnodeJson(dataTree, "/", encoder);
        System.out.print("]");
    }

    private static JsonStringEncoder printZnodeJson(final DataTree dataTree, final String fullPath, JsonStringEncoder encoder) throws IOException {


        final DataNode n = dataTree.getNode(fullPath);

        if (null == n) {
            System.err.println("DataTree Node for " + fullPath + " doesn't exist");
            return encoder;
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
            encoder = applyToChildren(dataTree, fullPath, children, SnapshotFormatter::printZnodeJson, encoder);
            System.out.print("]");
        } else {
            System.out.print(nodeSB);
        }
        return encoder;
    }

    private static ZipOutputStream dumpSnapshotZip(DataTree dataTree, String name, ZipOutputStream zip) throws IOException {
        DataNode n = dataTree.getNode(name);
        String subtreePrefix = name + "/";
        Set<String> children;
        long zxid;
        synchronized (n) { // keep findbugs happy
            String dataName;
            if (name.equals("/")) {
                dataName = ".data";
                subtreePrefix = "/";
            } else {
                String dirName = name.substring(1) + "/";
                dataName = dirName + ".data";
                subtreePrefix = name + "/";
                ZipEntry e = new ZipEntry(dirName);
                e.setCreationTime(FileTime.from(n.stat.getCtime(), TimeUnit.MILLISECONDS));
                e.setLastModifiedTime(FileTime.from(n.stat.getMtime(), TimeUnit.MILLISECONDS));
                zip.putNextEntry(e);
                zip.closeEntry();
            }

            if (n.data != null && n.data.length > 0) {
                ZipEntry e = new ZipEntry(dataName);
                e.setCreationTime(FileTime.from(n.stat.getCtime(), TimeUnit.MILLISECONDS));
                e.setLastModifiedTime(FileTime.from(n.stat.getMtime(), TimeUnit.MILLISECONDS));
                zip.putNextEntry(e);
                zip.write(n.data);
                zip.closeEntry();
            }

            children = n.getChildren();
        }
        if (children != null) {
            zip = applyToChildren(dataTree, name, children, SnapshotFormatter::dumpSnapshotZip, zip);
        }
        return zip;
    }
}
