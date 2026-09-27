package ch.ethz.dsg.timecrypt.bench;

import ch.ethz.dsg.timecrypt.DefaultConfigs;
import ch.ethz.dsg.timecrypt.TimeCryptClient;
import ch.ethz.dsg.timecrypt.client.serverInterface.EncryptedChunk;
import ch.ethz.dsg.timecrypt.client.state.LocalTimeCryptKeystore;
import ch.ethz.dsg.timecrypt.client.state.LocalTimeCryptProfile;
import ch.ethz.dsg.timecrypt.client.streamHandling.Chunk;
import ch.ethz.dsg.timecrypt.client.streamHandling.DataPoint;
import ch.ethz.dsg.timecrypt.client.streamHandling.InsertHandler;
import ch.ethz.dsg.timecrypt.client.streamHandling.TimeUtil;

import ch.ethz.dsg.timecrypt.protocol.EncryptionScheme;
import ch.ethz.dsg.timecrypt.protocol.chunk;
import ch.ethz.dsg.timecrypt.protocol.chunkCreationMessage;
import ch.ethz.dsg.timecrypt.protocol.chunkId;
import ch.ethz.dsg.timecrypt.protocol.digest;
import ch.ethz.dsg.timecrypt.protocol.longPayload;
import ch.ethz.dsg.timecrypt.protocol.metadataConfig;
import ch.ethz.dsg.timecrypt.protocol.metadataContent;
import com.google.protobuf.ByteString;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Scanner;

/**
 * Thin driver over the official TimeCrypt client + in-memory server.
 * Payload bytes are packed as native long DataPoints (8 bytes each, zero-padded).
 * Does not change HEAC / AES-GCM chunk encryption.
 */
public class LocalMicrobench {
    public static void main(String[] args) throws Exception {
        String host = args.length > 0 ? args[0] : "127.0.0.1";
        int port = args.length > 1 ? Integer.parseInt(args[1]) : 15000;
        Path ks = Files.createTempDirectory("tc-ks");
        LocalTimeCryptProfile profile = new LocalTimeCryptProfile(
                ks.resolve("profile").toString(), "benchUser", "benchProfile", host, port);
        LocalTimeCryptKeystore keystore = LocalTimeCryptKeystore.createLocalKeystore(
                ks.resolve("keys.jks").toString(), "bench-password-16".toCharArray());
        TimeCryptClient client = new TimeCryptClient(keystore, profile);
        long streamId = -1;
        int chunkIx = 0;
        long streamStart = 0;
        Scanner sc = new Scanner(System.in);
        while (sc.hasNextLine()) {
            String line = sc.nextLine().trim();
            if (line.isEmpty()) continue;
            if (line.equals("QUIT")) break;
            try {
                if (line.equals("SETUP")) {
                    streamStart = TimeUtil.getDateAtLastFullMinute().getTime() - 3_600_000L;
                    streamId = -1;
                    for (int attempt = 0; attempt < 16 && streamId <= 0; attempt++) {
                        streamId = client.createStream(
                                "bench-" + attempt,
                                "local-bench",
                                TimeUtil.Precision.ONE_MINUTE,
                                Collections.singletonList(TimeUtil.Precision.ONE_MINUTE),
                                DefaultConfigs.getDefaultMetaDataConfig(),
                                DefaultConfigs.getDefaultEncryptionScheme(),
                                null,
                                new Date(streamStart));
                    }
                    if (streamId <= 0) throw new IllegalStateException("no positive stream id");
                    chunkIx = 0;
                    System.out.println("OK " + streamId);
                    System.out.flush();
                } else if (line.startsWith("PROTECT ")) {
                    if (streamId <= 0) throw new IllegalStateException("SETUP first");
                    byte[] payload = hexToBytes(line.substring(8).trim());
                    long t0 = System.nanoTime();
                    long chunkStart = streamStart + chunkIx * 60_000L;
                    InsertHandler handler = client.getHandlerForBackupInsert(streamId, new Date(chunkStart));
                    long[] values = unpackLongs(payload);
                    for (int i = 0; i < values.length; i++) {
                        handler.writeDataPointToStream(new DataPoint(new Date(chunkStart + i), values[i]));
                    }
                    handler.terminate();
                    double ms = (System.nanoTime() - t0) / 1e6;
                    System.out.println("OK " + ms + " " + streamId + ":" + chunkIx + ":" + payload.length
                            + " 0 0 0 0 0 0");
                    chunkIx++;
                    System.out.flush();
                } else if (line.equals("ACCOUNT")) {
                    if (chunkIx <= 0) throw new IllegalStateException("PROTECT first");
                    int cix = chunkIx - 1;
                    int heac = 0;
                    byte[] blob = new byte[0];
                    for (EncryptedChunk ch : client.getServerInterface().getChunks(streamId, cix, cix + 1)) {
                        blob = ch.getPayload();
                    }
                    int enc = Math.max(0, blob.length - 12 - 16);
                    digest.Builder digestBuilder = digest.newBuilder()
                            .setStart(chunkId.newBuilder().setId(cix))
                            .setEnd(chunkId.newBuilder().setId(cix + 1));
                    java.util.List<ch.ethz.dsg.timecrypt.client.streamHandling.metaData.StreamMetaData> meta =
                            client.getStream(streamId).getMetaData();
                    java.util.List<ch.ethz.dsg.timecrypt.client.serverInterface.EncryptedDigest> digests =
                            client.getServerInterface().getStatisticalData(streamId, cix, cix + 1, 1, meta);
                    for (ch.ethz.dsg.timecrypt.client.serverInterface.EncryptedDigest d : digests) {
                        for (ch.ethz.dsg.timecrypt.client.serverInterface.EncryptedMetadata m : d.getPayload()) {
                            if (m.getPayload() != null) heac += m.getPayload().length;
                            if (m.getMac() != null) heac += m.getMac().length;
                            metadataContent.Builder b = metadataContent.newBuilder()
                                    .setConfig(metadataConfig.newBuilder()
                                            .setId(m.getMetadataId())
                                            .setScheme(EncryptionScheme.LONG));
                            if (m.getMac() != null && m.getMac().length > 0) {
                                b.setLongMacPayload(ch.ethz.dsg.timecrypt.protocol.longMacPayload.newBuilder()
                                        .setEncryptedLong(m.getPayloadAsLong())
                                        .setAuthCode(ByteString.copyFrom(m.getMac()))
                                        .setAuthCodeBits(m.getNumMacBits()));
                            } else {
                                b.setLongPayload(longPayload.newBuilder().setEncryptedLong(m.getPayloadAsLong()));
                            }
                            digestBuilder.addMetadataContent(b);
                        }
                    }
                    int serialized = chunkCreationMessage.newBuilder()
                            .setChunk(chunk.newBuilder()
                                    .setChunkId(chunkId.newBuilder().setId(cix))
                                    .setStreamId(ch.ethz.dsg.timecrypt.protocol.streamId.newBuilder().setStreamId(streamId))
                                    .setChunkContent(ByteString.copyFrom(blob)))
                            .setDigest(digestBuilder.build())
                            .build()
                            .getSerializedSize();
                    int other = serialized - enc - 12 - 16 - heac;
                    System.out.println("OK " + enc + " " + heac + " " + other + " " + serialized);
                    System.out.flush();
                } else if (line.startsWith("RECOVER ")) {
                    String[] parts = line.substring(8).trim().split(":");
                    long sid = Long.parseLong(parts[0]);
                    int cix = Integer.parseInt(parts[1]);
                    int nbytes = Integer.parseInt(parts[2]);
                    long t0 = System.nanoTime();
                    List<Chunk> chunks = client.getChunks(sid, cix, cix);
                    List<DataPoint> points = new ArrayList<>();
                    for (Chunk c : chunks) points.addAll(c.getValues());
                    points.sort((a, b) -> a.getTimestamp().compareTo(b.getTimestamp()));
                    long[] vals = new long[points.size()];
                    for (int i = 0; i < points.size(); i++) vals[i] = points.get(i).getValue();
                    byte[] payload = packLongs(vals);
                    if (payload.length < nbytes) throw new IllegalStateException("short plaintext");
                    payload = java.util.Arrays.copyOf(payload, nbytes);
                    double ms = (System.nanoTime() - t0) / 1e6;
                    System.out.println("OK " + ms + " " + bytesToHex(payload));
                    System.out.flush();
                } else {
                    System.out.println("ERR unknown");
                    System.out.flush();
                }
            } catch (Exception e) {
                System.out.println("ERR " + e.getClass().getSimpleName() + " " + String.valueOf(e.getMessage()).replace('\n', ' '));
                System.out.flush();
            }
        }
    }

    static long[] unpackLongs(byte[] payload) {
        int n = (payload.length + 7) / 8;
        byte[] padded = new byte[n * 8];
        System.arraycopy(payload, 0, padded, 0, payload.length);
        ByteBuffer buf = ByteBuffer.wrap(padded).order(ByteOrder.BIG_ENDIAN);
        long[] out = new long[n];
        for (int i = 0; i < n; i++) out[i] = buf.getLong();
        return out;
    }

    static byte[] packLongs(long[] vals) {
        ByteBuffer buf = ByteBuffer.allocate(vals.length * 8).order(ByteOrder.BIG_ENDIAN);
        for (long v : vals) buf.putLong(v);
        return buf.array();
    }

    static byte[] hexToBytes(String hex) {
        int n = hex.length() / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        return out;
    }

    static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) sb.append(String.format("%02x", v));
        return sb.toString();
    }
}
