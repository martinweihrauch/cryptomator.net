import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Arrays;

public class Impl implements UVFMasterkey {

    @Override
    public DestroyableSecretKey subKey(int seedId, int size, byte[] context, String algorithm) throws IllegalArgumentException {
        throwIfDestroyed();
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(algorithm, "algorithm");
        byte[] ikm = seeds.get(seedId);
        if (ikm == null) {
            throw new IllegalArgumentException("No seed for revision " + seedId);
        }

        // Log the IKM being used
        System.out.println("Java SubKey - Using IKM for seedId " + seedId + " (B64): " + Base64.getEncoder().encodeToString(ikm));
        System.out.println("Java SubKey - Salt (B64): " + Base64.getEncoder().encodeToString(this.kdfSalt));
        System.out.println("Java SubKey - Context (ASCII): " + new String(context, StandardCharsets.US_ASCII));
        System.out.println("Java SubKey - Size: " + size);

        byte[] subkey = HKDFHelper.hkdfSha512(this.kdfSalt, ikm, context, size);
        System.out.println("Java SubKey - Derived Subkey (B64): " + Base64.getEncoder().encodeToString(subkey));

        try {
            return new DestroyableSecretKey(subkey, algorithm);
        } finally {
            Arrays.fill(subkey, (byte) 0); // Zero out the temporary subkey array
        }
    }
} 