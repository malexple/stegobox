package ru.mcs;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.awt.image.BufferedImage;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Ядро стеганографии: LSB-встраивание + AES-256/GCM.
 *
 * Формат скрытых данных в изображении:
 *   [4 байта: длина payload] [payload]
 * где payload = [16 байт salt][12 байт IV][шифротекст + 16 байт auth tag].
 *
 * Все байты пишутся в младшие биты каналов R, G, B последовательно,
 * слева-направо, сверху-вниз.
 */
public final class StegoEngine {

    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 12;
    private static final int TAG_BITS = 128;
    private static final int PBKDF2_ITERATIONS = 120_000;
    private static final int KEY_BITS = 256;
    private static final String CIPHER = "AES/GCM/NoPadding";
    private static final String KDF = "PBKDF2WithHmacSHA256";

    private StegoEngine() {
    }

    public static BufferedImage hideText(BufferedImage source, String text, char[] password) {
        if (text == null || text.isEmpty()) {
            throw new IllegalArgumentException("Текст пустой");
        }
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Пароль пустой");
        }

        byte[] payload = encrypt(text, password);

        byte[] data = new byte[4 + payload.length];
        data[0] = (byte) (payload.length >>> 24);
        data[1] = (byte) (payload.length >>> 16);
        data[2] = (byte) (payload.length >>> 8);
        data[3] = (byte) (payload.length);
        System.arraycopy(payload, 0, data, 4, payload.length);

        BufferedImage out = toRgb(source);

        long capacityBytes = (long) out.getWidth() * out.getHeight() * 3 / 8;
        if (data.length > capacityBytes) {
            throw new IllegalArgumentException(
                    "Недостаточно места: нужно " + data.length
                            + " байт, доступно " + capacityBytes + " байт");
        }

        embedBits(out, data);
        return out;
    }

    public static String extractText(BufferedImage image, char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Пароль пустой");
        }

        byte[] header = readBytes(image, 0, 4);
        int payloadLen = ((header[0] & 0xFF) << 24)
                | ((header[1] & 0xFF) << 16)
                | ((header[2] & 0xFF) << 8)
                | (header[3] & 0xFF);

        long capacityBytes = (long) image.getWidth() * image.getHeight() * 3 / 8;
        if (payloadLen <= 0 || payloadLen + 4L > capacityBytes) {
            throw new IllegalStateException("Скрытые данные не найдены");
        }

        byte[] payload = readBytes(image, 4, payloadLen);
        try {
            return decrypt(payload, password);
        } catch (Exception e) {
            throw new IllegalStateException("Неверный пароль или повреждённые данные", e);
        }
    }

    // ---------- Встраивание / чтение бит ----------

    private static BufferedImage toRgb(BufferedImage source) {
        BufferedImage out = new BufferedImage(
                source.getWidth(), source.getHeight(), BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < source.getHeight(); y++) {
            for (int x = 0; x < source.getWidth(); x++) {
                out.setRGB(x, y, source.getRGB(x, y));
            }
        }
        return out;
    }

    private static void embedBits(BufferedImage image, byte[] data) {
        int totalBits = data.length * 8;
        int bitIndex = 0;

        outer:
        for (int y = 0; y < image.getHeight(); y++) {
            for (int x = 0; x < image.getWidth(); x++) {
                int rgb = image.getRGB(x, y);
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;

                if (bitIndex < totalBits) r = (r & 0xFE) | nextBit(data, bitIndex++);
                if (bitIndex < totalBits) g = (g & 0xFE) | nextBit(data, bitIndex++);
                if (bitIndex < totalBits) b = (b & 0xFE) | nextBit(data, bitIndex++);

                image.setRGB(x, y, (r << 16) | (g << 8) | b);

                if (bitIndex >= totalBits) {
                    break outer;
                }
            }
        }
    }

    private static int nextBit(byte[] data, int bitIndex) {
        int byteIndex = bitIndex >> 3;
        int bitInByte = 7 - (bitIndex & 7);
        return (data[byteIndex] >> bitInByte) & 1;
    }

    private static byte[] readBytes(BufferedImage image, int startByte, int count) {
        long capacityBytes = (long) image.getWidth() * image.getHeight() * 3 / 8;
        if ((long) startByte + count > capacityBytes) {
            throw new IllegalStateException("Недостаточно данных в изображении");
        }

        byte[] result = new byte[count];
        long skipBits = (long) startByte * 8;
        long globalBit = 0;
        int written = 0;
        int currentByte = 0;
        int bitCount = 0;

        outer:
        for (int y = 0; y < image.getHeight(); y++) {
            for (int x = 0; x < image.getWidth(); x++) {
                int rgb = image.getRGB(x, y);
                int[] channels = {(rgb >> 16) & 1, (rgb >> 8) & 1, rgb & 1};

                for (int bit : channels) {
                    globalBit++;
                    if (globalBit <= skipBits) {
                        continue;
                    }
                    currentByte = (currentByte << 1) | bit;
                    bitCount++;
                    if (bitCount == 8) {
                        result[written++] = (byte) currentByte;
                        if (written >= count) {
                            break outer;
                        }
                        currentByte = 0;
                        bitCount = 0;
                    }
                }
            }
        }
        return result;
    }

    // ---------- Криптография ----------

    private static byte[] encrypt(String text, char[] password) {
        try {
            SecureRandom rnd = new SecureRandom();
            byte[] salt = new byte[SALT_LEN];
            byte[] iv = new byte[IV_LEN];
            rnd.nextBytes(salt);
            rnd.nextBytes(iv);

            SecretKey key = deriveKey(password, salt);
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            byte[] cipherText = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));

            byte[] payload = new byte[SALT_LEN + IV_LEN + cipherText.length];
            System.arraycopy(salt, 0, payload, 0, SALT_LEN);
            System.arraycopy(iv, 0, payload, SALT_LEN, IV_LEN);
            System.arraycopy(cipherText, 0, payload, SALT_LEN + IV_LEN, cipherText.length);
            return payload;
        } catch (Exception e) {
            throw new IllegalStateException("Ошибка шифрования: " + e.getMessage(), e);
        }
    }

    private static String decrypt(byte[] payload, char[] password) throws Exception {
        if (payload.length < SALT_LEN + IV_LEN + 16) {
            throw new IllegalStateException("Повреждённые данные");
        }
        byte[] salt = Arrays.copyOfRange(payload, 0, SALT_LEN);
        byte[] iv = Arrays.copyOfRange(payload, SALT_LEN, SALT_LEN + IV_LEN);
        byte[] cipherText = Arrays.copyOfRange(payload, SALT_LEN + IV_LEN, payload.length);

        SecretKey key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        byte[] plain = cipher.doFinal(cipherText);
        return new String(plain, StandardCharsets.UTF_8);
    }

    private static SecretKey deriveKey(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_BITS);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF);
            byte[] keyBytes = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } finally {
            spec.clearPassword();
        }
    }
}