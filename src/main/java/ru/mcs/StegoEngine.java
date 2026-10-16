package ru.mcs;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.awt.image.BufferedImage;
import java.io.File;
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
    private static final int TAG_BYTES = TAG_BITS / 8;
    private static final int PBKDF2_ITERATIONS = 120_000;
    private static final int KEY_BITS = 256;
    private static final String CIPHER = "AES/GCM/NoPadding";
    private static final String KDF = "PBKDF2WithHmacSHA256";

    private StegoEngine() {
    }

    // ---------- Публичный API ----------

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

        long capacity = capacityBytes(out);
        if (data.length > capacity) {
            throw new IllegalArgumentException(String.format(
                    "Недостаточно места: нужно %s, доступно %s. "
                            + "Возьмите картинку большего разрешения или сократите текст.",
                    humanBytes(data.length), humanBytes(capacity)));
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

        long capacity = capacityBytes(image);
        if (payloadLen <= 0 || payloadLen + 4L > capacity) {
            throw new IllegalStateException("Скрытые данные не найдены");
        }

        byte[] payload = readBytes(image, 4, payloadLen);
        try {
            return decrypt(payload, password);
        } catch (Exception e) {
            throw new IllegalStateException("Неверный пароль или повреждённые данные", e);
        }
    }

    /**
     * Сколько байт полезной нагрузки поместится в изображение.
     * Формула: W × H × 3 / 8 (по 3 бита на пиксель).
     */
    public static long capacityBytes(BufferedImage image) {
        return (long) image.getWidth() * image.getHeight() * 3 / 8;
    }

    /**
     * Сколько байт займёт зашифрованный текст заданной длины (UTF-8).
     * Учитывает 4 байта длины, salt, IV и GCM-тег.
     */
    public static long payloadSize(int textBytesLength) {
        return 4L + SALT_LEN + IV_LEN + textBytesLength + TAG_BYTES;
    }

    /** Сколько байт займёт строка после шифрования. */
    public static long payloadSize(String text) {
        return payloadSize(text.getBytes(StandardCharsets.UTF_8).length);
    }

    /**
     * Человекочитаемый размер: «512 Б», «14.6 КБ», «3.42 МБ».
     * Используется и в UI, и в CLI, чтобы сообщения совпадали.
     */
    public static String humanBytes(long bytes) {
        if (bytes < 1024) return bytes + " Б";
        if (bytes < 1024 * 1024) return String.format("%.1f КБ", bytes / 1024.0);
        return String.format("%.2f МБ", bytes / (1024.0 * 1024));
    }

    /**
     * Формирует путь к выходному файлу рядом с исходником: <имя>_stego.png.
     * При коллизии добавляет суффикс _stego_N.
     */
    public static File buildOutputFile(File source) {
        File dir = source.getAbsoluteFile().getParentFile();
        String name = source.getName();
        int dot = name.lastIndexOf('.');
        String base = dot > 0 ? name.substring(0, dot) : name;

        File candidate = new File(dir, base + "_stego.png");
        int counter = 1;
        while (candidate.exists()) {
            candidate = new File(dir, base + "_stego_" + counter + ".png");
            counter++;
        }
        return candidate;
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
        long capacity = capacityBytes(image);
        if ((long) startByte + count > capacity) {
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
        if (payload.length < SALT_LEN + IV_LEN + TAG_BYTES) {
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