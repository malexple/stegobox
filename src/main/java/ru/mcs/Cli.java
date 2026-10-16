package ru.mcs;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Консольный режим StegoBox.
 *
 * Использование:
 *   stegobox hide    -i img.png -t "текст" -p пароль [-o out.png]
 *   stegobox extract -i img.png [-o out.txt]
 *   stegobox help
 *   stegobox version
 *
 * Коды возврата:
 *   0 — успех
 *   1 — ошибка выполнения (неверный пароль, недостаток места, битый файл…)
 *   2 — ошибка использования (не хватает аргументов и т. п.)
 */
public final class Cli {

    private static final String VERSION = "1.1.0";
    private static final String ENV_PASSWORD = "STEKOBOX_PASSWORD";

    private Cli() {
    }

    public static int run(String[] args) {
        try {
            String cmd = args[0];
            return switch (cmd) {
                case "hide" -> cmdHide(parse(args, 1));
                case "extract" -> cmdExtract(parse(args, 1));
                case "help", "-h", "--help" -> { printHelp(); yield 0; }
                case "version", "-v", "--version" -> {
                    System.out.println("StegoBox " + VERSION);
                    yield 0;
                }
                default -> {
                    System.err.println("Неизвестная команда: " + cmd);
                    System.err.println("Подсказка: stegobox help");
                    yield 2;
                }
            };
        } catch (UsageException e) {
            System.err.println("Ошибка: " + e.getMessage());
            System.err.println("Подсказка: stegobox help");
            return 2;
        } catch (Exception e) {
            System.err.println("Ошибка: " + e.getMessage());
            return 1;
        }
    }

    // ---------- Команды ----------

    private static int cmdHide(Map<String, String> opts) throws Exception {
        File input = requireFile(opts);
        char[] password = resolvePassword(opts);
        String text = resolveText(opts);

        try {
            BufferedImage img = readImage(input);
            BufferedImage stego = StegoEngine.hideText(img, text, password);

            File output = resolveOutput(opts, input);
            ImageIO.write(stego, "png", output);
            System.out.println("Сохранено: " + output.getAbsolutePath());
            return 0;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static int cmdExtract(Map<String, String> opts) throws Exception {
        File input = requireFile(opts);
        char[] password = resolvePassword(opts);

        String text;
        try {
            BufferedImage img = readImage(input);
            text = StegoEngine.extractText(img, password);
        } finally {
            Arrays.fill(password, '\0');
        }

        String outPath = getOpt(opts, "output", "o");
        if (outPath != null) {
            Files.writeString(Path.of(outPath), text, StandardCharsets.UTF_8);
            System.out.println("Текст сохранён: " + outPath);
        } else {
            System.out.println(text);
        }
        return 0;
    }

    // ---------- Разбор аргументов ----------

    private static Map<String, String> parse(String[] args, int from) {
        Map<String, String> opts = new LinkedHashMap<>();
        for (int i = from; i < args.length; i++) {
            String a = args[i];
            if (!a.startsWith("-")) {
                throw new UsageException("Неожиданный аргумент: " + a);
            }
            String key;
            String value;

            int eq = a.indexOf('=');
            if (eq > 0) {
                key = stripDashes(a.substring(0, eq));
                value = a.substring(eq + 1);
            } else {
                key = stripDashes(a);
                boolean nextIsValue = i + 1 < args.length
                        && (!args[i + 1].startsWith("-") || args[i + 1].equals("-"));
                value = nextIsValue ? args[++i] : "true";
            }
            opts.put(key, value);
        }
        return opts;
    }

    private static String stripDashes(String s) {
        int i = 0;
        while (i < s.length() && s.charAt(i) == '-') i++;
        return s.substring(i);
    }

    private static String getOpt(Map<String, String> opts, String... keys) {
        for (String k : keys) {
            if (opts.containsKey(k)) return opts.get(k);
        }
        return null;
    }

    // ---------- Помощники ----------

    private static File requireFile(Map<String, String> opts) {
        String path = getOpt(opts, "input", "i");
        if (path == null) throw new UsageException("Не указан входной файл (--input)");
        File f = new File(path);
        if (!f.exists()) throw new UsageException("Файл не найден: " + path);
        return f;
    }

    private static BufferedImage readImage(File file) throws Exception {
        BufferedImage img = ImageIO.read(file);
        if (img == null) {
            throw new IllegalArgumentException("Не удалось прочитать изображение: " + file);
        }
        return img;
    }

    private static File resolveOutput(Map<String, String> opts, File input) {
        String path = getOpt(opts, "output", "o");
        return path != null ? new File(path) : StegoEngine.buildOutputFile(input);
    }

    private static String resolveText(Map<String, String> opts) throws Exception {
        String inline = getOpt(opts, "text", "t");
        String file = getOpt(opts, "text-file");

        if (inline != null && file != null) {
            throw new UsageException("Укажите только одно из: --text или --text-file");
        }
        if (file != null) {
            return Files.readString(Path.of(file), StandardCharsets.UTF_8);
        }
        if (inline != null) {
            if ("-".equals(inline)) {
                return new String(System.in.readAllBytes(), StandardCharsets.UTF_8);
            }
            return inline;
        }
        throw new UsageException("Не указан текст: используйте --text или --text-file");
    }

    private static char[] resolvePassword(Map<String, String> opts) {
        String p = getOpt(opts, "password", "p");
        if (p == null) p = System.getenv(ENV_PASSWORD);
        if (p != null && !p.isEmpty()) return p.toCharArray();

        if (System.console() != null) {
            char[] pw = System.console().readPassword("Пароль: ");
            if (pw == null || pw.length == 0) throw new UsageException("Пароль не введён");
            return pw;
        }
        throw new UsageException(
                "Пароль не задан. Используйте --password, переменную " + ENV_PASSWORD
                        + " или запустите из терминала интерактивно.");
    }

    // ---------- Справка ----------

    private static void printHelp() {
        System.out.print("""
                StegoBox %s — LSB-стеганография + AES-256

                Использование:
                  stegobox                                 запустить графический интерфейс
                  stegobox hide    -i <img> -t <text> ...  спрятать текст в изображении
                  stegobox extract -i <img> ...            извлечь текст из изображения
                  stegobox help                            показать эту справку
                  stegobox version                         показать версию

                Общие параметры:
                  -i, --input   <file>   входное изображение (PNG/BMP)
                  -p, --password <pw>    пароль; если не задан — спросит интерактивно,
                                         либо возьмёт из переменной STEKOBOX_PASSWORD
                  -o, --output  <file>   выходной файл
                                         (hide: по умолчанию <имя>_stego.png рядом с исходником,
                                          extract: по умолчанию печать в stdout)

                Только для hide:
                  -t, --text      <text>  текст для сокрытия ("-" = читать из stdin)
                      --text-file <file>  прочитать текст из файла UTF-8

                Примеры:
                  stegobox hide -i photo.png -t "секрет" -p qwerty
                  stegobox hide -i photo.png --text-file secret.txt
                  cat secret.txt | stegobox hide -i photo.png -t - -p qwerty
                  stegobox extract -i photo_stego.png
                  stegobox extract -i photo_stego.png -o secret.txt

                Коды возврата:
                  0 — успех
                  1 — ошибка выполнения (неверный пароль, недостаток места и т. п.)
                  2 — ошибка использования аргументов
                """.formatted(VERSION));
    }

    // ---------- Исключение ----------

    private static final class UsageException extends RuntimeException {
        UsageException(String message) {
            super(message);
        }
    }
}