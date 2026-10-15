package ru.mcs;

import javax.imageio.ImageIO;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingWorker;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;

public class StegoFrame extends JFrame {

    private final JTextField pathField = new JTextField(30);
    private final JTextArea textArea = new JTextArea(12, 48);
    private final JPasswordField passwordField = new JPasswordField(20);
    private final JLabel statusLabel = new JLabel("Готов");
    private final JButton browseBtn = new JButton("Обзор...");
    private final JButton hideBtn = new JButton("Скрыть текст в изображении");
    private final JButton extractBtn = new JButton("Извлечь текст из изображения");

    private File selectedFile;
    private BufferedImage selectedImage;

    public StegoFrame() {
        super("StegoBox — LSB-стеганография + AES-256");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        initUI();
        pack();
        setMinimumSize(getSize());
        setLocationRelativeTo(null);
    }

    private void initUI() {
        JPanel root = new JPanel(new BorderLayout(10, 10));
        root.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        // --- Top: file selection
        JPanel filePanel = new JPanel(new BorderLayout(8, 0));
        filePanel.add(new JLabel("Изображение:"), BorderLayout.WEST);
        pathField.setEditable(false);
        filePanel.add(pathField, BorderLayout.CENTER);
        filePanel.add(browseBtn, BorderLayout.EAST);

        // --- Center: text + password
        JPanel center = new JPanel(new BorderLayout(0, 6));
        center.add(new JLabel("Текст для сокрытия / Извлечённый текст:"), BorderLayout.NORTH);

        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        center.add(new JScrollPane(textArea), BorderLayout.CENTER);

        JPanel passPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        passPanel.add(new JLabel("Пароль:"));
        passPanel.add(passwordField);
        passPanel.add(new JLabel("(AES-256 / PBKDF2 / GCM)"));
        center.add(passPanel, BorderLayout.SOUTH);

        // --- Bottom: buttons + status
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
        buttons.add(hideBtn);
        buttons.add(extractBtn);

        JPanel bottom = new JPanel(new BorderLayout(0, 6));
        bottom.add(buttons, BorderLayout.NORTH);
        bottom.add(statusLabel, BorderLayout.SOUTH);

        root.add(filePanel, BorderLayout.NORTH);
        root.add(center, BorderLayout.CENTER);
        root.add(bottom, BorderLayout.SOUTH);

        setContentPane(root);

        browseBtn.addActionListener(e -> chooseFile());
        hideBtn.addActionListener(e -> doHide());
        extractBtn.addActionListener(e -> doExtract());
    }

    private void chooseFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Выберите изображение (PNG или BMP)");
        chooser.setAcceptAllFileFilterUsed(false);
        chooser.setFileFilter(new FileNameExtensionFilter("Изображения PNG/BMP", "png", "bmp"));

        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File file = chooser.getSelectedFile();
        try {
            BufferedImage img = ImageIO.read(file);
            if (img == null) {
                showError("Не удалось прочитать изображение. Убедитесь, что это PNG или BMP.");
                return;
            }
            selectedFile = file;
            selectedImage = img;
            pathField.setText(file.getAbsolutePath());
            statusLabel.setText(String.format("Загружено: %s (%d×%d)",
                    file.getName(), img.getWidth(), img.getHeight()));
        } catch (IOException ex) {
            showError("Ошибка чтения файла: " + ex.getMessage());
        }
    }

    private void doHide() {
        if (selectedImage == null) {
            showError("Сначала выберите изображение");
            return;
        }
        String text = textArea.getText();
        if (text == null || text.isEmpty()) {
            showError("Введите текст для сокрытия");
            return;
        }
        char[] password = passwordField.getPassword();
        if (password.length == 0) {
            showError("Введите пароль");
            return;
        }

        setBusy(true);
        statusLabel.setText("Шифрование и встраивание...");

        new SwingWorker<File, Void>() {
            @Override
            protected File doInBackground() throws Exception {
                BufferedImage result = StegoEngine.hideText(selectedImage, text, password);
                File outFile = buildOutputFile(selectedFile);
                ImageIO.write(result, "png", outFile);
                return outFile;
            }

            @Override
            protected void done() {
                Arrays.fill(password, '\0');
                setBusy(false);
                try {
                    File out = get();
                    statusLabel.setText("Готово. Сохранено: " + out.getAbsolutePath());
                } catch (Exception ex) {
                    Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
                    showError("Ошибка: " + cause.getMessage());
                    statusLabel.setText("Ошибка");
                }
            }
        }.execute();
    }

    private void doExtract() {
        if (selectedImage == null) {
            showError("Сначала выберите изображение");
            return;
        }
        char[] password = passwordField.getPassword();
        if (password.length == 0) {
            showError("Введите пароль");
            return;
        }

        setBusy(true);
        statusLabel.setText("Извлечение и расшифровка...");

        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                return StegoEngine.extractText(selectedImage, password);
            }

            @Override
            protected void done() {
                Arrays.fill(password, '\0');
                setBusy(false);
                try {
                    String text = get();
                    textArea.setText(text);
                    statusLabel.setText("Готово. Извлечено " + text.length() + " символов");
                } catch (Exception ex) {
                    Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
                    showError("Не удалось извлечь: " + cause.getMessage());
                    statusLabel.setText("Ошибка");
                }
            }
        }.execute();
    }

    private File buildOutputFile(File source) {
        File dir = source.getParentFile();
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

    private void setBusy(boolean busy) {
        browseBtn.setEnabled(!busy);
        hideBtn.setEnabled(!busy);
        extractBtn.setEnabled(!busy);
        passwordField.setEnabled(!busy);
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Ошибка", JOptionPane.ERROR_MESSAGE);
    }
}