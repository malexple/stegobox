package ru.mcs;

import com.formdev.flatlaf.FlatLightLaf;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;

public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        if (args.length > 0) {
            System.exit(Cli.run(args));
        }
        // GUI-режим
        FlatLightLaf.setup();
        UIManager.put("Component.focusWidth", 1);
        UIManager.put("Button.arc", 10);
        UIManager.put("Component.arc", 8);
        UIManager.put("TextComponent.arc", 8);

        SwingUtilities.invokeLater(() -> new StegoFrame().setVisible(true));
    }
}