package dev.roshin.pgp_analyzer.gui;

import dev.roshin.pgp_analyzer.PGPAnalyzer;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;

public class PGPAnalyzerGUI extends JFrame {
    // GUI components
    private JTextField fileField;
    private JTextField keyFileField;
    private JTextArea outputArea;
    private JButton browseFileButton;
    private JButton browseKeyButton;
    private JButton analyzeButton;
    private JFileChooser fileChooser;


    public PGPAnalyzerGUI() {
        setTitle("PGP Analyzer");
        setSize(600, 400);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        initComponents();
    }

    private void initComponents() {
        fileField = new JTextField(30);
        keyFileField = new JTextField(30);
        outputArea = new JTextArea(15, 50);
        outputArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(outputArea);

        browseFileButton = new JButton("Browse...");
        browseKeyButton = new JButton("Browse...");
        analyzeButton = new JButton("Analyze");

        fileChooser = new JFileChooser();

        // Layout components
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        topPanel.add(new JLabel("File to Analyze:"), gbc);

        gbc.gridx = 1;
        topPanel.add(fileField, gbc);

        gbc.gridx = 2;
        topPanel.add(browseFileButton, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        topPanel.add(new JLabel("ASC Key File (Optional):"), gbc);

        gbc.gridx = 1;
        topPanel.add(keyFileField, gbc);

        gbc.gridx = 2;
        topPanel.add(browseKeyButton, gbc);

        gbc.gridx = 1;
        gbc.gridy = 2;
        topPanel.add(analyzeButton, gbc);

        add(topPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);

        // Add action listeners
        browseFileButton.addActionListener(e -> browseFile(fileField));
        browseKeyButton.addActionListener(e -> browseFile(keyFileField));
        analyzeButton.addActionListener(e -> analyzeAction());
    }

    private void browseFile(JTextField targetField) {
        int returnVal = fileChooser.showOpenDialog(this);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            targetField.setText(file.getAbsolutePath());
        }
    }

    private void analyzeAction() {
        String filePath = fileField.getText();
        String ascKeyPath = keyFileField.getText().isEmpty() ? null : keyFileField.getText();

        if (filePath.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Please select a file to analyze.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Clear the output area
        outputArea.setText("");

        // Run the analysis in a separate thread to avoid freezing the GUI
        new Thread(() -> {
            try {
                // Create a PrintStream that writes to the outputArea
                OutputStream outStream = new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        outputArea.append(String.valueOf((char) b));
                    }
                };
                PrintStream printStream = new PrintStream(outStream, true);

                PGPAnalyzer.analyzeFile(filePath, ascKeyPath, printStream);
            } catch (Exception e) {
                outputArea.append("An error occurred during analysis:\n");
                outputArea.append(e.getMessage());
            }
        }).start();
    }


}
