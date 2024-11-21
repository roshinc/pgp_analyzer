package dev.roshin.pgp_analyzer;

import org.junit.jupiter.api.Test;

class PGPAnalyzerTest {


    @Test
    void analyzeFile() {
        PGPAnalyzer.main(new String[]{"C:\\Github\\pgp_analyzer\\encrypted.gpg", "C:\\Github\\pgp_analyzer\\encryption_key.sec"});
    }

    @Test
    void analyzeCompressedData() {
    }

    @Test
    void checkKeyInKeyring() {
    }
}