package io._focuson.libdte;

import org.junit.jupiter.api.Test;

import java.io.File;

public class LibdteApplicationTest {

    @Test
    void testWsdl() {

        Connection connection = new Connection();

        File key = new File("test/xxxxx.p12");
        String password = "xxxxx";
        connection.getToken(key, password);

    }
}
