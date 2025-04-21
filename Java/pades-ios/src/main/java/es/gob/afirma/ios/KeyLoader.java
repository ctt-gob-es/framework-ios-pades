package es.gob.afirma.ios;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class KeyLoader {

    public static PrivateKey loadPrivateKey(InputStream inputStream, String algorithm) throws Exception {
        // Leer todos los bytes del InputStream
        byte[] keyBytes = readInputStream(inputStream);

        // Crear una especificación de clave PKCS#8
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);

        // Obtener una instancia de KeyFactory para el tipo de clave
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);

        // Generar la clave privada
        return keyFactory.generatePrivate(keySpec);
    }

    // Método para leer todos los bytes de un InputStream
    private static byte[] readInputStream(InputStream inputStream) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int bytesRead;

        while ((bytesRead = inputStream.read(buffer)) != -1) {
            baos.write(buffer, 0, bytesRead);
        }

        return baos.toByteArray();
    }
}