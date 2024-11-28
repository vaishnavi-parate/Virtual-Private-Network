import java.io.*;
import java.net.*;
import javax.crypto.SecretKey;

public class VPNServer {
    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(12345)) {
            System.out.println("Server is listening on port 12345...");
            Socket socket = serverSocket.accept();
            System.out.println("Client connected.");

            // Create a shared secret key (in a real implementation, key exchange should be secure)
            SecretKey sharedKey = EncryptionUtil.generateKey();
            String encodedKey = EncryptionUtil.encodeKey(sharedKey);
            System.out.println("Shared secret key: " + encodedKey);

            // Set up streams
            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter output = new PrintWriter(socket.getOutputStream(), true);

            // Send the key to the client (insecure method for this demo)
            output.println(encodedKey);

            String encryptedMessage;
            while ((encryptedMessage = input.readLine()) != null) {
                String decryptedMessage = EncryptionUtil.decrypt(encryptedMessage, sharedKey);
                System.out.println("Client: " + decryptedMessage);
                // Respond with encrypted message
                String response = "Hello from Server!";
                encryptedMessage = EncryptionUtil.encrypt(response, sharedKey);
                output.println(encryptedMessage);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
