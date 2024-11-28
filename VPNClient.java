import java.io.*;
import java.net.*;
import javax.crypto.SecretKey;

public class VPNClient {
    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 12345)) {
            System.out.println("Connected to the server.");

            // Set up streams
            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter output = new PrintWriter(socket.getOutputStream(), true);

            // Receive the shared secret key from the server
            String encodedKey = input.readLine();
            SecretKey sharedKey = EncryptionUtil.decodeKey(encodedKey);
            System.out.println("Received shared secret key: " + encodedKey);

            // Send an encrypted message to the server
            String message = "Hello from Client!";
            String encryptedMessage = EncryptionUtil.encrypt(message, sharedKey);
            output.println(encryptedMessage);

            // Receive response from server
            String response = input.readLine();
            String decryptedResponse = EncryptionUtil.decrypt(response, sharedKey);
            System.out.println("Server: " + decryptedResponse);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
