import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class StegoPassword {
    private static final String ALGORITHM = "AES";
    private static final int BITS_PER_PIXEL = 3; // RGB channels
    private static final Scanner scanner = new Scanner(System.in);
    private static final String DEFAULT_INPUT_IMAGE = "input.png";
    private static final String DEFAULT_OUTPUT_IMAGE = "output.png";

    public static void main(String[] args) {
        System.out.println("Password Manager with Steganography");
        while (true) {
            displayMenu();
            String choice = scanner.nextLine().trim();
            try {
                switch (choice) {
                    case "1":
                        handleStorePasswords();
                        break;
                    case "2":
                        handleRetrievePasswords();
                        break;
                    case "3":
                        System.out.println("Exiting...");
                        return;
                    default:
                        System.out.println("Invalid choice. Please enter 1, 2, or 3.");
                }
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
                System.out.println("Please try again.");
            }
        }
    }

    private static void displayMenu() {
        System.out.println("\nMenu:");
        System.out.println("1. Store passwords in image");
        System.out.println("2. Retrieve passwords from image");
        System.out.println("3. Exit");
        System.out.print("Enter choice (1-3): ");
    }

    private static void handleStorePasswords() throws Exception {
        System.out.println("Checking input image: " + DEFAULT_INPUT_IMAGE);
        File inputFile = new File(DEFAULT_INPUT_IMAGE);
        if (!inputFile.exists()) {
            throw new FileNotFoundException("Input image not found at: " + inputFile.getAbsolutePath() +
                    ". Please place a PNG image named 'input.png' in the project root.");
        }

        System.out.println("Will save to: " + DEFAULT_OUTPUT_IMAGE);
        System.out.println("Enter encryption key (16, 24, or 32 characters):");
        String encryptionKey = scanner.nextLine().trim();
        if (encryptionKey.length() != 16 && encryptionKey.length() != 24 && encryptionKey.length() != 32) {
            throw new IllegalArgumentException("Encryption key must be 16, 24, or 32 characters long.");
        }

        Map<String, String> passwords = new HashMap<>();
        System.out.println("Enter at least one password (format: username password). Type 'done' to finish:");
        while (true) {
            String input = scanner.nextLine().trim();
            if (input.equalsIgnoreCase("done")) {
                if (passwords.isEmpty()) {
                    System.out.println("Error: At least one password is required.");
                    continue;
                }
                break;
            }
            String[] parts = input.split("\\s+", 2);
            if (parts.length != 2) {
                System.out.println("Invalid format. Use: username password");
                continue;
            }
            passwords.put(parts[0], parts[1]);
            System.out.println("Added " + parts[0] + ". Enter another or 'done'.");
        }

        System.out.println("Storing passwords...");
        storePasswords(passwords, encryptionKey, DEFAULT_INPUT_IMAGE, DEFAULT_OUTPUT_IMAGE);
        System.out.println("Success: Passwords stored in " + DEFAULT_OUTPUT_IMAGE);
        System.out.println("Output file created at: " + new File(DEFAULT_OUTPUT_IMAGE).getAbsolutePath());
    }

    private static void handleRetrievePasswords() throws Exception {
        System.out.println("Checking image: " + DEFAULT_OUTPUT_IMAGE);
        File imageFile = new File(DEFAULT_OUTPUT_IMAGE);
        if (!imageFile.exists()) {
            throw new FileNotFoundException("Output image not found at: " + imageFile.getAbsolutePath());
        }

        System.out.println("Enter encryption key:");
        String encryptionKey = scanner.nextLine().trim();

        System.out.println("Retrieving passwords...");
        Map<String, String> passwords = retrievePasswords(encryptionKey, DEFAULT_OUTPUT_IMAGE);
        System.out.println("Retrieved passwords:");
        if (passwords.isEmpty()) {
            System.out.println("  (None)");
        } else {
            for (Map.Entry<String, String> entry : passwords.entrySet()) {
                System.out.println("  Username: " + entry.getKey() + ", Password: " + entry.getValue());
            }
        }
    }

    // Store passwords in image
    private static void storePasswords(Map<String, String> passwords, String encryptionKey,
                                       String inputImagePath, String outputImagePath) throws Exception {
        System.out.println("Serializing passwords...");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(passwords);
        oos.close();
        byte[] passwordBytes = baos.toByteArray();

        System.out.println("Encrypting data...");
        byte[] encryptedData = encrypt(passwordBytes, encryptionKey);

        System.out.println("Embedding data in image...");
        embedDataInImage(encryptedData, inputImagePath, outputImagePath);
    }

    // extract pws from image
    @SuppressWarnings("unchecked")
    private static Map<String, String> retrievePasswords(String encryptionKey, String imagePath) throws Exception {
        System.out.println("Extracting data from image...");
        byte[] encryptedData = extractDataFromImage(imagePath);

        System.out.println("Decrypting data...");
        byte[] decryptedData = decrypt(encryptedData, encryptionKey);

        System.out.println("Deserializing passwords...");
        ByteArrayInputStream bais = new ByteArrayInputStream(decryptedData);
        ObjectInputStream ois = new ObjectInputStream(bais);
        Map<String, String> passwords = (Map<String, String>) ois.readObject();
        ois.close();
        return passwords;
    }

    // Encrypt with aes
    private static byte[] encrypt(byte[] data, String key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(generateKey(key), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    // Decrypt aes
    private static byte[] decrypt(byte[] data, String key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(generateKey(key), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }

    // Generate AES key from string (hash to match key length)
    private static byte[] generateKey(String key) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = sha.digest(key.getBytes(StandardCharsets.UTF_8));
        if (key.length() == 16) {
            return Arrays.copyOf(keyBytes, 16); // AES-128
        } else if (key.length() == 24) {
            return Arrays.copyOf(keyBytes, 24); // AES-192
        } else {
            return Arrays.copyOf(keyBytes, 32); // AES-256
        }
    }

    // Embed data into image using LSB steganography
    private static void embedDataInImage(byte[] data, String inputImagePath, String outputImagePath) throws Exception {
        System.out.println("Loading input image: " + inputImagePath);
        File inputFile = new File(inputImagePath);
        if (!inputFile.exists()) {
            throw new FileNotFoundException("Input image not found: " + inputFile.getAbsolutePath());
        }
        BufferedImage image = ImageIO.read(inputFile);
        int width = image.getWidth();
        int height = image.getHeight();

        // Check if image can hold the data
        int dataBits = (data.length + 4) * 8; // +4 for length prefix
        int capacityBits = width * height * BITS_PER_PIXEL;
        System.out.println("Data size: " + dataBits + " bits, Image capacity: " + capacityBits + " bits");
        if (dataBits > capacityBits) {
            throw new IllegalArgumentException("Image too small to hold data. Required: " + dataBits +
                    " bits, Available: " + capacityBits + " bits.");
        }

        // Convert data length to 4 bytes
        byte[] lengthBytes = new byte[]{
                (byte) (data.length >> 24),
                (byte) (data.length >> 16),
                (byte) (data.length >> 8),
                (byte) (data.length)
        };

        // Combine length and data
        byte[] fullData = new byte[data.length + 4];
        System.arraycopy(lengthBytes, 0, fullData, 0, 4);
        System.arraycopy(data, 0, fullData, 4, data.length);

        // Embed data into image
        System.out.println("Embedding " + (fullData.length * 8) + " bits into image...");
        int bitIndex = 0;
        outer:
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                if (bitIndex >= fullData.length * 8) {
                    break outer;
                }

                int rgb = image.getRGB(x, y);
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;

                // Embed 3 bits (one per channel)
                if (bitIndex < fullData.length * 8) {
                    r = setLSB(r, getBit(fullData, bitIndex++));
                }
                if (bitIndex < fullData.length * 8) {
                    g = setLSB(g, getBit(fullData, bitIndex++));
                }
                if (bitIndex < fullData.length * 8) {
                    b = setLSB(b, getBit(fullData, bitIndex++));
                }

                // Set new RGB value
                int newRGB = (r << 16) | (g << 8) | b;
                image.setRGB(x, y, (rgb & 0xFF000000) | newRGB);
            }
        }

        // Save modified image
        System.out.println("Writing output image to: " + outputImagePath);
        File outputFile = new File(outputImagePath);
        if (!ImageIO.write(image, "png", outputFile)) {
            throw new IOException("Failed to write output image. No suitable writer found for PNG format.");
        }
        System.out.println("Output image written successfully.");
    }

    // Extract data from image
    private static byte[] extractDataFromImage(String imagePath) throws Exception {
        System.out.println("Loading image: " + imagePath);
        File imageFile = new File(imagePath);
        if (!imageFile.exists()) {
            throw new FileNotFoundException("Image not found: " + imageFile.getAbsolutePath());
        }
        BufferedImage image = ImageIO.read(imageFile);
        int width = image.getWidth();
        int height = image.getHeight();

        // Extract length (first 32 bits)
        byte[] lengthBytes = new byte[4];
        int bitIndex = 0;
        for (int i = 0; i < 32; i++) {
            int x = (bitIndex / BITS_PER_PIXEL) % width;
            int y = (bitIndex / BITS_PER_PIXEL) / width;
            int rgb = image.getRGB(x, y);
            int channel = bitIndex % BITS_PER_PIXEL;
            int value = (channel == 0) ? ((rgb >> 16) & 0xFF) :
                    (channel == 1) ? ((rgb >> 8) & 0xFF) :
                            (rgb & 0xFF);
            setBit(lengthBytes, i, value & 1);
            bitIndex++;
        }

        // Convert length bytes to int
        int dataLength = ((lengthBytes[0] & 0xFF) << 24) |
                ((lengthBytes[1] & 0xFF) << 16) |
                ((lengthBytes[2] & 0xFF) << 8) |
                (lengthBytes[3] & 0xFF);

        // Extract data
        byte[] data = new byte[dataLength];
        for (int i = 0; i < dataLength * 8; i++) {
            int x = (bitIndex / BITS_PER_PIXEL) % width;
            int y = (bitIndex / BITS_PER_PIXEL) / width;
            int rgb = image.getRGB(x, y);
            int channel = bitIndex % BITS_PER_PIXEL;
            int value = (channel == 0) ? ((rgb >> 16) & 0xFF) :
                    (channel == 1) ? ((rgb >> 8) & 0xFF) :
                            (rgb & 0xFF);
            setBit(data, i, value & 1);
            bitIndex++;
        }

        return data;
    }

    // Get bit at index from byte array
    private static int getBit(byte[] data, int bitIndex) {
        int byteIndex = bitIndex / 8;
        int bitPos = 7 - (bitIndex % 8);
        return (data[byteIndex] >> bitPos) & 1;
    }

    // Set LSB of a value
    private static int setLSB(int value, int bit) {
        return (value & 0xFE) | bit;
    }

    // Set bit at index in byte array
    private static void setBit(byte[] data, int bitIndex, int bit) {
        int byteIndex = bitIndex / 8;
        int bitPos = 7 - (bitIndex % 8);
        data[byteIndex] = (byte) ((data[byteIndex] & ~(1 << bitPos)) | (bit << bitPos));
    }
}